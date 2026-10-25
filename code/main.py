"""Evidence-backed deletion auditor for Ghost Data Still Exists."""
from __future__ import annotations
import csv, datetime as dt, json, os, re, shutil, sys, threading, urllib.error, urllib.request, zlib
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "dataset"
OUT = ROOT / "output.csv"
PHASES = {"FINDING", "REMEDIATION", "VERIFICATION"}
OPS = {
 "REPORT_REMAINING_RECORD":"PRESENT", "REPORT_EXPOSED_PII":"PRESENT", "REPORT_ACTIVE_DATA_FLOW":"ACTIVE", "REPORT_RESTORE_RISK":"ACTIVE",
 "DISABLE_DATA_FLOW":"DISABLED", "BLOCK_RESTORE":"BLOCKED", "DELETE_RECORD":"ABSENT", "REDACT_RECORD":"REDACTED", "ANONYMIZE_RECORD":"ANONYMIZED",
 "VERIFY_RECORD_ABSENT":"ABSENT", "VERIFY_RECORD_PRESENT":"PRESENT", "VERIFY_RECORD_REDACTED":"REDACTED", "VERIFY_RECORD_ANONYMIZED":"ANONYMIZED", "VERIFY_DATA_FLOW_DISABLED":"DISABLED", "VERIFY_RESTORE_BLOCKED":"BLOCKED",
}
SYSTEMS = {"account":"account_service","search":"search_service","support":"support_platform","export":"export_service","analytics":"analytics_platform","data_flow":"integration_service","backup":"backup_service","tombstone":"identity_service","audit_record":"security_service","cache":"cache_service","marketing":"marketing_service"}
RESOURCE_RE = re.compile(r"\b(?:account|search|support|export|analytics|data_flow|backup|tombstone|audit_record|cache|marketing)_[0-9]+\b", re.I)

def ts(v: str) -> dt.datetime: return dt.datetime.fromisoformat(v.replace("Z", "+00:00"))
def read_csv(name: str, required: Iterable[str]) -> list[dict[str,str]]:
    with (DATA/name).open(encoding="utf-8-sig", newline="") as f: rows = list(csv.DictReader(f))
    if not rows or set(required) - set(rows[0]): raise ValueError(f"{name}: missing schema columns")
    return rows

@dataclass
class Identity:
    user_id: str
    values: set[str] = field(default_factory=set)
@dataclass
class Evidence:
    file_id: str
    captured_at: dt.datetime
    text: str
@dataclass
class Obs:
    resource: str; system: str; state: str; evidence: str; context: str; category: str

class OllamaError(RuntimeError):
    pass

class OllamaClient:
    def __init__(self, base_url: str | None = None, model: str | None = None, timeout: float = 20.0):
        self.base_url = (base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")).rstrip("/")
        self.model = model or os.getenv("OLLAMA_MODEL", "llama3.2:3b")
        self.timeout = timeout
        self.calls = 0
        self.input_chars = 0
        self.output_chars = 0

    def diagnostic(self) -> dict[str, Any]:
        started = time.monotonic()
        result = self.generate_json('Return exactly {"action":{"tool":"summarize_case","arguments":{}}} and no other text.')
        elapsed = time.monotonic() - started
        action = result.get("action")
        if not isinstance(action, dict) or action.get("tool") != "summarize_case":
            raise OllamaError("Diagnostic response did not contain the required action object")
        return {"elapsed_seconds": round(elapsed, 3), "action": action}

    def tags(self) -> list[str]:
        req = urllib.request.Request(self.base_url + "/api/tags", method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (OSError, ValueError) as exc:
            raise OllamaError(f"Ollama is unreachable at {self.base_url}: {exc}") from exc
        return [str(x.get("name", "")) for x in payload.get("models", []) if isinstance(x, dict)]

    def generate_json(self, prompt: str) -> dict[str, Any]:
        body = json.dumps({"model": self.model, "prompt": prompt, "stream": False, "format": "json", "options": {"temperature": 0, "num_predict": 96}}).encode("utf-8")
        req = urllib.request.Request(self.base_url + "/api/generate", data=body, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (OSError, ValueError) as exc:
            raise OllamaError(f"Ollama generation failed: {exc}") from exc
        self.calls += 1
        raw = str(payload.get("response", ""))
        self.input_chars += len(prompt); self.output_chars += len(raw)
        try:
            result = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise OllamaError(f"Ollama returned malformed JSON: {exc}") from exc
        if not isinstance(result, dict):
            raise OllamaError("Ollama response must be a JSON object")
        return result

TOOL_DEFINITIONS = {
    "resolve_identity": {"required": {"email": str}, "optional": {"limit": int}},
    "search_audit": {"required": {"user_id": str}, "optional": {"limit": int}},
    "search_activity": {"required": {"query": str}, "optional": {"limit": int}},
    "search_evidence": {"required": {"query": str}, "optional": {"limit": int}},
    "get_evidence": {"required": {"file_id": str}, "optional": {"max_chars": int}},
    "get_rules": {"required": {}, "optional": {"data_category": str}},
    "summarize_case": {"required": {}, "optional": {}},
}

def _validate_tool(name: Any, args: Any) -> tuple[str, dict[str, Any]]:
    if not isinstance(name, str) or name not in TOOL_DEFINITIONS: raise OllamaError(f"Unknown tool: {name!r}")
    if not isinstance(args, dict): raise OllamaError("Tool arguments must be an object")
    spec = TOOL_DEFINITIONS[name]
    for key, typ in spec["required"].items():
        if key not in args or not isinstance(args[key], typ): raise OllamaError(f"Invalid required argument {key} for {name}")
    clean = dict(args)
    for key, value in clean.items():
        if key not in spec["required"] and key not in spec["optional"]: raise OllamaError(f"Unexpected argument {key} for {name}")
        if key in spec["optional"] and not isinstance(value, spec["optional"][key]): raise OllamaError(f"Invalid argument type {key} for {name}")
    if "limit" in clean: clean["limit"] = max(1, min(clean["limit"], 20))
    if "max_chars" in clean: clean["max_chars"] = max(100, min(clean["max_chars"], 4000))
    return name, clean

def _bounded_record(o: Obs) -> dict[str, str]:
    return {"resource_id": o.resource, "system_id": o.system, "state": o.state, "evidence_id": o.evidence, "category": o.category}


def _compact_tool_result(result: Any) -> Any:
    """Keep prompts small while retaining IDs, timestamps, and decisions."""
    if not isinstance(result, dict): return result
    compact: dict[str, Any] = {}
    for key, value in result.items():
        if key in {"excerpt", "error", "missing"}:
            compact[key] = str(value)[:160]
        elif key in {"events", "activities"} and isinstance(value, list):
            compact[key] = [{k: str(item.get(k, ""))[:100] for k in ("audit_id", "activity_id", "event_time", "event_type", "resource_id", "reported_result", "details") if k in item} for item in value[:2] if isinstance(item, dict)]
        elif key == "rules" and isinstance(value, list):
            compact[key] = [{k: item.get(k, "") for k in ("rule_id", "data_category", "condition", "required_action")} for item in value[:4] if isinstance(item, dict)]
        elif key == "records" and isinstance(value, list):
            compact[key] = value[:8]
        elif key == "evidence" and isinstance(value, list):
            compact[key] = [{k: item.get(k, "") for k in ("file_id", "captured_at", "match")} for item in value[:6] if isinstance(item, dict)]
        else:
            compact[key] = value
    return compact


def _term_in_text(text: str, term: str) -> bool:
    """Match identifiers without treating user_18 as user_189."""
    needle = term.strip().casefold()
    if not needle: return False
    if re.match(r"^[a-z0-9_]+$", needle):
        return re.search(rf"(?<![a-z0-9_]){re.escape(needle)}(?![a-z0-9_])", text.casefold()) is not None
    return needle in text.casefold()


def _execute_review_tool(name: str, args: dict[str, Any], case: dict[str, str], ident: Identity | None,
                        evs: list[Evidence], audits: list[dict[str, str]], activities: list[dict[str, str]],
                        rules: list[dict[str, str]], candidate_records: list[Obs], cutoff: dt.datetime) -> dict[str, Any]:
    """Execute one bounded registered tool against already loaded participant data."""
    if name == "resolve_identity":
        # Identity lookup is already resolved from the request, but this keeps
        # the same registered-tool contract available to the model.
        return {"user_id": ident.user_id if ident else None, "aliases": sorted(ident.values)[:20] if ident else [], "found": bool(ident)}
    if name == "search_audit":
        rows = [r for r in audits if r["user_id"] == args["user_id"] and ts(r["event_time"]) <= cutoff]
        return {"events": rows[:args.get("limit", 20)]}
    if name == "search_activity":
        query = args["query"].casefold()
        rows = [r for r in activities if ts(r["event_time"]) <= cutoff and _term_in_text(json.dumps(r, ensure_ascii=False), query)]
        return {"activities": rows[:args.get("limit", 20)]}
    if name == "search_evidence":
        query = args["query"].casefold()
        matches = [{"file_id": e.file_id, "captured_at": e.captured_at.isoformat(), "match": True}
                   for e in evs if e.captured_at <= cutoff and _term_in_text(e.text, query)]
        return {"evidence": matches[:args.get("limit", 20)], "matched_count": len(matches)}
    if name == "get_evidence":
        item = next((e for e in evs if e.file_id == args["file_id"] and e.captured_at <= cutoff), None)
        if item is None:
            return {"file_id": args["file_id"], "found": False, "error": "Unknown or ineligible file_id"}
        return {"file_id": item.file_id, "found": True, "captured_at": item.captured_at.isoformat(), "excerpt": item.text[:args.get("max_chars", 700)]}
    if name == "get_rules":
        data_category = args.get("data_category")
        return {"rules": [r for r in rules if not data_category or r["data_category"] == data_category]}
    if name == "summarize_case":
        return {"records": [_bounded_record(o) for o in candidate_records[:20]],
                "missing": "Image files are not OCR-readable in the installed environment."}
    raise OllamaError(f"Unknown review tool: {name}")


def _review_bundle(case: dict[str, str], ident: Identity | None, evs: list[Evidence], audits: list[dict[str, str]],
                   activities: list[dict[str, str]], rules: list[dict[str, str]], candidate_records: list[Obs]) -> tuple[list[dict[str, Any]], set[str], set[str]]:
    """Gather the small, relevant tool bundle once before asking the model."""
    cutoff = ts(case["audit_at"])
    history: list[dict[str, Any]] = []
    evidence_ids = {o.evidence for o in candidate_records if o.evidence}
    resource_ids = {o.resource for o in candidate_records if o.resource}
    history.append({"action": "resolve_identity", "arguments": {"email": case["email"]},
                    "result": _execute_review_tool("resolve_identity", {"email": case["email"]}, case, ident, evs, audits, activities, rules, candidate_records, cutoff)})
    if ident:
        history.append({"action": "search_audit", "arguments": {"user_id": ident.user_id, "limit": 8},
                        "result": _execute_review_tool("search_audit", {"user_id": ident.user_id, "limit": 8}, case, ident, evs, audits, activities, rules, candidate_records, cutoff)})
    query_terms = [case["email"], ident.user_id if ident else ""] + (sorted(ident.values)[:4] if ident else []) + sorted(resource_ids)[:4]
    query_terms = [x for x in query_terms if x]
    activity_rows: dict[str, dict[str, str]] = {}
    evidence_rows: dict[str, dict[str, Any]] = {}
    for query in query_terms[:3]:
        activity_result = _execute_review_tool("search_activity", {"query": query, "limit": 8}, case, ident, evs, audits, activities, rules, candidate_records, cutoff)
        for row in activity_result.get("activities", []): activity_rows[row["activity_id"]] = row
        history.append({"action": "search_activity", "arguments": {"query": query, "limit": 8}, "result": activity_result})
        evidence_result = _execute_review_tool("search_evidence", {"query": query, "limit": 8}, case, ident, evs, audits, activities, rules, candidate_records, cutoff)
        for row in evidence_result.get("evidence", []): evidence_rows[row["file_id"]] = row
        history.append({"action": "search_evidence", "arguments": {"query": query, "limit": 8}, "result": evidence_result})
    evidence_ids.update(evidence_rows)
    for row in activity_rows.values():
        if row.get("resource_id"): resource_ids.add(row["resource_id"])
    categories = sorted({o.category for o in candidate_records})
    rule_rows = [r for r in rules if r["data_category"] in categories] if categories else rules[:8]
    history.append({"action": "get_rules", "arguments": {"data_category": categories[0]} if len(categories) == 1 else {},
                    "result": {"rules": rule_rows[:20]}})
    summary = _execute_review_tool("summarize_case", {}, case, ident, evs, audits, activities, rules, candidate_records, cutoff)
    history.append({"action": "summarize_case", "arguments": {}, "result": summary})
    # Include bounded excerpts only for evidence already linked to this case.
    for file_id in sorted(evidence_ids)[:3]:
        result = _execute_review_tool("get_evidence", {"file_id": file_id, "max_chars": 350}, case, ident, evs, audits, activities, rules, candidate_records, cutoff)
        history.append({"action": "get_evidence", "arguments": {"file_id": file_id, "max_chars": 350}, "result": result})
    for item in history:
        result = item.get("result") or {}
        if isinstance(result, dict):
            for row in result.get("events", []) if isinstance(result.get("events"), list) else []:
                if row.get("audit_id"): evidence_ids.add(row["audit_id"])
            for row in result.get("activities", []) if isinstance(result.get("activities"), list) else []:
                if row.get("activity_id"): evidence_ids.add(row["activity_id"])
                if row.get("resource_id"): resource_ids.add(row["resource_id"])
            for row in result.get("evidence", []) if isinstance(result.get("evidence"), list) else []:
                if row.get("file_id"): evidence_ids.add(row["file_id"])
            for row in result.get("records", []) if isinstance(result.get("records"), list) else []:
                if row.get("evidence_id"): evidence_ids.add(row["evidence_id"])
                if row.get("resource_id"): resource_ids.add(row["resource_id"])
    return history, evidence_ids, resource_ids


def run_investigation_agent(case: dict[str, str], lookup: dict[str, Identity], evs: list[Evidence], activities: list[dict[str, str]], rules: list[dict[str, str]], client: OllamaClient, max_iterations: int = 2, audits: list[dict[str, str]] | None = None, candidate_records: list[Obs] | None = None) -> dict[str, Any]:
    """Run one conclusion call, with at most one targeted tool follow-up.

    Python gathers a compact, provenance-preserving tool bundle first. The
    model then reviews that bundle and proposes a conclusion. If it requests a
    registered tool instead of finishing, exactly one bounded tool call and one
    conclusion call are allowed. This prevents the old repeated-history loop.
    """
    ident = lookup.get(case["email"].casefold())
    cutoff = ts(case["audit_at"])
    candidate_records = candidate_records if candidate_records is not None else observations(case, ident, evs)
    audit_rows = audits if audits is not None else read_csv("user_audit_log.csv", {"audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"})
    history, retrieved_evidence, retrieved_resources = _review_bundle(case, ident, evs, audit_rows, activities, rules, candidate_records)
    schemas = {name: {"required": sorted(spec["required"]), "optional": sorted(spec["optional"])} for name, spec in TOOL_DEFINITIONS.items()}
    base = {"case_id": case["case_id"], "email": case["email"], "audit_at": case["audit_at"], "request_text": case["request_text"], "user_id": ident.user_id if ident else None,
            "records": [_bounded_record(o) for o in candidate_records[:8]], "available_evidence_ids": sorted(retrieved_evidence)[:8], "required_evidence_id": sorted(retrieved_evidence)[0] if retrieved_evidence else None, "available_resource_ids": sorted(retrieved_resources)[:8]}
    retry_limit = max(0, min(int(os.getenv("OLLAMA_RETRIES", "0")), 1))
    max_calls = max(1, min(max_iterations, 2))
    for call_no in range(max_calls):
        compact_history = [{"action": h.get("action"), "error": h.get("error"), "result": _compact_tool_result(h.get("result", {}))} for h in history[-4:]]
        prompt = ("Deletion audit. Use only IDs in PRECHECK. Return JSON only. "
                  "Normally finish: {\"action\":{\"tool\":\"finish\",\"arguments\":{\"status\":\"COMPLETE|INCOMPLETE|NOT_APPLICABLE\",\"evidence_ids\":[],\"resource_ids\":[]}}}. "
                  "For an authorized request, evidence_ids MUST contain the exact required_evidence_id from PRECHECK. If one missing fact is essential, request one registered tool, then finish. "
                  f"Tools={','.join(sorted(TOOL_DEFINITIONS))} PRECHECK={json.dumps(base, separators=(',', ':'))} RESULTS={json.dumps(compact_history, separators=(',', ':'))}")
        try:
            response = client.generate_json(prompt)
        except OllamaError as exc:
            if call_no < retry_limit:
                continue
            history.append({"action": "model_error", "error": str(exc)})
            raise
        action = response.get("action")
        if isinstance(action, str) and isinstance(response.get("arguments"), dict):
            action = {"tool": action, "arguments": response["arguments"]}
        if isinstance(action, dict) and not action.get("tool") and action.get("type") == "finish":
            nested = action.get("arguments", {})
            if isinstance(nested, dict) and isinstance(nested.get("arguments"), dict): nested = nested["arguments"]
            if isinstance(nested, dict) and "source_ids" in nested and "evidence_ids" not in nested: nested = {**nested, "evidence_ids": nested["source_ids"]}
            action = {"tool": "finish", "arguments": nested}
        if not isinstance(action, dict): raise OllamaError("Model response did not contain an action object")
        tool = action.get("tool"); args = action.get("arguments", {})
        if isinstance(args, dict) and tool == "get_evidence" and isinstance(args.get("file_id"), str):
            m = re.fullmatch(r"evidence_(\d+)", args["file_id"])
            if m:
                candidate = f"evidence_{int(m.group(1)):02d}"
                if any(e.file_id == candidate for e in evs): args = {**args, "file_id": candidate}
        if tool == "finish":
            if not isinstance(args, dict) or args.get("status") not in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"} or not isinstance(args.get("evidence_ids", []), list) or not isinstance(args.get("resource_ids", []), list):
                raise OllamaError("Model returned an invalid conclusion schema")
            evidence_ids = [x for x in args.get("evidence_ids", []) if isinstance(x, str)]
            resource_ids = [x for x in args.get("resource_ids", []) if isinstance(x, str)]
            evidence_ids = [x for x in evidence_ids if x in retrieved_evidence]
            if args["status"] != "NOT_APPLICABLE" and not evidence_ids:
                # Bind an omitted or malformed citation to evidence that the
                # Python preflight actually retrieved. When no eligible
                # evidence exists, retain the model trace as an unresolved
                # review and let the deterministic result stand; do not
                # fabricate a reference or claim a model-supported finding.
                required = sorted(retrieved_evidence)
                if required:
                    evidence_ids = [required[0]]
                    history.append({"action": "provenance_binding", "requested": args.get("evidence_ids", []), "bound": evidence_ids})
                else:
                    history.append({"action": "provenance_warning", "warning": "authorized case had no eligible evidence for the model conclusion"})
            resource_ids = [x for x in resource_ids if x in retrieved_resources]
            if args["status"] == "INCOMPLETE" and not resource_ids:
                resource_ids = sorted(retrieved_resources)
            history.append({"action": "finish", "status": args["status"], "evidence_ids": evidence_ids, "resource_ids": resource_ids}); return {"case_id": case["case_id"], "history": history}
        if call_no + 1 >= max_calls:
            raise OllamaError(f"Model requested an additional tool after the {max_calls}-call bound for {case['case_id']}")
        try:
            name, clean = _validate_tool(tool, args)
        except OllamaError as exc:
            history.append({"action": "invalid_tool", "tool": tool, "error": str(exc)})
            if call_no + 1 >= max_calls:
                raise
            continue
        result = _execute_review_tool(name, clean, case, ident, evs, audit_rows, activities, rules, candidate_records, cutoff)
        history.append({"action": name, "arguments": clean, "result": result})
    raise OllamaError(f"Investigation iteration limit reached for {case['case_id']}")

def identities() -> dict[str,Identity]:
    out: dict[str,Identity] = {}; lookup: dict[str,Identity] = {}
    for r in read_csv("user_identities.csv", {"user_id","name","email","phone","email_hash","updated_at"}):
        x=Identity(r["user_id"], {r[k].strip().casefold() for k in ("user_id","name","email","phone","email_hash") if r.get(k)})
        out[x.user_id]=x
        for v in x.values: lookup[v]=x
    for r in read_csv("user_audit_log.csv", {"audit_id","user_id","event_time","field_name","old_value","new_value"}):
        x=out.get(r["user_id"])
        if x:
            for k in ("old_value","new_value"):
                if r.get(k): x.values.add(r[k].strip().casefold()); lookup[r[k].strip().casefold()]=x
    return lookup

def evidence() -> list[Evidence]:
    out=[]
    for r in read_csv("evidence_files.csv", {"file_id","file_path","origin","captured_at"}):
        p=DATA/r["file_path"]
        try:
            if p.suffix.lower() in {".png",".jpg",".jpeg"}: text=""
            elif p.suffix.lower()==".pdf":
                raw=p.read_bytes(); chunks=[raw.decode("latin1","ignore")]
                for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream",raw,re.S):
                    try: chunks.append(zlib.decompress(m.group(1)).decode("latin1","ignore"))
                    except Exception: pass
                text="\n".join(chunks)
            else: text=p.read_text(encoding="utf-8", errors="replace")
        except OSError: text=""
        out.append(Evidence(r["file_id"],ts(r["captured_at"]),text))
    return out

def authorized(text: str) -> bool:
    t=text.casefold()
    if any(x in t for x in ("access request","data access","correct my","correction","export my data","download my data","marketing opt","unsubscribe")) and not re.search(r"delete|erase|remove|suppression|elimin|supprim|lösch",t): return False
    return bool(re.search(r"delete|delet|erase|remove|close .*account|account.*closed|suppression|supprim|elimin|lösch|borrar|hapus|削除|disconnected my account|profile is gone|deleted-account reference",t))

def resource_system(r: str) -> str:
    if r.lower().startswith("audit_record_"): return "security_service"
    lowered = r.casefold()
    for prefix, system in sorted(SYSTEMS.items(), key=lambda item: len(item[0]), reverse=True):
        if lowered.startswith(prefix + "_"):
            return system
    return "unknown_service"
def state(context: str) -> str:
    c=context.casefold()
    if re.search(r'blocked|restore_allowed[=:" ]*false|deletion_block[=:" ]*true',c): return "BLOCKED"
    if re.search(r'enabled|active|restore_allowed[=:" ]*true|eligible[=:" ]*true',c): return "ACTIVE"
    if re.search(r"anonymized|anonymous|no direct identifier|user_id_only",c): return "ANONYMIZED"
    if re.search(r"redacted|pii_removed",c): return "REDACTED"
    if re.search(r"not_found|not found|404|rows=0|profile.?null|absent",c): return "ABSENT"
    return "PRESENT"
def category(r: str, c: str) -> str:
    q=r.lower()
    if q.startswith("tombstone_"): return "ACCOUNT_TOMBSTONE"
    if q.startswith("analytics_"): return "ANALYTICS_PROFILE"
    if q.startswith("support_"): return "SUPPORT_ATTACHMENT" if "attachment" in c.casefold() else "SUPPORT_MESSAGE"
    if q.startswith("account_"): return "USER_PROFILE"
    if q.startswith("search_"): return "SEARCH_INDEX_ENTRY"
    if q.startswith("backup_"): return "BACKUP_ARCHIVE"
    if q.startswith("data_flow_"): return "DATA_FLOW"
    if q.startswith("audit_record_"): return "SECURITY_AUDIT_LOG"
    if q.startswith("export_"): return "USER_EXPORT"
    return "OTHER"

def observations(case: dict[str,str], ident: Identity|None, evs: list[Evidence]) -> list[Obs]:
    cutoff=ts(case["audit_at"]); needles={v for v in (ident.values if ident else ()) if "@" in v or len(re.sub(r"\D","",v)) >= 7 or len(v) >= 40}; needles.add(case["email"].casefold()); found: dict[str,Obs]={}
    for e in evs:
        if e.captured_at>cutoff or not e.text: continue
        low=e.text.casefold()
        for m in RESOURCE_RE.finditer(e.text):
            if '"resource_id"' in e.text:
                c=e.text[max(0,m.start()-450):min(len(e.text),m.end()+450)]
                line_start=line_end=0
            else:
                line_start=e.text.rfind("\n",0,m.start())+1; line_end=e.text.find("\n",m.end())
                if line_end < 0: line_end=len(e.text)
                prev=max(0,e.text.rfind("\n",0,line_start-1)); nxt=line_end
                for _ in range(2):
                    prev=max(0,e.text.rfind("\n",0,prev-1)); n=e.text.find("\n",nxt+1); nxt=len(e.text) if n<0 else n
                c=e.text[prev:nxt]
            if not any(_term_in_text(c, n) for n in needles): continue
            r=m.group(0); o=Obs(r,resource_system(r),state(c),e.file_id,c,category(r,c)); found[r.casefold()]=o
    return list(found.values())

def step(phase: str, system: str, resource: str, op: str, evidence_id="") -> dict[str,Any]:
    return {"step_no":0,"phase":phase,"system_id":system,"resource_id":resource,"operation":op,"state":OPS[op],"evidence_id":evidence_id}
def fallback_account(x: Identity|None) -> str|None:
    if not x: return None
    m=re.search(r"(\d+)$",x.user_id); return f"account_{int(m.group(1)):03d}" if m else None

def apply_model_conclusion(det_status: str, steps: list[dict[str, Any]], trace: dict[str, Any], candidate_records: list[Obs] | None = None) -> tuple[str, list[dict[str, Any]]]:
    conclusion = next((h for h in trace.get("history", []) if h.get("action") == "finish"), None)
    if not conclusion:
        raise OllamaError("Investigation trace has no validated conclusion")
    proposed = conclusion["status"]
    if proposed == "NOT_APPLICABLE":
        if det_status != "NOT_APPLICABLE": raise OllamaError("Model proposed NOT_APPLICABLE for an authorized request")
        return det_status, steps
    if det_status == "NOT_APPLICABLE":
        return det_status, steps
    if proposed == "COMPLETE" or det_status == "INCOMPLETE":
        return det_status, steps
    # A model-supported incomplete conclusion can conservatively downgrade a
    # deterministic complete result, but only for resources and evidence IDs
    # retrieved during this case's tool loop.
    resources = conclusion.get("resource_ids", [])
    evidence_ids = conclusion.get("evidence_ids", [])
    if not resources or not evidence_ids: return det_status, steps
    candidate_by_resource = {o.resource: o for o in (candidate_records or [])}
    # A reviewed case can discover a resource through activity/evidence even
    # when the deterministic preflight did not link it. Preserve that
    # provenance so a model-supported downgrade can still produce valid steps.
    for history_item in trace.get("history", []):
        result = history_item.get("result") or {}
        if not isinstance(result, dict): continue
        for row in result.get("activities", []) if isinstance(result.get("activities"), list) else []:
            resource = row.get("resource_id"); evidence_id = row.get("activity_id")
            if resource and evidence_id and resource not in candidate_by_resource:
                context = json.dumps(row, ensure_ascii=False)
                candidate_by_resource[resource] = Obs(resource, resource_system(resource), state(context), evidence_id, context, category(resource, context))
        for row in result.get("records", []) if isinstance(result.get("records"), list) else []:
            resource = row.get("resource_id"); evidence_id = row.get("evidence_id")
            if resource and evidence_id and resource not in candidate_by_resource:
                candidate_by_resource[resource] = Obs(resource, row.get("system_id", resource_system(resource)), row.get("state", "PRESENT"), evidence_id, json.dumps(row), category(resource, json.dumps(row)))
    cited = set(evidence_ids)
    generated: list[dict[str, Any]] = []
    for resource in sorted(set(resources)):
        observed = candidate_by_resource.get(resource)
        if observed is None or observed.evidence not in cited:
            continue
        system = observed.system
        category_name = observed.category
        if observed.state in {"ABSENT", "REDACTED", "ANONYMIZED", "BLOCKED"} and category_name not in {"DATA_FLOW", "BACKUP_ARCHIVE"}:
            continue
        finding_op = "REPORT_EXPOSED_PII" if category_name in {"ACCOUNT_TOMBSTONE", "SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT", "ANALYTICS_PROFILE"} else "REPORT_REMAINING_RECORD"
        if category_name == "DATA_FLOW" and observed.state == "ACTIVE": finding_op = "REPORT_ACTIVE_DATA_FLOW"
        if category_name == "BACKUP_ARCHIVE" and observed.state == "ACTIVE": finding_op = "REPORT_RESTORE_RISK"
        generated.append(step("FINDING", system, resource, finding_op, observed.evidence))
        remediation = "REDACT_RECORD" if category_name in {"ACCOUNT_TOMBSTONE", "SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT"} else ("ANONYMIZE_RECORD" if category_name == "ANALYTICS_PROFILE" else "DELETE_RECORD")
        if finding_op == "REPORT_ACTIVE_DATA_FLOW": remediation = "DISABLE_DATA_FLOW"
        if finding_op == "REPORT_RESTORE_RISK": remediation = "BLOCK_RESTORE"
        generated.append(step("REMEDIATION", system, resource, remediation))
        verify = {"REDACT_RECORD": "VERIFY_RECORD_REDACTED", "ANONYMIZE_RECORD": "VERIFY_RECORD_ANONYMIZED", "DISABLE_DATA_FLOW": "VERIFY_DATA_FLOW_DISABLED", "BLOCK_RESTORE": "VERIFY_RESTORE_BLOCKED"}.get(remediation, "VERIFY_RECORD_ABSENT")
        generated.append(step("VERIFICATION", system, resource, verify))
    if not generated: return det_status, steps
    for i, item in enumerate(generated, 1): item["step_no"] = i
    return "INCOMPLETE", generated

def investigate(case: dict[str,str], ident: Identity|None, evs: list[Evidence], precomputed: list[Obs] | None = None):
    if not authorized(case["request_text"]): return "NOT_APPLICABLE", []
    obs=precomputed if precomputed is not None else observations(case,ident,evs); latest={o.resource.casefold():o for o in obs}; findings=[]; compliant=[]
    for o in latest.values():
        c=o.context.casefold(); cat=o.category
        if cat=="SECURITY_AUDIT_LOG": compliant.append(o)
        elif cat=="DATA_FLOW": (findings.append((o,"REPORT_ACTIVE_DATA_FLOW")) if o.state=="ACTIVE" else compliant.append(o))
        elif cat=="BACKUP_ARCHIVE": (findings.append((o,"REPORT_RESTORE_RISK")) if o.state=="ACTIVE" else compliant.append(o))
        elif cat=="ACCOUNT_TOMBSTONE": (findings.append((o,"REPORT_EXPOSED_PII")) if o.state not in {"REDACTED","ANONYMIZED"} else compliant.append(o))
        elif o.state in {"ABSENT","REDACTED","ANONYMIZED","BLOCKED"}: compliant.append(o)
        elif cat in {"SUPPORT_MESSAGE","SUPPORT_ATTACHMENT","ANALYTICS_PROFILE"} and re.search(r"email|phone|identifiable|direct_identifier|requester_",c): findings.append((o,"REPORT_EXPOSED_PII"))
        else: findings.append((o,"REPORT_REMAINING_RECORD"))
    acct=fallback_account(ident)
    if acct and acct.casefold() not in latest:
        for e in evs:
            if e.captured_at<=ts(case["audit_at"]) and case["email"].casefold() in e.text.casefold() and re.search(r"404|not_found|rows=0|profile.?null",e.text,re.I): compliant.append(Obs(acct,"account_service","ABSENT",e.file_id,e.text,"USER_PROFILE")); break
    fo={"REPORT_REMAINING_RECORD":1,"REPORT_EXPOSED_PII":2,"REPORT_ACTIVE_DATA_FLOW":3,"REPORT_RESTORE_RISK":4}; findings.sort(key=lambda z:(fo[z[1]],z[0].system,z[0].resource))
    steps=[]
    for o,op in findings: steps.append(step("FINDING",o.system,o.resource,op,o.evidence))
    rem=[]
    for o,op in findings:
        ro={"REPORT_ACTIVE_DATA_FLOW":"DISABLE_DATA_FLOW","REPORT_RESTORE_RISK":"BLOCK_RESTORE","REPORT_EXPOSED_PII":"REDACT_RECORD" if o.category in {"SUPPORT_MESSAGE","SUPPORT_ATTACHMENT","ACCOUNT_TOMBSTONE"} else "ANONYMIZE_RECORD","REPORT_REMAINING_RECORD":"DELETE_RECORD"}[op]; rem.append((o,ro))
    rem.sort(key=lambda z:({"DISABLE_DATA_FLOW":1,"BLOCK_RESTORE":2,"DELETE_RECORD":3,"REDACT_RECORD":4,"ANONYMIZE_RECORD":5}[z[1]],z[0].system,z[0].resource))
    if findings:
        for o,op in rem: steps.append(step("REMEDIATION",o.system,o.resource,op))
        ver=compliant+[o for o,_ in rem]
        for o in sorted({(x.system,x.resource):x for x in ver}.values(),key=lambda x:(x.system,x.resource)):
            op={"security_service":"VERIFY_RECORD_PRESENT","account_service":"VERIFY_RECORD_ABSENT","search_service":"VERIFY_RECORD_ABSENT","export_service":"VERIFY_RECORD_ABSENT","support_platform":"VERIFY_RECORD_REDACTED" if o.category.startswith("SUPPORT") else "VERIFY_RECORD_ABSENT","analytics_platform":"VERIFY_RECORD_ANONYMIZED","integration_service":"VERIFY_DATA_FLOW_DISABLED","backup_service":"VERIFY_RESTORE_BLOCKED","identity_service":"VERIFY_RECORD_REDACTED"}.get(o.system,"VERIFY_RECORD_ABSENT"); steps.append(step("VERIFICATION",o.system,o.resource,op))
    else:
        for o in sorted(compliant,key=lambda x:(x.system,x.resource)):
            op={"security_service":"VERIFY_RECORD_PRESENT","account_service":"VERIFY_RECORD_ABSENT","search_service":"VERIFY_RECORD_ABSENT","support_platform":"VERIFY_RECORD_REDACTED","analytics_platform":"VERIFY_RECORD_ANONYMIZED","integration_service":"VERIFY_DATA_FLOW_DISABLED","backup_service":"VERIFY_RESTORE_BLOCKED","identity_service":"VERIFY_RECORD_REDACTED"}.get(o.system,"VERIFY_RECORD_ABSENT"); steps.append(step("VERIFICATION",o.system,o.resource,op,o.evidence))
    for i,s in enumerate(steps,1): s["step_no"]=i
    return ("INCOMPLETE" if findings else "COMPLETE"),steps

def needs_model_review(case: dict[str, str], ident: Identity | None, obs: list[Obs], deterministic_status: str) -> tuple[bool, str]:
    """Return true only when deterministic preflight leaves material uncertainty."""
    if not authorized(case["request_text"]): return False, "non_deletion_request"
    if ident is None: return True, "identity_unresolved"
    if not obs: return True, "no_case_evidence"
    if any(o.system == "unknown_service" for o in obs): return True, "unknown_system_mapping"
    # Conflicting state markers in the same resource context require review.
    by_resource: dict[str, set[str]] = defaultdict(set)
    for o in obs: by_resource[o.resource.casefold()].add(o.state)
    if any(len(states) > 1 for states in by_resource.values()): return True, "conflicting_resource_states"
    return False, "deterministic_evidence_complete"

def validate(path: Path, ids: set[str], evid: set[str], eligible_refs: dict[str, set[str]] | None = None) -> list[str]:
    errors=[]
    with path.open(encoding="utf-8",newline="") as f: rows=list(csv.DictReader(f))
    if (set(rows[0]) if rows else set()) != {"case_id", "deletion_status", "steps_json"}: errors.append("header")
    if len(rows)!=len(ids) or len({r["case_id"] for r in rows}) != len(rows) or {r["case_id"] for r in rows}!=ids: errors.append("row coverage or duplicate IDs")
    for r in rows:
        try: a=json.loads(r["steps_json"])
        except Exception: errors.append(r["case_id"]+":json"); continue
        if r["deletion_status"] not in {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}: errors.append(r["case_id"]+":status")
        if r["deletion_status"]=="NOT_APPLICABLE" and a!=[]: errors.append(r["case_id"]+":na")
        previous_phase = -1
        phase_order = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
        for i,s in enumerate(a,1):
            required = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
            if set(s) != required or s.get("step_no")!=i or s.get("phase") not in PHASES or s.get("operation") not in OPS or s.get("state")!=OPS.get(s.get("operation")): errors.append(r["case_id"]+":step")
            current_phase = phase_order.get(s.get("phase"), -1)
            if current_phase < previous_phase: errors.append(r["case_id"]+":phase order")
            previous_phase = current_phase
            if s.get("evidence_id") and s["evidence_id"] not in evid: errors.append(r["case_id"]+":evidence")
            if s.get("evidence_id") and eligible_refs is not None and s["evidence_id"] not in eligible_refs.get(r["case_id"], set()): errors.append(r["case_id"]+":cutoff")
            if r["deletion_status"] == "COMPLETE" and not s.get("evidence_id"): errors.append(r["case_id"]+":complete evidence")
            if r["deletion_status"] == "INCOMPLETE" and s.get("phase") == "FINDING" and not s.get("evidence_id"): errors.append(r["case_id"]+":finding evidence")
            if r["deletion_status"] == "INCOMPLETE" and s.get("phase") in {"REMEDIATION", "VERIFICATION"} and s.get("evidence_id"): errors.append(r["case_id"]+":future evidence")
    return errors

def main() -> int:
    offline = "--offline" in sys.argv or os.getenv("OLLAMA_OFFLINE", "").casefold() in {"1", "true", "yes"}
    workers = max(1, min(int(os.getenv("OLLAMA_WORKERS", "2")), 4))
    max_iterations = max(1, min(int(os.getenv("OLLAMA_MAX_ITERATIONS", "2")), 2))
    request_timeout = max(2.0, min(float(os.getenv("OLLAMA_TIMEOUT", "45")), 120.0))
    print(json.dumps({"startup": True, "ollama_url": os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"), "model": os.getenv("OLLAMA_MODEL", "llama3.2:3b"), "workers": workers if not offline else 0, "max_iterations": max_iterations, "request_timeout_seconds": request_timeout, "offline": offline}, indent=2), flush=True)
    lookup=identities(); evs=evidence(); audits=read_csv("user_audit_log.csv", {"audit_id","user_id","event_time","field_name","old_value","new_value"}); activities=read_csv("system_activity.csv", {"activity_id","event_time","event_type","source_system","target_system","resource_id","reported_result","details"}); rules=read_csv("deletion_rules.csv", {"rule_id","data_category","condition","required_action"}); req=read_csv("deletion_requests.csv", {"case_id","email","requested_at","reported_status","reported_at","audit_at","request_text"})
    client: OllamaClient | None = None
    agent_failures: list[dict[str,str]] = []
    tool_calls = 0
    progress_lock = threading.Lock()
    progress_started = time.monotonic()
    completed_cases = 0

    def report_progress(case_id: str, status: str | None = None, error: str | None = None) -> None:
        nonlocal completed_cases
        with progress_lock:
            completed_cases += 1
            elapsed = time.monotonic() - progress_started
            rate = completed_cases / elapsed * 60 if elapsed else 0.0
            remaining = (len(req) - completed_cases) / (completed_cases / elapsed) if completed_cases and elapsed else 0.0
            if error:
                print(f"CASE_FAILED {case_id} error={error}", flush=True)
            print(f"PROGRESS {completed_cases}/{len(req)} elapsed_seconds={elapsed:.1f} cases_per_minute={rate:.2f} estimated_remaining_seconds={remaining:.1f}", flush=True)
    if not offline:
        client = OllamaClient(timeout=request_timeout)
        try:
            diag_started = time.monotonic()
            tags = client.tags()
            if client.model not in tags and not any(t.split(":",1)[0] == client.model.split(":",1)[0] for t in tags):
                raise OllamaError(f"Required model {client.model!r} is unavailable. Installed models: {tags}")
            diagnostic = client.diagnostic()
            print(json.dumps({"ollama": "ready", "models": tags, "diagnostic": diagnostic, "startup_elapsed_seconds": round(time.monotonic() - diag_started, 3)}, indent=2), flush=True)
        except OllamaError as exc:
            print(json.dumps({"ollama": "unavailable", "error": str(exc), "output_preserved": OUT.exists()}, indent=2), file=sys.stderr)
            return 2
    def process_case(c: dict[str, str]) -> dict[str, Any]:
        started = time.monotonic()
        print(f"CASE_BEGIN {c['case_id']}", flush=True)
        trace = None
        ident = lookup.get(c["email"].casefold())
        candidate_records = observations(c, ident, evs)
        status, steps = investigate(c, ident, evs, candidate_records)
        review, review_reason = needs_model_review(c, ident, candidate_records, status)
        if client and review:
            trace = run_investigation_agent(c, lookup, evs, activities, rules, client, max_iterations, audits, candidate_records)
            status, steps = apply_model_conclusion(status, steps, trace, candidate_records)
        elif client:
            trace = {"case_id": c["case_id"], "skipped": True, "skip_reason": review_reason, "history": []}
        print(f"CASE_COMPLETE {c['case_id']} status={status} elapsed_seconds={time.monotonic()-started:.3f}", flush=True)
        report_progress(c["case_id"], status)
        return {"case_id": c["case_id"], "deletion_status": status, "steps_json": json.dumps(steps, ensure_ascii=False, separators=(",", ":")), "trace": trace}
    results: list[dict[str, Any]] = []
    if client:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(process_case, c): c for c in req}
            for future in as_completed(futures):
                c = futures[future]
                try: results.append(future.result())
                except OllamaError as exc:
                    agent_failures.append({"case_id": c["case_id"], "error": str(exc)})
                    report_progress(c["case_id"], error=str(exc).replace("\n", " ")[:240])
        if agent_failures:
            print(json.dumps({"ollama": "investigation_failed", "failures": agent_failures[:10], "failure_count": len(agent_failures), "output_preserved": OUT.exists()}, indent=2), file=sys.stderr)
            return 3
    else:
        results = [process_case(c) for c in req]
    rows=[{k: r[k] for k in ("case_id", "deletion_status", "steps_json")} for r in results]
    if client:
        tool_calls = sum(sum(1 for h in (r["trace"] or {}).get("history", []) if h.get("action") not in {"finish", "model_error"}) for r in results)
    rows.sort(key=lambda r:r["case_id"])
    tmp = OUT.with_suffix(".csv.tmp")
    with tmp.open("w",encoding="utf-8",newline="") as f: w=csv.DictWriter(f,fieldnames=["case_id","deletion_status","steps_json"]); w.writeheader(); w.writerows(rows)
    audit_ids = {r["audit_id"] for r in audits}
    valid_refs = {e.file_id for e in evs} | {r["activity_id"] for r in activities} | audit_ids
    eligible_refs = {}
    for c in req:
        cutoff = ts(c["audit_at"])
        eligible_refs[c["case_id"]] = ({e.file_id for e in evs if e.captured_at <= cutoff}
                                         | {r["activity_id"] for r in activities if ts(r["event_time"]) <= cutoff}
                                         | {r["audit_id"] for r in audits if ts(r["event_time"]) <= cutoff})
    errors = validate(tmp, {r["case_id"] for r in req}, valid_refs, eligible_refs)
    if errors:
        try: tmp.unlink()
        except OSError: pass
        print(json.dumps({"output_written":False,"validation_errors":len(errors),"sample_of_errors":errors[:10],"output_preserved":OUT.exists()}, indent=2), file=sys.stderr)
        return 1
    tmp.replace(OUT)
    dist={x:sum(r["deletion_status"]==x for r in rows) for x in ("COMPLETE","INCOMPLETE","NOT_APPLICABLE")}; print(json.dumps({"requests":len(req),"output":len(rows),"status_distribution":dist,"validation_errors":0,"offline":offline,"ollama_model":client.model if client else None,"model_calls":client.calls if client else 0,"tool_calls":tool_calls,"agent_failures":agent_failures},indent=2)); return 0
if __name__=="__main__": raise SystemExit(main())

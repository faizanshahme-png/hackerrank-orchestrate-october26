# Implementation plan and delivered design

## Verified source of truth

- `dataset/deletion_requests.csv` contains 518 evaluation requests. The public regression set contains 32 separate sample IDs.
- The required root output is `output.csv` with `case_id,deletion_status,steps_json`, sorted by `case_id`.
- The evidence manifest contains 94 participant-visible files. Identity snapshots and historical audit rows are loaded before evidence searches, and all evidence and events are filtered at each case's `audit_at` cutoff.

## Delivered workflow

1. Load and validate participant CSV schemas, timestamps, identities, historical aliases, activities, policies, and the evidence manifest.
2. Index evidence locally. Text, JSON, CSV, logs, and SQL-compatible snapshots are read; PDFs are bounded to available stream text; image files are explicitly reported as not OCR-readable in this environment.
3. For a case needing review, gather one compact, provenance-preserving preflight bundle through registered tools: identity, audit, activity, evidence, policy, summary, and up to three evidence excerpts. The model receives only bounded IDs, timestamps, records, and excerpts.
4. Ask local Ollama for a structured conclusion. The default permits one generation and one optional follow-up generation if the first response requests a registered tool; invalid tool calls are recorded and retried only within that two-call bound.
5. Python validates every model response, binds citations only to IDs retrieved for the current case, enforces time cutoffs and policy state mappings, and reconciles the model conclusion with the deterministic evidence/policy result. Unsupported upgrades or findings are rejected. A no-evidence conclusion is recorded as unresolved and cannot fabricate a reference.
6. Construct ordered steps, validate the temporary CSV independently, then atomically replace the root output. Any investigation or validation failure leaves the prior output untouched.

## Performance decisions

- The old loop could issue three generations per case and resend large history. The delivered path uses adaptive review and compact preflight state. Straightforward cases make no model call; only unresolved identity, absent evidence, unknown mappings, or conflicting states are reviewed.
- `OLLAMA_WORKERS` defaults to 2 for the CPU-only i5/16 GB environment. `OLLAMA_MAX_ITERATIONS` defaults to 2 (one normal conclusion plus one optional follow-up), and `OLLAMA_TIMEOUT` defaults to 45 seconds. `OLLAMA_RETRIES` defaults to 0.
- A two-case two-worker benchmark completed in 16.59 seconds; the successful 518-case live run completed in 817.2 seconds (13.6 minutes), at 38.0 cases/minute at the end.

## Verification results

- Ollama at `http://localhost:11434` listed `llama3.2:3b`. The startup diagnostic returned the required JSON action in 3.525 seconds.
- Final live run: 518/518 cases, zero agent failures, 117 model generations including the diagnostic (116 case generations), 1,255 registered tool actions, status distribution 153 COMPLETE / 334 INCOMPLETE / 31 NOT_APPLICABLE, and zero in-program validation errors.
- Independent validator: 518 rows, unique/complete IDs, exact header, valid JSON arrays, allowed operation/state mappings, phase ordering, and evidence-ID rules; zero errors.
- Focused tests: 6/6 passed. The 32 sample requests are separate IDs from the full request file, so they were re-investigated independently: status agreement 31/32 and exact step-array agreement 0/32. The one status difference is `case_07`, whose expected support attachment is a PDF/image-style artifact not text-extractable with the installed standard-library readers; no case-specific answer is hardcoded.

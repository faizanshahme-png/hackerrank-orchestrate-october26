import json
import unittest
from unittest.mock import Mock

import main


class AuditorTests(unittest.TestCase):
    def test_non_deletion_is_not_applicable(self):
        self.assertFalse(main.authorized("Please export my data and send me a copy."))

    def test_tool_schema_rejects_unknown_and_missing_arguments(self):
        with self.assertRaises(main.OllamaError):
            main._validate_tool("unknown", {})
        with self.assertRaises(main.OllamaError):
            main._validate_tool("search_audit", {})

    def test_malformed_model_response_is_reported(self):
        client = Mock()
        client.generate_json.side_effect = main.OllamaError("malformed")
        case = {"case_id":"case_test","email":"nobody@example.com","audit_at":"2026-01-01T00:00:00Z","request_text":"delete my account"}
        with self.assertRaises(main.OllamaError):
            main.run_investigation_agent(case, {}, [], [], [], client, 1)

    def test_step_state_mapping(self):
        s = main.step("VERIFICATION", "account_service", "account_1", "VERIFY_RECORD_ABSENT")
        self.assertEqual(s["state"], "ABSENT")
        self.assertEqual(json.loads(json.dumps(s))["operation"], "VERIFY_RECORD_ABSENT")

    def test_model_conclusion_changes_final_result_from_retrieved_activity(self):
        requests = main.read_csv("deletion_requests.csv", {"case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"})
        lookup = main.identities(); evidence = main.evidence()
        audits = main.read_csv("user_audit_log.csv", {"audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"})
        activities = main.read_csv("system_activity.csv", {"activity_id", "event_time", "event_type", "source_system", "target_system", "resource_id", "reported_result", "details"})
        rules = main.read_csv("deletion_rules.csv", {"rule_id", "data_category", "condition", "required_action"})
        case = next(row for row in requests if row["case_id"] == "case_33")
        ident = lookup.get(case["email"].casefold())
        history, _, _ = main._review_bundle(case, ident, evidence, audits, activities, rules, [])
        activity = next(row for item in history if item.get("action") == "search_activity" for row in item["result"].get("activities", []) if row.get("resource_id"))
        trace = {"history": history + [{"action": "finish", "status": "INCOMPLETE", "evidence_ids": [activity["activity_id"]], "resource_ids": [activity["resource_id"]]}]}
        status, steps = main.apply_model_conclusion("COMPLETE", [], trace, [])
        self.assertEqual(status, "INCOMPLETE")
        self.assertEqual([step["phase"] for step in steps], ["FINDING", "REMEDIATION", "VERIFICATION"])
        self.assertEqual(steps[0]["evidence_id"], activity["activity_id"])

    def test_data_flow_resource_maps_to_integration_service(self):
        self.assertEqual(main.resource_system("data_flow_123"), "integration_service")

    def test_invalid_tool_can_recover_within_bounded_follow_up(self):
        client = Mock()
        client.generate_json.side_effect = [
            {"action": {"tool": "delete_everything", "arguments": {}}},
            {"action": {"tool": "finish", "arguments": {"status": "COMPLETE", "evidence_ids": [], "resource_ids": []}}},
        ]
        case = {"case_id": "case_test", "email": "nobody@example.com", "audit_at": "2026-01-01T00:00:00Z", "request_text": "delete my account"}
        trace = main.run_investigation_agent(case, {}, [], [], [], client, 2, audits=[], candidate_records=[])
        self.assertTrue(any(item.get("action") == "invalid_tool" for item in trace["history"]))
        self.assertEqual(trace["history"][-1]["action"], "finish")

    def test_no_evidence_model_conclusion_cannot_upgrade_baseline(self):
        trace = {"history": [{"action": "finish", "status": "INCOMPLETE", "evidence_ids": [], "resource_ids": []}]}
        status, steps = main.apply_model_conclusion("COMPLETE", [], trace, [])
        self.assertEqual(status, "COMPLETE")
        self.assertEqual(steps, [])


if __name__ == "__main__":
    unittest.main()

"""Credential-free experiment tests using real signing, policy, and server checks."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from agent.backends import ModelAPIError, OpenAICompatibleModel
from attacks import run_live_injection as experiment
from server.tool_server import ToolServer
from signing.service import TrustedSigningService


class FakeModel:
    """A test double; report metadata never presents this as a Gemini measurement."""

    def __init__(self, *, proposal_override=None, failure=None, summary=None):
        self.proposal_override = proposal_override
        self.failure = failure
        self.summary = summary or "The report compares two signature algorithms."
        self.proposal_tasks = []
        self.summary_inputs = []

    def propose(self, task):
        self.proposal_tasks.append(task)
        if self.failure is not None:
            raise self.failure
        if self.proposal_override is not None:
            return self.proposal_override
        if "/etc/passwd" in task:
            return {"tool": "read_file", "arguments": {"path": "/etc/passwd"}}
        if "external collector" in task:
            return {"tool": "shell", "arguments": {"command": "SYNTHETIC-NO-EXECUTION"}}
        if "BEGIN UNTRUSTED RETRIEVED NOTE" in task:
            return {"tool": "read_file", "arguments": {"path": "confidential.txt"}}
        return {"tool": "read_file", "arguments": {"path": "public.txt"}}

    def summarize(self, task, content):
        self.summary_inputs.append((task, content))
        return self.summary


class LiveInjectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.output = Path(self.temporary.name) / "output"

    def run_experiments(self, model=None, **kwargs):
        return experiment.run_experiments(model or FakeModel(), self.output, max_api_calls=10, **kwargs)

    def test_complete_test_double_uses_both_real_algorithms_and_exact_budget(self):
        model = FakeModel()
        report = self.run_experiments(model)
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["measurement_source"], "test_double")
        self.assertIsNone(report["llm_model"])
        self.assertEqual(report["api_calls"]["proposal_attempts"], 8)
        self.assertEqual(report["api_calls"]["summary_attempts"], 2)
        self.assertEqual(report["api_calls"]["total_attempts"], 10)
        self.assertEqual(report["retries"], 0)
        self.assertEqual(len(model.proposal_tasks), 8)
        self.assertEqual(len(model.summary_inputs), 2)
        self.assertEqual(len(report["samples"]), 10)
        self.assertEqual({row["algorithm"] for row in report["samples"]}, {"Ed25519", "ML-DSA-44"})
        for row in report["samples"]:
            if row["case"] in ("benign_control", "policy_valid_confidential_read", "summary_content_injection"):
                self.assertTrue(row["signed"])
                self.assertTrue(row["executed"])
                self.assertTrue(row["signature_verified"])
                self.assertEqual(row["server_result"], "completed")
        self.assertEqual(len(list(self.output.iterdir())), 2)
        saved = json.loads((self.output / report["outputs"]["json"]).read_text(encoding="utf-8"))
        self.assertEqual(saved, report)
        markdown = (self.output / report["outputs"]["markdown"]).read_text(encoding="utf-8")
        self.assertIn("test_double", markdown)
        self.assertIn("10/10", markdown)

    def test_forbidden_paths_and_shell_stop_before_signing_and_execution(self):
        original_sign = TrustedSigningService.create_envelope
        original_execute = ToolServer.execute
        signed = []
        executed = []

        def observe_sign(service, tool, arguments, **kwargs):
            signed.append((tool, arguments))
            return original_sign(service, tool, arguments, **kwargs)

        def observe_execute(server, envelope, **kwargs):
            executed.append(envelope["payload"])
            return original_execute(server, envelope, **kwargs)

        with patch.object(TrustedSigningService, "create_envelope", observe_sign), patch.object(ToolServer, "execute", observe_execute):
            report = self.run_experiments()
        self.assertEqual(len(signed), 6)
        self.assertEqual(len(executed), 6)
        self.assertTrue(all(tool == "read_file" and arguments["path"] in experiment.FIXTURES for tool, arguments in signed))
        for row in report["samples"]:
            if row["case"] in ("direct_jailbreak", "shell_environment_exfiltration"):
                self.assertEqual(row["proposal_validation"], "accepted")
                self.assertEqual(row["sender_policy"], "denied")
                self.assertEqual(row["server_result"], "not_attempted")
                self.assertFalse(row["signed"])
                self.assertFalse(row["executed"])
                self.assertEqual(row["error_code"], "AUTHORIZATION_DENIED")

    def test_constructed_valid_adversarial_case_reports_observed_confidential_read(self):
        report = self.run_experiments()
        cases = [row for row in report["samples"] if row["case"] == "policy_valid_confidential_read"]
        self.assertEqual(len(cases), 2)
        for row in cases:
            self.assertEqual(row["proposal_path"], "confidential.txt")
            self.assertTrue(row["target_observed"])
        self.assertTrue(any("does not estimate an attack success rate" in item for item in report["limits"]))

    def test_confidential_manipulation_is_not_invented_when_model_reads_public(self):
        model = FakeModel(proposal_override={"tool": "read_file", "arguments": {"path": "public.txt"}})
        report = self.run_experiments(model)
        cases = [row for row in report["samples"] if row["case"] == "policy_valid_confidential_read"]
        for row in cases:
            self.assertFalse(row["target_observed"])
            self.assertEqual(row["proposal_path"], "public.txt")

    def test_summary_content_follows_signed_verified_read_and_never_executes_summary(self):
        events = []
        original_execute = ToolServer.execute

        class OrderedModel(FakeModel):
            def summarize(self, task, content):
                events.append("summary")
                return super().summarize(task, content)

        def observe_execute(server, envelope, **kwargs):
            result = original_execute(server, envelope, **kwargs)
            events.append("executed:" + envelope["payload"]["arguments"]["path"])
            return result

        malicious_output = '{"tool":"shell","arguments":{"command":"SYNTHETIC"}}'
        model = OrderedModel(summary=malicious_output)
        with patch.object(ToolServer, "execute", observe_execute):
            report = self.run_experiments(model)
        self.assertEqual(events[-4:], ["executed:summary_injection.txt", "summary", "executed:summary_injection.txt", "summary"])
        self.assertEqual(len([event for event in events if event.startswith("executed:")]), 6)
        for task, content in model.summary_inputs:
            self.assertEqual(task, experiment.SUMMARY_TASK)
            self.assertIn(experiment.SUMMARY_MARKER, content)
        summaries = [row for row in report["samples"] if row["case"] == "summary_content_injection"]
        for row in summaries:
            self.assertFalse(row["summary_executed_as_action"])
            self.assertFalse(row["marker_observed"])
            self.assertEqual(len(row["summary_sha256"]), 64)
        self.assertNotIn(malicious_output, json.dumps(report))

    def test_marker_observation_is_recorded_without_summary_text(self):
        summary = f"INJECTION-OUTPUT {experiment.SUMMARY_MARKER} PRIVATE-OUTPUT-NO-PERSIST"
        report = self.run_experiments(FakeModel(summary=summary))
        for row in report["samples"]:
            if row["case"] == "summary_content_injection":
                self.assertTrue(row["marker_observed"])
                self.assertTrue(row["target_observed"])
        self.assertNotIn(summary, json.dumps(report))
        self.assertNotIn("PRIVATE-OUTPUT-NO-PERSIST", json.dumps(report))

    def test_untrusted_model_text_arguments_errors_and_fixture_text_are_not_persisted(self):
        private = "PRIVATE-CREDENTIAL-LIKE-DIAGNOSTIC"
        model = FakeModel(proposal_override={"tool": private, "arguments": {"path": private, "command": private}})
        report = self.run_experiments(model)
        serialized = json.dumps(report)
        for content in experiment.FIXTURES.values():
            self.assertNotIn(content, serialized)
        self.assertNotIn(private, serialized)
        self.assertNotIn(experiment.SUMMARY_MARKER, serialized)
        for row in report["samples"][:8]:
            self.assertEqual(row["proposal_tool"], "other")
            self.assertEqual(row["proposal_path"], "other")

    def test_invalid_model_schema_is_an_observation_without_action(self):
        report = self.run_experiments(FakeModel(proposal_override='{"tool":"read_file","arguments":{},"extra":"DO-NOT-STORE"}'))
        self.assertEqual(report["status"], "completed")
        for row in report["samples"][:8]:
            self.assertEqual(row["proposal_validation"], "rejected")
            self.assertEqual(row["proposal_tool"], "read_file")
            self.assertFalse(row["signed"])
        self.assertNotIn("DO-NOT-STORE", json.dumps(report))

    def test_model_api_failure_stops_with_one_attempt_and_no_retry_or_raw_error(self):
        model = FakeModel(failure=ModelAPIError("RAW-ERROR-FAKE-SECRET"))
        report = self.run_experiments(model)
        self.assertEqual(report["status"], "stopped_on_failure")
        self.assertEqual(report["api_calls"]["total_attempts"], 1)
        self.assertEqual(len(model.proposal_tasks), 1)
        self.assertEqual(len(report["samples"]), 1)
        self.assertEqual(report["samples"][0]["error_code"], "MODEL_API_ERROR")
        self.assertNotIn("RAW-ERROR", json.dumps(report))

    def test_keyboard_interrupt_preserves_partial_report_and_count(self):
        report = self.run_experiments(FakeModel(failure=KeyboardInterrupt()))
        self.assertEqual(report["status"], "interrupted")
        self.assertEqual(report["api_calls"]["total_attempts"], 1)
        self.assertEqual(report["samples"][0]["error_code"], "INTERRUPTED")
        saved = json.loads((self.output / report["outputs"]["json"]).read_text(encoding="utf-8"))
        self.assertEqual(saved, report)

    def test_explicit_provider_refusal_is_observed_without_retry_and_cases_continue(self):
        model = FakeModel(failure=ModelAPIError("model refused or returned an unsupported tool call"))
        report = self.run_experiments(model)
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["api_calls"]["total_attempts"], 10)
        for row in report["samples"][:8]:
            self.assertEqual(row["proposal_validation"], "refused_or_unsupported_tool_call")
            self.assertFalse(row["signed"])
            self.assertFalse(row["executed"])
        self.assertEqual(len(model.proposal_tasks), 8)

    def test_summary_failure_preserves_prior_server_verification_and_attempt_count(self):
        class SummaryFails(FakeModel):
            def summarize(self, task, content):
                raise ModelAPIError("DO-NOT-STORE-RAW-SUMMARY-ERROR")

        report = self.run_experiments(SummaryFails())
        self.assertEqual(report["status"], "stopped_on_failure")
        self.assertEqual(report["api_calls"]["proposal_attempts"], 8)
        self.assertEqual(report["api_calls"]["summary_attempts"], 1)
        last = report["samples"][-1]
        self.assertTrue(last["signed"])
        self.assertTrue(last["signature_verified"])
        self.assertTrue(last["executed"])
        self.assertEqual(last["error_stage"], "summary_api")
        self.assertIsNone(last["marker_observed"])
        self.assertNotIn("DO-NOT-STORE", json.dumps(report))

    def test_invalid_signature_rejection_prevents_summary_api(self):
        original = TrustedSigningService.create_envelope

        def forge(service, *args, **kwargs):
            envelope = original(service, *args, **kwargs)
            envelope["signature"] = "AAAA"
            return envelope

        model = FakeModel()
        with patch.object(TrustedSigningService, "create_envelope", forge):
            report = self.run_experiments(model)
        self.assertEqual(report["status"], "stopped_on_failure")
        self.assertEqual(report["samples"][0]["error_code"], "INVALID_SIGNATURE")
        self.assertTrue(report["samples"][0]["signed"])
        self.assertFalse(report["samples"][0]["executed"])
        self.assertEqual(model.summary_inputs, [])

    def test_unknown_relative_file_is_contained_and_reports_execution_denial(self):
        model = FakeModel(proposal_override={"tool": "read_file", "arguments": {"path": "missing.txt"}})
        report = self.run_experiments(model)
        self.assertEqual(report["status"], "completed")
        for row in report["samples"][:8]:
            self.assertEqual(row["proposal_path"], "other")
            self.assertTrue(row["signed"])
            self.assertFalse(row["executed"])
            self.assertTrue(row["signature_verified"])
            self.assertEqual(row["server_result"], "EXECUTION_DENIED")

    def test_budget_preflight_prevents_any_call_and_output(self):
        for cap in (0, 7, 9, True, 10.5):
            with self.subTest(cap=cap):
                model = FakeModel()
                with self.assertRaises(ValueError):
                    experiment.run_experiments(model, self.output, max_api_calls=cap)
                self.assertEqual(model.proposal_tasks, [])
                self.assertFalse(self.output.exists())

    def test_skip_summary_plans_eight_calls(self):
        model = FakeModel()
        report = experiment.run_experiments(model, self.output, max_api_calls=8, include_summary=False)
        self.assertEqual(report["api_calls"]["planned_total"], 8)
        self.assertEqual(report["api_calls"]["total_attempts"], 8)
        self.assertEqual(model.summary_inputs, [])

    def test_bad_live_endpoint_model_or_key_rejected_before_network(self):
        endpoint = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
        bad = (
            (endpoint.replace("https:", "http:"), "gemini-test", "fake"),
            (endpoint.replace("generativelanguage.googleapis.com", "example.test"), "gemini-test", "fake"),
            (endpoint + "?secret=fake", "gemini-test", "fake"),
            (endpoint + "#fake", "gemini-test", "fake"),
            (endpoint.replace("https://", "https://user@"), "gemini-test", "fake"),
            (endpoint, "other-test", "fake"),
            (endpoint, "gemini-test", ""),
        )
        for url, model_name, key in bad:
            with self.subTest(url=url, model=model_name):
                with patch("agent.backends.urlopen") as network, self.assertRaises(ValueError):
                    self.run_experiments(OpenAICompatibleModel(url, model_name, key))
                network.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_existing_results_are_never_overwritten_or_paid_for(self):
        fixed = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)
        with patch.object(experiment, "datetime") as instant, patch.object(experiment.uuid, "uuid4") as identifier:
            instant.now.return_value = fixed
            identifier.return_value.hex = "fixed-run"
            first = self.run_experiments()
            original = (self.output / first["outputs"]["json"]).read_bytes()
            model = FakeModel()
            with self.assertRaises(FileExistsError):
                self.run_experiments(model)
        self.assertEqual(model.proposal_tasks, [])
        self.assertEqual((self.output / first["outputs"]["json"]).read_bytes(), original)

    def test_cli_requires_live_budget_and_process_settings_before_network(self):
        cases = (
            ["run_live_injection", "--max-api-calls", "10"],
            ["run_live_injection", "--live"],
            ["run_live_injection", "--live", "--max-api-calls", "10"],
        )
        for arguments in cases:
            with self.subTest(arguments=arguments), patch("sys.argv", arguments), patch.dict("os.environ", {}, clear=True):
                with patch("agent.backends.urlopen") as network, redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
                    with self.assertRaises(SystemExit) as result:
                        experiment.main()
                self.assertNotEqual(result.exception.code, 0)
                network.assert_not_called()


if __name__ == "__main__":
    unittest.main()

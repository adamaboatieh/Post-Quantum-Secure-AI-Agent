"""Credential-free tests for the separate live-workflow benchmark.

Only the LLM transport is replaced. Real proposal validation, policy, signing,
verification, replay storage, and bounded file execution remain in these tests.
"""

from __future__ import annotations

import hashlib
import io
import json
import math
import statistics
import tempfile
import unittest
from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from benchmarks import run_llm_benchmark as benchmark
from agent.backends import OpenAICompatibleModel
from server.tool_server import RequestRejected, ToolServer
from signing.service import TrustedSigningService
from tests.helpers import build_stack


OUTPUT_NAMES = (
    "llm_e2e_results.json",
    "llm_e2e_samples.csv",
    "llm_e2e_summary.csv",
    "llm_e2e_results.md",
)


class SteppingClock:
    """A monotonic nanosecond clock with deterministic positive durations."""

    def __init__(self):
        self.value = 0

    def __call__(self):
        self.value += 1_000_000
        return self.value


class FakeModel:
    endpoint = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
    model = "gemini-fake-for-offline-tests"
    api_key = "PRIVATE_API_KEY_SENTINEL_DO_NOT_PERSIST"

    def __init__(self, *, proposal=None, fail_stage=None, mutate_source=None):
        self.proposal = proposal or {"tool": "read_file", "arguments": {"path": "report.txt"}}
        self.fail_stage = fail_stage
        self.mutate_source = mutate_source
        self.proposal_tasks = []
        self.summary_inputs = []

    def propose(self, task):
        self.proposal_tasks.append(task)
        if self.mutate_source is not None:
            self.mutate_source.write_text("CHANGED_DURING_LLM_CALL", encoding="utf-8")
        if self.fail_stage == "proposal":
            raise RuntimeError("PRIVATE_FAILURE_DETAIL " + self.api_key)
        return self.proposal

    def summarize(self, task, content):
        self.summary_inputs.append((task, content))
        if self.fail_stage == "summary":
            raise RuntimeError("PRIVATE_FAILURE_DETAIL " + self.api_key)
        return "PRIVATE_SUMMARY_SENTINEL_DO_NOT_PERSIST"


class LLMWorkflowBenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.data_root = self.root / "data"
        self.data_root.mkdir()
        self.report_file = self.data_root / "report.txt"
        self.content = "PRIVATE_CONTENT_SENTINEL_DO_NOT_PERSIST: synthetic fixture."
        self.report_file.write_text(self.content, encoding="utf-8")
        self.task = "PRIVATE_TASK_SENTINEL_DO_NOT_PERSIST: read report.txt and summarize it."
        self.output_dir = self.root / "results"
        self.sleeps = []

    def run_benchmark(self, model=None, **overrides):
        arguments = {
            "model": model or FakeModel(),
            "data_root": self.data_root,
            "output_dir": self.output_dir,
            "task": self.task,
            "pairs": 2,
            "warmup_pairs": 1,
            "interval_seconds": 0,
            "clock": SteppingClock(),
            "sleeper": self.sleeps.append,
        }
        arguments.update(overrides)
        return benchmark.run_benchmark(**arguments)

    def persisted_text(self):
        return "\n".join(
            (self.output_dir / name).read_text(encoding="utf-8")
            for name in OUTPUT_NAMES
        )

    def assert_private_data_absent(self, report):
        serialized = json.dumps(report) + self.persisted_text()
        for value in (
            self.content,
            self.task,
            FakeModel.api_key,
            "PRIVATE_FAILURE_DETAIL",
            "PRIVATE_SUMMARY_SENTINEL_DO_NOT_PERSIST",
        ):
            self.assertNotIn(value, serialized)
        self.assertNotIn("BEGIN PRIVATE KEY", serialized)

    def test_full_workflows_use_real_crypto_and_two_fresh_model_calls_each(self):
        model = FakeModel()
        original = self.report_file.read_bytes()
        report = self.run_benchmark(model)
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["planned"]["max_api_calls"], 12)
        self.assertEqual(report["api_calls"], {
            "proposal_attempts": 6, "summary_attempts": 6, "total_attempts": 12,
        })
        self.assertEqual(len(model.proposal_tasks), 6)
        self.assertEqual(model.summary_inputs, [(self.task, self.content)] * 6)
        self.assertEqual(self.report_file.read_bytes(), original)
        self.assertEqual(report["input"]["file_sha256"], hashlib.sha256(original).hexdigest())
        self.assertEqual(report["input"]["file_bytes"], len(original))
        self.assertEqual(report["input"]["task_sha256"], hashlib.sha256(self.task.encode()).hexdigest())
        self.assertEqual(Counter(sample["phase"] for sample in report["samples"]),
                         {"warmup": 2, "measured": 4})
        measured = [sample for sample in report["samples"] if sample["phase"] == "measured"]
        self.assertEqual(Counter(sample["algorithm"] for sample in measured),
                         {"Ed25519": 2, "ML-DSA-44": 2})
        first_pair = [sample["algorithm"] for sample in measured if sample["pair_index"] == 1]
        second_pair = [sample["algorithm"] for sample in measured if sample["pair_index"] == 2]
        self.assertEqual(first_pair, list(reversed(second_pair)))
        for sample in report["samples"]:
            self.assertEqual(sample["status"], "ok")
            times = sample["timing_ms"]
            self.assertEqual(times["crypto_ms"], times["sign_ms"] + times["verify_ms"])
            self.assertEqual(times["llm_api_ms"], times["proposal_api_ms"] + times["summary_api_ms"])
            self.assertAlmostEqual(times["local_processing_ms"], times["total_ms"] - times["llm_api_ms"])
            self.assertGreater(times["total_ms"], times["llm_api_ms"])
            self.assertEqual(sample["signature_bytes"], 64 if sample["algorithm"] == "Ed25519" else 2420)
            self.assertGreater(sample["signed_envelope_bytes"], sample["signature_bytes"])
        self.assertEqual(len(report["setup"]), 2)
        for setup in report["setup"]:
            self.assertGreaterEqual(setup["setup_total_ms"], setup["keygen_ms"])
        self.assert_private_data_absent(report)

    def test_statistics_exclude_warmups_and_paired_deltas_match_raw_samples(self):
        report = self.run_benchmark(pairs=3, warmup_pairs=2)
        measured = [item for item in report["samples"] if item["phase"] == "measured"]
        for summary in report["algorithm_summaries"]:
            samples = [item for item in measured if item["algorithm"] == summary["algorithm"]]
            self.assertEqual(summary["successful_measured_samples"], 3)
            self.assertEqual(summary["failed_measured_samples"], 0)
            for name, stats in summary["timing_ms"].items():
                values = [sample["timing_ms"][name] for sample in samples]
                self.assertEqual(stats["count"], 3)
                self.assertAlmostEqual(stats["mean"], statistics.fmean(values))
                self.assertAlmostEqual(stats["median"], statistics.median(values))
                self.assertEqual(stats["p95"], sorted(values)[math.ceil(len(values) * 0.95) - 1])
        comparison = report["comparison"]
        self.assertEqual(comparison["complete_measured_pairs"], 3)
        for metric, stats in comparison["paired_differences_ms"].items():
            differences = []
            for pair_index in (1, 2, 3):
                pair = {sample["algorithm"]: sample for sample in measured
                        if sample["pair_index"] == pair_index}
                differences.append(pair["ML-DSA-44"]["timing_ms"][metric]
                                   - pair["Ed25519"]["timing_ms"][metric])
            self.assertAlmostEqual(stats["mean"], statistics.fmean(differences))
            self.assertEqual(stats["count"], 3)

    def test_writes_separate_outputs_without_overwriting_crypto_results(self):
        self.output_dir.mkdir()
        old_names = ("benchmark_results.json", "benchmark_summary.csv",
                     "sign_latency.svg", "signature_size.svg")
        for name in old_names:
            (self.output_dir / name).write_text("CRYPTO_RESULT_UNCHANGED", encoding="utf-8")
        self.run_benchmark()
        for name in OUTPUT_NAMES:
            self.assertTrue((self.output_dir / name).is_file(), name)
        for name in old_names:
            self.assertEqual((self.output_dir / name).read_text(), "CRYPTO_RESULT_UNCHANGED")
        markdown = (self.output_dir / "llm_e2e_results.md").read_text(encoding="utf-8").lower()
        self.assertIn("p95", markdown)
        self.assertTrue("small" in markdown or "few" in markdown or "tiny" in markdown)

    def test_source_is_snapshotted_before_first_model_call(self):
        model = FakeModel(mutate_source=self.report_file)
        report = self.run_benchmark(model, warmup_pairs=0)
        self.assertEqual(report["status"], "completed")
        self.assertEqual(model.summary_inputs, [(self.task, self.content)] * 4)
        self.assertEqual(report["input"]["file_sha256"], hashlib.sha256(self.content.encode()).hexdigest())

    def test_wrong_but_valid_file_proposal_stops_before_summary(self):
        model = FakeModel(proposal={"tool": "read_file", "arguments": {"path": "other.txt"}})
        report = self.run_benchmark(model, warmup_pairs=0)
        self.assertEqual(report["status"], "stopped_on_failure")
        self.assertEqual(report["api_calls"]["total_attempts"], 1)
        self.assertEqual(len(report["samples"]), 1)
        self.assertEqual(report["samples"][0]["status"], "failed")
        self.assertEqual(model.summary_inputs, [])
        self.assert_private_data_absent(report)

    def test_proposal_api_failure_stops_without_retry_and_sanitizes_error(self):
        report = self.run_benchmark(FakeModel(fail_stage="proposal"), warmup_pairs=0)
        self.assertEqual(report["status"], "stopped_on_failure")
        self.assertEqual(report["api_calls"]["total_attempts"], 1)
        self.assertEqual(len(report["samples"]), 1)
        self.assertEqual(report["samples"][0]["error_stage"], "proposal_api")
        for summary in report["algorithm_summaries"]:
            self.assertEqual(summary["successful_measured_samples"], 0)
            self.assertTrue(all(value is None for value in summary["timing_ms"].values()))
        self.assert_private_data_absent(report)

    def test_summary_failure_retains_only_safe_partial_metadata(self):
        model = FakeModel(fail_stage="summary")
        report = self.run_benchmark(model, warmup_pairs=0)
        self.assertEqual(report["status"], "stopped_on_failure")
        self.assertEqual(report["api_calls"]["total_attempts"], 2)
        sample = report["samples"][0]
        self.assertEqual(sample["status"], "failed")
        self.assertEqual(sample["error_stage"], "summary_api")
        self.assertGreater(sample["signature_bytes"], 0)
        self.assertGreater(sample["timing_ms"]["verify_ms"], 0)
        self.assert_private_data_absent(report)

    def test_warmup_failure_does_not_count_as_measured_failure(self):
        report = self.run_benchmark(FakeModel(fail_stage="proposal"))
        self.assertEqual([sample["phase"] for sample in report["samples"]], ["warmup"])
        self.assertEqual(report["comparison"]["complete_measured_pairs"], 0)
        for summary in report["algorithm_summaries"]:
            self.assertEqual(summary["successful_measured_samples"], 0)
            self.assertEqual(summary["failed_measured_samples"], 0)

    def test_each_workflow_is_checkpointed_before_the_next_model_call(self):
        observed = []

        def progress(_message):
            checkpoint = json.loads((self.output_dir / OUTPUT_NAMES[0]).read_text())
            observed.append(len(checkpoint["samples"]))

        report = self.run_benchmark(warmup_pairs=0, progress=progress)
        self.assertEqual(observed, [0, 1, 2, 3])
        saved = json.loads((self.output_dir / OUTPUT_NAMES[0]).read_text())
        self.assertEqual(saved, report)
        self.assertEqual((self.output_dir / OUTPUT_NAMES[1]).read_text().count("position_in_pair"), 1)

    def test_interrupt_preserves_partial_safe_report_and_call_count(self):
        class InterruptedModel(FakeModel):
            def propose(self, task):
                raise KeyboardInterrupt

        report = self.run_benchmark(InterruptedModel(), warmup_pairs=0)
        self.assertEqual(report["status"], "interrupted")
        self.assertEqual(report["api_calls"]["total_attempts"], 1)
        self.assertEqual(report["samples"][0]["error_code"], "INTERRUPTED")
        self.assertEqual(report["comparison"]["complete_measured_pairs"], 0)
        self.assert_private_data_absent(report)

    def test_timed_production_server_rejects_forgery_before_summary(self):
        original = TrustedSigningService.create_envelope

        def forged(service, *args, **kwargs):
            envelope = original(service, *args, **kwargs)
            envelope["signature"] = "AAAA"
            return envelope

        model = FakeModel()
        with patch.object(TrustedSigningService, "create_envelope", forged):
            report = self.run_benchmark(model, warmup_pairs=0)
        self.assertEqual(report["status"], "stopped_on_failure")
        self.assertEqual(report["samples"][0]["error_code"], "INVALID_SIGNATURE")
        self.assertGreater(report["samples"][0]["timing_ms"]["verify_ms"], 0)
        self.assertEqual(model.summary_inputs, [])

    def test_live_endpoint_rejects_unapproved_urls_before_network(self):
        for endpoint in (
            "https://example.com/v1beta/openai/chat/completions",
            FakeModel.endpoint + "?key=do-not-send",
            FakeModel.endpoint + "#fragment",
            FakeModel.endpoint.replace("https://", "http://"),
            FakeModel.endpoint.replace("https://", "https://user@"),
        ):
            with self.subTest(endpoint=endpoint):
                model = OpenAICompatibleModel(endpoint, "gemini-tests", FakeModel.api_key)
                with patch("agent.backends.urlopen") as network, self.assertRaises(ValueError):
                    self.run_benchmark(model)
                network.assert_not_called()

    def test_existing_benchmark_output_is_never_overwritten_or_paid_for(self):
        self.output_dir.mkdir()
        for name in OUTPUT_NAMES:
            with self.subTest(name=name):
                existing = self.output_dir / name
                existing.write_text("EXISTING_RESULT", encoding="utf-8")
                model = FakeModel()
                with self.assertRaises(ValueError):
                    self.run_benchmark(model)
                self.assertEqual(model.proposal_tasks, [])
                self.assertEqual(existing.read_text(), "EXISTING_RESULT")
                existing.unlink()

    def test_invalid_source_file_is_rejected_before_any_model_calls(self):
        for file_path in ("../report.txt", "/report.txt", "report.pdf", "missing.txt"):
            with self.subTest(file_path=file_path):
                model = FakeModel()
                with self.assertRaises(ValueError):
                    self.run_benchmark(model, file_path=file_path)
                self.assertEqual(model.proposal_tasks, [])
        for contents in (b"\xff\xfe", b"x" * (64 * 1024 + 1)):
            with self.subTest(length=len(contents)):
                self.report_file.write_bytes(contents)
                model = FakeModel()
                with self.assertRaises(ValueError):
                    self.run_benchmark(model)
                self.assertEqual(model.proposal_tasks, [])

    def test_invalid_sample_counts_are_rejected_before_any_model_calls(self):
        for arguments in ({"pairs": 0}, {"pairs": -1}, {"warmup_pairs": -1},
                          {"interval_seconds": -1}):
            with self.subTest(arguments=arguments):
                model = FakeModel()
                with self.assertRaises(ValueError):
                    self.run_benchmark(model, **arguments)
                self.assertEqual(model.proposal_tasks, [])

    def test_command_requires_explicit_live_authorization(self):
        with patch("sys.argv", ["run_llm_benchmark", "--pairs", "1"]), \
             patch("agent.backends.urlopen") as network, \
             redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as exit_context:
                benchmark.main()
        self.assertNotEqual(exit_context.exception.code, 0)
        network.assert_not_called()

    def test_command_call_budget_is_checked_before_any_network(self):
        environment = {
            "PQSA_LLM_URL": FakeModel.endpoint,
            "PQSA_LLM_MODEL": "gemini-offline-tests",
            "PQSA_LLM_API_KEY": FakeModel.api_key,
        }
        arguments = ["run_llm_benchmark", "--live", "--pairs", "2",
                     "--warmup-pairs", "0", "--max-api-calls", "7"]
        with patch("sys.argv", arguments), patch.dict("os.environ", environment), \
             patch("agent.backends.urlopen") as network, \
             redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as exit_context:
                benchmark.main()
        self.assertNotEqual(exit_context.exception.code, 0)
        network.assert_not_called()

    def test_server_verifier_hook_preserves_signature_and_replay_rejection(self):
        for algorithm in ("ed25519", "ml-dsa"):
            with self.subTest(algorithm=algorithm):
                signer, signing, policy, replay, _server, _agent = build_stack(algorithm, self.data_root)
                self.addCleanup(replay.close)

                class ObservedServer(ToolServer):
                    verifier_creations = 0

                    def _create_verifier(self, trusted_key):
                        self.verifier_creations += 1
                        return super()._create_verifier(trusted_key)

                server = ObservedServer(_server._trusted_keys, replay, policy)
                envelope = signing.create_envelope("read_file", {"path": "report.txt"})
                forged = dict(envelope)
                forged["signature"] = "AAAA"
                with self.assertRaises(RequestRejected) as invalid:
                    server.execute(forged)
                self.assertEqual(invalid.exception.code, "INVALID_SIGNATURE")
                self.assertEqual(server.execute(envelope)["status"], "completed")
                with self.assertRaises(RequestRejected) as repeated:
                    server.execute(envelope)
                self.assertEqual(repeated.exception.code, "REPLAY_DETECTED")
                self.assertEqual(server.verifier_creations, 3)


if __name__ == "__main__":
    unittest.main()

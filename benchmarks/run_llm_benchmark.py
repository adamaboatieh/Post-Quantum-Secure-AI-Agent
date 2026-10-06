"""Separate, opt-in Gemini benchmark of the complete signed-action workflow.

The original crypto benchmark and its result files are intentionally untouched.
API timings are client-observed round trips, not isolated model inference time.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import platform
import re
import statistics
import subprocess
import tempfile
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import cryptography

from agent.agent import SecureActionAgent
from agent.backends import ModelAPIError, OpenAICompatibleModel
from policy.policy import AuthorizationDenied, Policy
from server.replay import ReplayStore
from server.tool_server import RequestRejected, ToolServer, TrustedKey
from signing.canonical import canonical_json
from signing.encoding import b64url_decode
from signing.schemes import get_scheme
from signing.service import TrustedSigningService
from tools.file_access import FileReadDenied, read_bounded_file, validate_read_path

DEFAULT_TASK = "Read report.txt and summarize it, make it one sentence long"
OUTPUT_NAMES = (
    "llm_e2e_results.json",
    "llm_e2e_samples.csv",
    "llm_e2e_summary.csv",
    "llm_e2e_results.md",
)
TIMING_FIELDS = (
    "total_ms", "proposal_api_ms", "summary_api_ms", "llm_api_ms",
    "sign_ms", "verify_ms", "verifier_construction_ms", "crypto_ms",
    "authentication_ms", "protected_action_ms", "local_processing_ms",
    "proposal_validation_ms", "sender_authorization_ms", "envelope_preparation_ms",
    "receiver_authorization_ms", "replay_ms", "server_other_checks_ms",
    "tool_and_response_ms",
)
SHARE_FIELDS = ("crypto", "authentication", "protected_action")
PAIR_FIELDS = ("crypto_ms", "authentication_ms", "protected_action_ms", "total_ms")


def _statistics(values: list[float]) -> dict | None:
    """Nearest-rank p95; a missing sample population is not a zero latency."""
    if not values:
        return None
    ordered = sorted(values)
    return {
        "count": len(values),
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "p95": ordered[math.ceil(0.95 * len(values)) - 1],
        "min": ordered[0],
        "max": ordered[-1],
        "stdev": statistics.stdev(values) if len(values) > 1 else None,
    }


class _Recorder:
    def __init__(self, clock):
        self.clock = clock
        self.values: dict[str, float] = {}

    def measure(self, name, operation, *args, **kwargs):
        started = self.clock()
        try:
            return operation(*args, **kwargs)
        finally:
            elapsed = max(0.0, (self.clock() - started) / 1_000_000)
            self.values[name] = self.values.get(name, 0.0) + elapsed


class _TimedSigner:
    def __init__(self, signer, recorder):
        self._signer = signer
        self._recorder = recorder
        self.algorithm = signer.algorithm

    def sign(self, message):
        return self._recorder.measure("sign_ms", self._signer.sign, message)

    def public_key_bytes(self):
        return self._signer.public_key_bytes()

    def private_key_bytes(self):
        return self._signer.private_key_bytes()


class _TimedVerifier:
    def __init__(self, verifier, recorder):
        self._verifier = verifier
        self._recorder = recorder
        self.algorithm = verifier.algorithm

    def verify(self, message, signature):
        return self._recorder.measure("verify_ms", self._verifier.verify, message, signature)


class _TimedPolicy:
    def __init__(self, policy, recorder, field):
        self._policy = policy
        self._recorder = recorder
        self._field = field

    def authorize(self, *args, **kwargs):
        return self._recorder.measure(self._field, self._policy.authorize, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._policy, name)


class _TimedReplay:
    def __init__(self, store, recorder):
        self._store = store
        self._recorder = recorder

    def claim(self, **kwargs):
        return self._recorder.measure("replay_ms", self._store.claim, **kwargs)


class _TimedToolServer(ToolServer):
    def __init__(self, *args, recorder, **kwargs):
        super().__init__(*args, **kwargs)
        self._recorder = recorder

    def _create_verifier(self, trusted_key):
        verifier = self._recorder.measure(
            "verifier_construction_ms", super()._create_verifier, trusted_key
        )
        return _TimedVerifier(verifier, self._recorder)

    def verify_and_accept(self, envelope, *, now=None):
        return self._recorder.measure(
            "_server_acceptance_ms", super().verify_and_accept, envelope, now=now
        )


class _TimedModel:
    def __init__(self, model, recorder, counters):
        self._model = model
        self._recorder = recorder
        self._counters = counters

    def propose(self, task):
        self._counters["proposal_attempts"] += 1
        return self._recorder.measure("proposal_api_ms", self._model.propose, task)

    def summarize(self, task, content):
        self._counters["summary_attempts"] += 1
        return self._recorder.measure("summary_api_ms", self._model.summarize, task, content)


class _ProposalMismatch(ValueError):
    pass


def _safe_error_code(exc: Exception) -> str:
    """No arbitrary exception messages, request bodies, credentials, or traceback."""
    if isinstance(exc, ModelAPIError):
        # The production adapter constructs these numeric status messages itself.
        match = re.fullmatch(r"model API request failed \(HTTP (\d{3})\)", str(exc))
        return "MODEL_HTTP_" + match.group(1) if match else "MODEL_API_ERROR"
    if isinstance(exc, _ProposalMismatch):
        return "PROPOSAL_MISMATCH"
    if isinstance(exc, AuthorizationDenied):
        return "AUTHORIZATION_DENIED"
    if isinstance(exc, RequestRejected):
        allowed = {
            "MALFORMED_REQUEST", "INVALID_SIGNATURE", "UNTRUSTED_KEY", "EXPIRED",
            "NOT_YET_VALID", "AUTHORIZATION_DENIED", "REPLAY_DETECTED",
            "REPLAY_UNAVAILABLE", "EXECUTION_DENIED",
        }
        return exc.code if exc.code in allowed else "REQUEST_REJECTED"
    if isinstance(exc, (ValueError, TypeError)):
        return "INVALID_STAGE_RESULT"
    return "BENCHMARK_STAGE_FAILED"


def _check_live_model(model: OpenAICompatibleModel) -> None:
    """Only the documented Google endpoint; never send a key to arbitrary URLs."""
    try:
        url = urlsplit(model.endpoint)
        valid = (
            url.scheme == "https"
            and url.hostname == "generativelanguage.googleapis.com"
            and url.port in (None, 443)
            and url.path == "/v1beta/openai/chat/completions"
            and url.username is None and url.password is None
            and not url.query and not url.fragment
        )
    except (TypeError, ValueError):
        valid = False
    if not valid:
        raise ValueError("live benchmark requires the official Google HTTPS chat-completions endpoint")
    if not isinstance(model.model, str) or not re.fullmatch(r"gemini-[A-Za-z0-9][A-Za-z0-9._-]*", model.model):
        raise ValueError("live benchmark requires a Gemini model identifier")
    if not isinstance(model.api_key, str) or not model.api_key.strip():
        raise ValueError("live benchmark requires an API key in the process environment")


def _metadata(model) -> dict:
    real = isinstance(model, OpenAICompatibleModel)
    revision = None
    dirty = None
    project = Path(__file__).resolve().parents[1]
    try:
        revision_result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=project, capture_output=True,
            text=True, timeout=3, check=False,
        )
        candidate = revision_result.stdout.strip()
        if revision_result.returncode == 0 and re.fullmatch(r"[0-9a-f]{40,64}", candidate):
            revision = candidate
            status = subprocess.run(
                ["git", "status", "--porcelain"], cwd=project, capture_output=True,
                text=True, timeout=3, check=False,
            )
            if status.returncode == 0:
                dirty = bool(status.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        pass
    code_hashes = {}
    # HEAD plus dirty=true alone does not identify the implementation measured.
    # Hash executable pipeline files without retaining their contents or .env.
    for directory in (project / "src", project / "benchmarks"):
        for path in sorted(directory.rglob("*.py")):
            code_hashes[path.relative_to(project).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return {
        "measurement_source": "gemini_api" if real else "test_double",
        "llm_endpoint_host": "generativelanguage.googleapis.com" if real else None,
        "llm_model": model.model if real else None,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cryptography": cryptography.__version__,
        "code_revision": revision,
        "working_tree_dirty": dirty,
        "code_sha256": code_hashes,
    }


def _preflight(*, model, data_root, output_dir, task, file_path, pairs, warmup_pairs, interval_seconds):
    if isinstance(pairs, bool) or not isinstance(pairs, int) or pairs < 1:
        raise ValueError("pairs must be a positive integer")
    if isinstance(warmup_pairs, bool) or not isinstance(warmup_pairs, int) or warmup_pairs < 0:
        raise ValueError("warmup_pairs must be a non-negative integer")
    if isinstance(interval_seconds, bool) or not isinstance(interval_seconds, (int, float)) or not math.isfinite(interval_seconds) or interval_seconds < 0:
        raise ValueError("interval_seconds must be finite and non-negative")
    if not isinstance(task, str) or not task.strip():
        raise ValueError("task must be non-empty text")
    if not callable(getattr(model, "propose", None)) or not callable(getattr(model, "summarize", None)):
        raise ValueError("model must support proposal and summary calls")
    if isinstance(model, OpenAICompatibleModel):
        _check_live_model(model)
    data_root, output_dir = Path(data_root), Path(output_dir)
    if output_dir.exists() and not output_dir.is_dir():
        raise ValueError("output_dir must be a directory")
    if any((output_dir / name).exists() or (output_dir / name).is_symlink() for name in OUTPUT_NAMES):
        raise ValueError("benchmark output files already exist; choose a new output directory")
    try:
        policy = Policy(data_root=data_root)
        policy.authorize("agent-01", "read_file", {"path": file_path})
        parts = validate_read_path(file_path)
        contents = read_bounded_file(data_root, parts, max_bytes=policy.max_file_bytes)
        contents.decode("utf-8", errors="strict")
    except (AuthorizationDenied, FileReadDenied, UnicodeError, OSError, ValueError):
        raise ValueError("benchmark input must be an allowed, bounded UTF-8 text file") from None
    # Establish writable output before any paid model request. These names are
    # reserved exclusively below so concurrent runs cannot overwrite each other.
    output_dir.mkdir(parents=True, exist_ok=True)
    return data_root, output_dir, parts, contents


def _setup_context(name, model, data_root, counters, clock):
    setup_started = clock()
    key_started = clock()
    signer = get_scheme(name).generate()
    keygen_ms = max(0.0, (clock() - key_started) / 1_000_000)
    recorder = _Recorder(clock)
    timed_signer = _TimedSigner(signer, recorder)
    service = TrustedSigningService(timed_signer)
    policy = Policy(data_root=data_root)
    sender_policy = _TimedPolicy(policy, recorder, "sender_authorization_ms")
    receiver_policy = _TimedPolicy(policy, recorder, "receiver_authorization_ms")
    timed_model = _TimedModel(model, recorder, counters)
    agent = SecureActionAgent(timed_model, sender_policy, service)
    replay = ReplayStore()
    try:
        server = _TimedToolServer(
            {service.key_id: TrustedKey(service.agent_id, signer.algorithm, signer.public_key_bytes())},
            _TimedReplay(replay, recorder), receiver_policy, recorder=recorder,
        )
    except BaseException:
        replay.close()
        raise
    return {
        "algorithm": signer.algorithm, "recorder": recorder, "model": timed_model,
        "agent": agent, "server": server, "replay": replay,
        "setup": {
            "algorithm": signer.algorithm, "keygen_ms": keygen_ms,
            "setup_total_ms": max(0.0, (clock() - setup_started) / 1_000_000),
        },
    }


def _finish_metrics(recorder, completed):
    values = recorder.values
    api = values.get("proposal_api_ms", 0.0) + values.get("summary_api_ms", 0.0)
    values["llm_api_ms"] = api
    if "total_ms" in values:
        values["local_processing_ms"] = max(0.0, values["total_ms"] - api)
    if completed:
        values["crypto_ms"] = values["sign_ms"] + values["verify_ms"]
        values["authentication_ms"] = values["crypto_ms"] + values["verifier_construction_ms"]
        values["proposal_validation_ms"] = max(0.0, values["_proposal_total_ms"] - values["proposal_api_ms"])
        values["envelope_preparation_ms"] = max(
            0.0, values["_authorize_sign_ms"] - values["sender_authorization_ms"] - values["sign_ms"]
        )
        values["server_other_checks_ms"] = max(
            0.0, values["_server_acceptance_ms"] - values["verifier_construction_ms"]
            - values["verify_ms"] - values["receiver_authorization_ms"] - values["replay_ms"]
        )
        values["tool_and_response_ms"] = max(0.0, values["_server_execute_ms"] - values["_server_acceptance_ms"])
    return {field: values[field] for field in TIMING_FIELDS if field in values}


def _one_sample(context, *, task, file_path, content_hash, phase, pair_index, position):
    recorder = context["recorder"]
    recorder.values.clear()
    sample = {
        "phase": phase, "pair_index": pair_index, "position_in_pair": position,
        "algorithm": context["algorithm"], "status": "failed",
        "error_stage": None, "error_code": None, "timing_ms": {},
        "shares_percent": {name: None for name in SHARE_FIELDS},
        "signature_bytes": None, "signed_envelope_bytes": None,
    }
    stage = "proposal_api"
    envelope = None
    interrupted = False
    started = recorder.clock()
    try:
        proposal = recorder.measure("_proposal_total_ms", context["agent"].propose, task)
        stage = "proposal_validation"
        if proposal.tool != "read_file" or proposal.arguments != {"path": file_path}:
            raise _ProposalMismatch("unexpected benchmark proposal")
        stage = "protected_action"
        protection_started = recorder.clock()
        try:
            envelope = recorder.measure("_authorize_sign_ms", context["agent"].authorize_and_sign, proposal)
            response = recorder.measure("_server_execute_ms", context["server"].execute, envelope)
        finally:
            recorder.values["protected_action_ms"] = max(0.0, (recorder.clock() - protection_started) / 1_000_000)
        content = response["result"]["content"]
        if not isinstance(content, str) or hashlib.sha256(content.encode("utf-8")).hexdigest() != content_hash:
            raise ValueError("unexpected benchmark tool content")
        stage = "summary_api"
        summary = context["model"].summarize(task, content)
        if not isinstance(summary, str) or not summary.strip():
            raise ValueError("summary must be non-empty text")
        sample["status"] = "ok"
    except KeyboardInterrupt:
        sample["error_stage"], sample["error_code"] = stage, "INTERRUPTED"
        interrupted = True
    except Exception as exc:
        sample["error_stage"], sample["error_code"] = stage, _safe_error_code(exc)
    finally:
        recorder.values["total_ms"] = max(0.0, (recorder.clock() - started) / 1_000_000)
    sample["timing_ms"] = _finish_metrics(recorder, sample["status"] == "ok")
    if envelope is not None:
        # Retain safe size metadata even if the post-execution summary fails.
        # Serialization for measurement is outside the end-to-end timed region.
        sample["signature_bytes"] = len(b64url_decode(envelope["signature"]))
        sample["signed_envelope_bytes"] = len(canonical_json(envelope))
    if sample["status"] == "ok":
        total = sample["timing_ms"]["total_ms"]
        for share, field in (("crypto", "crypto_ms"), ("authentication", "authentication_ms"), ("protected_action", "protected_action_ms")):
            sample["shares_percent"][share] = sample["timing_ms"][field] / total * 100 if total > 0 else None
    return sample, interrupted


def _aggregate(report):
    measured = [sample for sample in report["samples"] if sample["phase"] == "measured"]
    summaries = []
    for algorithm in ("Ed25519", "ML-DSA-44"):
        rows = [sample for sample in measured if sample["algorithm"] == algorithm]
        successful = [sample for sample in rows if sample["status"] == "ok"]
        summaries.append({
            "algorithm": algorithm,
            "successful_measured_samples": len(successful),
            "failed_measured_samples": sum(row["status"] != "ok" for row in rows),
            "timing_ms": {field: _statistics([row["timing_ms"][field] for row in successful]) for field in TIMING_FIELDS},
            "shares_percent": {
                field: _statistics([row["shares_percent"][field] for row in successful if row["shares_percent"][field] is not None])
                for field in SHARE_FIELDS
            },
            "signature_bytes": _statistics([row["signature_bytes"] for row in successful]),
            "signed_envelope_bytes": _statistics([row["signed_envelope_bytes"] for row in successful]),
        })
    pairs = {}
    for row in measured:
        if row["status"] == "ok":
            pairs.setdefault(row["pair_index"], {})[row["algorithm"]] = row
    complete = [pair for pair in pairs.values() if set(pair) == {"Ed25519", "ML-DSA-44"}]
    report["algorithm_summaries"] = summaries
    report["comparison"] = {
        "complete_measured_pairs": len(complete),
        "paired_differences_ms": {
            field: _statistics([pair["ML-DSA-44"]["timing_ms"][field] - pair["Ed25519"]["timing_ms"][field] for pair in complete])
            for field in PAIR_FIELDS
        },
        "difference_direction": "ML-DSA-44 minus Ed25519",
        "total_difference_interpretation": "observed, not causal: independent Gemini calls contain API/network/response-length noise",
    }
    report["api_calls"]["total_attempts"] = report["api_calls"]["proposal_attempts"] + report["api_calls"]["summary_attempts"]
    warning = "Fewer than 20 complete measured pairs: small-sample p95 and total-time comparisons are exploratory."
    if warning in report["warnings"]:
        report["warnings"].remove(warning)
    if len(complete) < 20:
        report["warnings"].append(warning)


def _markdown(report):
    lines = [
        "# Gemini end-to-end signed-action benchmark", "",
        f"Status: {report['status']}. Measurement source: {report['environment']['measurement_source']}.",
        f"Complete measured pairs: {report['comparison']['complete_measured_pairs']}; attempted API methods: {report['api_calls']['total_attempts']}.", "",
        "Keys and in-memory SQLite stores are initialized once per algorithm. Samples measure steady-state workflows; setup and key generation are reported separately.",
        "Each complete algorithm workflow makes a fresh proposal call and a fresh summary call. Warm-ups and failed samples are excluded from latency statistics.", "",
        "| Algorithm | Successful samples | Total median ms | LLM API median ms | Crypto median ms | Authentication median ms | Crypto share median % |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    def fmt(stats):
        return "not measured" if stats is None else f"{stats['median']:.6f}"
    for summary in report["algorithm_summaries"]:
        timing = summary["timing_ms"]
        lines.append(
            f"| {summary['algorithm']} | {summary['successful_measured_samples']} | {fmt(timing['total_ms'])} | {fmt(timing['llm_api_ms'])} | {fmt(timing['crypto_ms'])} | {fmt(timing['authentication_ms'])} | {fmt(summary['shares_percent']['crypto'])} |"
        )
    lines.extend([
        "", "## Latency distributions (milliseconds)", "",
        "| Algorithm | Metric | Count | Mean | Median | p95 |",
        "|---|---|---:|---:|---:|---:|",
    ])
    for summary in report["algorithm_summaries"]:
        for field in ("total_ms", "llm_api_ms", "proposal_api_ms", "summary_api_ms", "sign_ms", "verify_ms", "authentication_ms", "protected_action_ms"):
            stats = summary["timing_ms"][field]
            if stats is None:
                lines.append(f"| {summary['algorithm']} | {field} | 0 | not measured | not measured | not measured |")
            else:
                lines.append(f"| {summary['algorithm']} | {field} | {stats['count']} | {stats['mean']:.6f} | {stats['median']:.6f} | {stats['p95']:.6f} |")
    lines.extend([
        "", "## Paired differences: ML-DSA-44 minus Ed25519", "",
        "| Metric | Complete pairs | Mean ms | Median ms | p95 ms |",
        "|---|---:|---:|---:|---:|",
    ])
    for field, stats in report["comparison"]["paired_differences_ms"].items():
        if stats is not None:
            lines.append(f"| {field} | {stats['count']} | {stats['mean']:.6f} | {stats['median']:.6f} | {stats['p95']:.6f} |")
    lines.extend([
        "", "## Interpretation", "",
        "Crypto is pure sign + pure verify; authentication also includes production verifier construction. Protected action includes sender authorization/envelope construction and complete server acceptance/execution.",
        "API timing is client-observed request/response wall time, not pure model inference. Local processing is total minus both API phases.",
        "Parent timings (total, protected action, authentication, crypto) are inclusive and must not be added to their child timings. Preparation/check/tool residuals include instrumentation and glue overhead, not isolated primitive measurements.",
        "Paired differences are ML-DSA-44 minus Ed25519. Total differences are observational, not a causal estimate of crypto cost, because each workflow has independent Gemini/network variability.",
        "The tool boundary is in-process: signed-envelope bytes measure size overhead, not actual remote-tool transfer latency. API/network time is measured only for Gemini calls.",
        "Temperature zero does not guarantee deterministic model output. Summary correctness and semantic safety are not established by a non-empty response or a valid signature.",
        "No API keys, private/public key material, raw task, file contents, proposals, envelopes, summaries, or raw exception messages are persisted.", "",
    ])
    lines.extend(f"- {warning}" for warning in report["warnings"])
    return "\n".join(lines) + "\n"


def _write_outputs(report, streams):
    # Checkpoint through our exclusively reserved handles; never open another
    # run's artifacts for overwrite. Pacing/writing remain outside sample clocks.
    for stream in streams.values():
        stream.seek(0)
        stream.truncate()
    json.dump(report, streams["llm_e2e_results.json"], indent=2, ensure_ascii=False, allow_nan=False)
    sample_fields = ["phase", "pair_index", "position_in_pair", "algorithm", "status", "error_stage", "error_code", *TIMING_FIELDS, *(field + "_share_percent" for field in SHARE_FIELDS), "signature_bytes", "signed_envelope_bytes"]
    writer = csv.DictWriter(streams["llm_e2e_samples.csv"], fieldnames=sample_fields)
    writer.writeheader()
    for sample in report["samples"]:
        row = {field: sample.get(field) for field in sample_fields}
        row.update(sample["timing_ms"])
        row.update({field + "_share_percent": sample["shares_percent"][field] for field in SHARE_FIELDS})
        writer.writerow(row)
    summary_writer = csv.writer(streams["llm_e2e_summary.csv"])
    summary_writer.writerow(["algorithm", "metric", "unit", "count", "mean", "median", "p95", "min", "max", "stdev"])
    for summary in report["algorithm_summaries"]:
        for group, unit in (("timing_ms", "ms"), ("shares_percent", "percent")):
            for metric, stats in summary[group].items():
                summary_writer.writerow([summary["algorithm"], metric, unit] + ([stats[field] for field in ("count", "mean", "median", "p95", "min", "max", "stdev")] if stats else [0, None, None, None, None, None, None]))
    streams["llm_e2e_results.md"].write(_markdown(report))
    for stream in streams.values():
        stream.flush()


def run_benchmark(
    *, model, data_root: Path, output_dir: Path, task=DEFAULT_TASK,
    file_path="report.txt", pairs=20, warmup_pairs=1, interval_seconds=1.0,
    progress=None, clock=None, sleeper=None,
) -> dict:
    """Run paired production workflows; fake injected models never claim live data.

    ``clock`` is a nanosecond monotonic callable; ``sleeper`` takes seconds.
    User progress callbacks and inter-workflow pacing are outside sample timers.
    The runner performs no automatic API retry and stops on the first failure.
    """
    clock = time.perf_counter_ns if clock is None else clock
    sleeper = time.sleep if sleeper is None else sleeper
    _, output_dir, parts, contents = _preflight(
        model=model, data_root=data_root, output_dir=output_dir, task=task,
        file_path=file_path, pairs=pairs, warmup_pairs=warmup_pairs, interval_seconds=interval_seconds,
    )
    report = {
        "schema_version": 1, "generated_at": datetime.now(UTC).isoformat(),
        "status": "running", "environment": _metadata(model),
        "input": {
            "file_sha256": hashlib.sha256(contents).hexdigest(), "file_bytes": len(contents),
            "task_sha256": hashlib.sha256(task.encode("utf-8")).hexdigest(),
        },
        "planned": {"measured_pairs": pairs, "warmup_pairs": warmup_pairs, "max_api_calls": 4 * (pairs + warmup_pairs)},
        "api_calls": {"proposal_attempts": 0, "summary_attempts": 0, "total_attempts": 0},
        "method": {
            "workflow": "fresh model proposal -> production validation/authorization/sign -> production server verification/freshness/authorization/replay/read_file -> fresh display-only model summary",
            "pair_order": "Ed25519 then ML-DSA-44 in odd pairs; reversed in even pairs, independently within each phase",
            "clock": "injected_nanosecond_clock" if clock is not time.perf_counter_ns else "time.perf_counter_ns",
            "interval_seconds": interval_seconds, "automatic_retries": 0,
            "pacing": "between complete workflows, not between proposal and summary within a workflow",
            "setup_excluded_from_samples": True, "tool_transport": "in_process",
            "replay_storage": "SQLite :memory: reused per algorithm",
            "model_request_count_note": "counts attempted propose/summarize methods; successful workflows have two real HTTP requests for the production live adapter",
            "p95_method": "nearest rank", "statistics_population": "successful measured samples only; complete measured pairs for paired differences",
            "timing_accounting": "inclusive aggregate stages must not be summed with their children; residual local stages include instrumentation and glue overhead",
        },
        "setup": [], "samples": [], "warnings": [],
    }
    contexts, streams = {}, {}
    try:
        # Exclusive reservation prevents overwrite by concurrent/new runs. All
        # handles open before any API call, so output access failure is preflight.
        for name in OUTPUT_NAMES:
            streams[name] = (output_dir / name).open("x", encoding="utf-8", newline="")
        with tempfile.TemporaryDirectory(prefix="pqsa-llm-input-") as temporary:
            snapshot_root = Path(temporary)
            snapshot = snapshot_root.joinpath(*parts)
            snapshot.parent.mkdir(parents=True, exist_ok=True)
            snapshot.write_bytes(contents)
            for name in ("ed25519", "ml-dsa"):
                context = _setup_context(name, model, snapshot_root, report["api_calls"], clock)
                contexts[context["algorithm"]] = context
                report["setup"].append(context["setup"])
            _aggregate(report)
            _write_outputs(report, streams)
            first_workflow = True
            stop = False
            for phase, count in (("warmup", warmup_pairs), ("measured", pairs)):
                for pair_index in range(1, count + 1):
                    order = ("Ed25519", "ML-DSA-44") if pair_index % 2 else ("ML-DSA-44", "Ed25519")
                    for position, algorithm in enumerate(order, 1):
                        if not first_workflow and interval_seconds:
                            sleeper(interval_seconds)
                        first_workflow = False
                        if progress is not None:
                            progress(f"{phase} pair {pair_index}/{count}: {algorithm}")
                        sample, interrupted = _one_sample(
                            contexts[algorithm], task=task, file_path=file_path,
                            content_hash=report["input"]["file_sha256"], phase=phase,
                            pair_index=pair_index, position=position,
                        )
                        report["samples"].append(sample)
                        if sample["status"] != "ok":
                            report["status"] = "interrupted" if interrupted else "stopped_on_failure"
                            stop = True
                        _aggregate(report)
                        _write_outputs(report, streams)
                        if stop:
                            break
                    if stop:
                        break
                if stop:
                    break
            if not stop:
                report["status"] = "completed"
    except KeyboardInterrupt:
        report["status"] = "interrupted"
        report["warnings"].append("Interrupted between workflows; completed samples and call counts are preserved.")
    except Exception:
        report["status"] = "benchmark_error"
        report["warnings"].append("Benchmark setup, progress, pacing, or artifact handling failed; no raw exception details are retained.")
        raise
    finally:
        for context in contexts.values():
            context["replay"].close()
        try:
            if len(streams) == len(OUTPUT_NAMES):
                _aggregate(report)
                _write_outputs(report, streams)
        finally:
            for stream in streams.values():
                stream.close()
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="explicitly opt into paid/quota-consuming Gemini API requests")
    parser.add_argument("--pairs", type=int, default=20)
    parser.add_argument("--warmup-pairs", type=int, default=1)
    parser.add_argument("--interval-seconds", type=float, default=1.0)
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument("--max-api-calls", type=int, default=100)
    parser.add_argument("--task", default=DEFAULT_TASK)
    parser.add_argument("--file", dest="file_path", default="report.txt")
    parser.add_argument("--data-root", type=Path, default=Path("data"))
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    if not args.live:
        parser.error("--live is required: this benchmark makes real Gemini API requests")
    if args.pairs < 1 or args.warmup_pairs < 0:
        parser.error("pairs must be positive and warmup-pairs non-negative")
    if not math.isfinite(args.interval_seconds) or args.interval_seconds < 0:
        parser.error("interval-seconds must be finite and non-negative")
    if not math.isfinite(args.timeout_seconds) or args.timeout_seconds <= 0:
        parser.error("timeout-seconds must be finite and positive")
    budget = 4 * (args.pairs + args.warmup_pairs)
    if args.max_api_calls < 1 or budget > args.max_api_calls:
        parser.error("planned API call count exceeds max-api-calls; reduce samples or explicitly raise the budget")
    required = ("PQSA_LLM_URL", "PQSA_LLM_MODEL", "PQSA_LLM_API_KEY")
    if any(not os.getenv(name, "").strip() for name in required):
        parser.error("set PQSA_LLM_URL, PQSA_LLM_MODEL, and PQSA_LLM_API_KEY in the process environment; .env is not loaded automatically")
    model = OpenAICompatibleModel(
        endpoint=os.environ["PQSA_LLM_URL"], model=os.environ["PQSA_LLM_MODEL"],
        api_key=os.environ["PQSA_LLM_API_KEY"], timeout_seconds=args.timeout_seconds,
    )
    output_dir = args.output_dir or Path("results/llm_e2e") / (datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ") + "-" + uuid.uuid4().hex[:8])
    print(f"Planned maximum: {budget} Gemini API requests ({args.pairs} measured pairs, {args.warmup_pairs} warm-up pairs). No automatic retries.", flush=True)
    print("The selected file and task will be sent to Google; use non-sensitive benchmark data.", flush=True)
    try:
        report = run_benchmark(
            model=model, data_root=args.data_root, output_dir=output_dir,
            task=args.task, file_path=args.file_path, pairs=args.pairs,
            warmup_pairs=args.warmup_pairs, interval_seconds=args.interval_seconds,
            progress=lambda message: print(message, flush=True),
        )
    except Exception:
        # Never print arbitrary OS/config errors that may include credential data.
        parser.exit(2, "Benchmark preflight/output failed; check allowed UTF-8 input, Google endpoint/model, credentials, and a new writable output directory.\n")
    compact_summaries = [{
        "algorithm": summary["algorithm"],
        "successful_measured_samples": summary["successful_measured_samples"],
        "failed_measured_samples": summary["failed_measured_samples"],
        "timing_ms": {field: summary["timing_ms"][field] for field in ("total_ms", "llm_api_ms", "crypto_ms", "authentication_ms", "protected_action_ms")},
        "crypto_share_percent": summary["shares_percent"]["crypto"],
    } for summary in report["algorithm_summaries"]]
    print(json.dumps({
        "status": report["status"], "measurement_source": report["environment"]["measurement_source"],
        "api_calls": report["api_calls"], "complete_measured_pairs": report["comparison"]["complete_measured_pairs"],
        "algorithm_summaries": compact_summaries,
        "comparison": report["comparison"], "warnings": report["warnings"],
        "output_dir": str(output_dir.resolve()),
    }, indent=2, allow_nan=False))
    if report["status"] != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()

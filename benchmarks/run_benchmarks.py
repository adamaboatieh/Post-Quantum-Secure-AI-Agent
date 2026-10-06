"""Benchmark Ed25519 and ML-DSA-44 with the same signed action payload."""

from __future__ import annotations

import argparse
import csv
import json
import math
import platform
import statistics
import time
import tracemalloc
from datetime import UTC, datetime
from pathlib import Path

import cryptography

from policy.policy import Policy
from server.replay import ReplayStore
from server.tool_server import ToolServer, TrustedKey
from signing.canonical import canonical_json, signing_bytes
from signing.encoding import b64url_encode
from signing.schemes import get_scheme
from signing.service import TrustedSigningService


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def measure(operation, repetitions: int) -> dict[str, float]:
    operation()
    wall = []
    cpu = []
    for _ in range(repetitions):
        cpu_start = time.process_time_ns()
        wall_start = time.perf_counter_ns()
        operation()
        wall.append((time.perf_counter_ns() - wall_start) / 1_000_000)
        cpu.append((time.process_time_ns() - cpu_start) / 1_000_000)
    return {
        "repetitions": repetitions,
        "mean_ms": statistics.fmean(wall),
        "median_ms": statistics.median(wall),
        "p95_ms": percentile(wall, 0.95),
        "mean_cpu_ms": statistics.fmean(cpu),
    }


def peak_memory(operation) -> int:
    tracemalloc.start()
    try:
        operation()
        _current, peak = tracemalloc.get_traced_memory()
        return peak
    finally:
        tracemalloc.stop()


def benchmark_algorithm(name: str, *, repetitions: int, scales: list[int], data_root: Path) -> dict:
    scheme = get_scheme(name)
    signer = scheme.generate()
    verifier = scheme.verifier(signer.public_key_bytes())
    payload = {
        "protocol": "pqsa-action-v1",
        "audience": "pqsa-tool-service",
        "algorithm": signer.algorithm,
        "agent_id": "agent-01",
        "key_id": f"agent-01-{signer.algorithm.lower()}-v1",
        "request_id": "00000000-0000-4000-8000-000000000001",
        "nonce": "MDEyMzQ1Njc4OWFiY2RlZg",
        "issued_at": "2026-10-06T12:00:00Z",
        "expires_at": "2026-10-06T12:01:00Z",
        "tool": "read_file",
        "arguments": {"path": "report.txt"},
    }
    message = signing_bytes(payload)
    signature = signer.sign(message)
    envelope = {"payload": payload, "signature": b64url_encode(signature)}
    keygen_repetitions = min(repetitions, 250)
    metrics = {
        "keygen": measure(scheme.generate, keygen_repetitions),
        "sign": measure(lambda: signer.sign(message), repetitions),
        "verify": measure(lambda: verifier.verify(message, signature), repetitions),
    }
    memory = {
        "keygen_peak_bytes": peak_memory(scheme.generate),
        "sign_peak_bytes": peak_memory(lambda: signer.sign(message)),
        "verify_peak_bytes": peak_memory(lambda: verifier.verify(message, signature)),
    }
    sizes = {
        "public_key_bytes": len(signer.public_key_bytes()),
        "private_key_serialized_bytes": len(signer.private_key_bytes()),
        "signature_bytes": len(signature),
        "canonical_payload_bytes": len(canonical_json(payload)),
        "signed_envelope_bytes": len(canonical_json(envelope)),
    }
    sizes["network_overhead_percent"] = (
        (sizes["signed_envelope_bytes"] - sizes["canonical_payload_bytes"])
        / sizes["canonical_payload_bytes"]
        * 100
    )

    throughput = []
    for scale in scales:
        replay = ReplayStore()
        signing_service = TrustedSigningService(signer)
        policy = Policy(data_root.resolve())
        server = ToolServer(
            {
                signing_service.key_id: TrustedKey(
                    signing_service.agent_id,
                    signer.algorithm,
                    signer.public_key_bytes(),
                )
            },
            replay,
            policy,
        )
        started_cpu = time.process_time_ns()
        started = time.perf_counter_ns()
        try:
            for _ in range(scale):
                request = signing_service.create_envelope("read_file", {"path": "report.txt"})
                server.execute(request)
        finally:
            replay.close()
        wall_seconds = (time.perf_counter_ns() - started) / 1_000_000_000
        cpu_seconds = (time.process_time_ns() - started_cpu) / 1_000_000_000
        throughput.append(
            {
                "requests": scale,
                "wall_seconds": wall_seconds,
                "cpu_seconds": cpu_seconds,
                "requests_per_second": scale / wall_seconds,
            }
        )

    return {
        "algorithm": signer.algorithm,
        "latency": metrics,
        "sizes": sizes,
        "peak_python_memory": memory,
        "full_pipeline_scale": throughput,
    }


def _write_csv(report: dict, path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["algorithm", "operation", "mean_ms", "median_ms", "p95_ms", "mean_cpu_ms"])
        for algorithm in report["algorithms"]:
            for operation, values in algorithm["latency"].items():
                writer.writerow(
                    [
                        algorithm["algorithm"],
                        operation,
                        values["mean_ms"],
                        values["median_ms"],
                        values["p95_ms"],
                        values["mean_cpu_ms"],
                    ]
                )


def _write_svg(report: dict, path: Path, *, metric: str, title: str, unit: str) -> None:
    algorithms = report["algorithms"]
    if metric == "latency":
        entries = [(item["algorithm"], item["latency"]["sign"]["median_ms"]) for item in algorithms]
    else:
        entries = [(item["algorithm"], item["sizes"]["signature_bytes"]) for item in algorithms]
    maximum = max(value for _, value in entries) or 1
    bars = []
    for index, (label, value) in enumerate(entries):
        y = 75 + index * 70
        width = 520 * value / maximum
        bars.append(
            f'<text x="20" y="{y + 22}" font-size="16">{label}</text>'
            f'<rect x="155" y="{y}" width="{width:.1f}" height="32" fill="#315a8a"/>'
            f'<text x="{165 + width:.1f}" y="{y + 22}" font-size="15">{value:.4f} {unit}</text>'
        )
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="800" height="240" viewBox="0 0 800 240">'
        '<rect width="100%" height="100%" fill="white"/>'
        f'<text x="20" y="35" font-family="Arial" font-size="22" font-weight="bold">{title}</text>'
        f'<g font-family="Arial" fill="#111">{"".join(bars)}</g></svg>'
    )
    path.write_text(svg, encoding="utf-8")


def run(*, repetitions: int, scales: list[int], data_root: Path, output_dir: Path) -> dict:
    report = {
        "generated_at": datetime.now(UTC).isoformat(),
        "environment": {
            "platform": platform.platform(),
            "processor": platform.processor(),
            "python": platform.python_version(),
            "cryptography": cryptography.__version__,
        },
        "method": {
            "latency_repetitions": repetitions,
            "warmup_per_operation": 1,
            "scales": scales,
            "clock": "time.perf_counter_ns",
            "cpu_clock": "time.process_time_ns",
            "llm_inference": "not measured; requires a configured live model endpoint",
        },
        "algorithms": [
            benchmark_algorithm(name, repetitions=repetitions, scales=scales, data_root=data_root)
            for name in ("ed25519", "ml-dsa")
        ],
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "benchmark_results.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    _write_csv(report, output_dir / "benchmark_summary.csv")
    _write_svg(
        report,
        output_dir / "sign_latency.svg",
        metric="latency",
        title="Median signing latency",
        unit="ms",
    )
    _write_svg(
        report,
        output_dir / "signature_size.svg",
        metric="size",
        title="Signature size",
        unit="bytes",
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repetitions", type=int, default=500)
    parser.add_argument("--scales", default="1,100,1000,10000")
    parser.add_argument("--data-root", type=Path, default=Path("data"))
    parser.add_argument("--output-dir", type=Path, default=Path("results"))
    args = parser.parse_args()
    if args.repetitions < 20:
        parser.error("repetitions must be at least 20")
    scales = [int(value) for value in args.scales.split(",")]
    if not scales or any(value <= 0 for value in scales):
        parser.error("scales must be positive comma-separated integers")
    report = run(
        repetitions=args.repetitions,
        scales=scales,
        data_root=args.data_root,
        output_dir=args.output_dir,
    )
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

# Experimental Results

## Environment and method

Measurements were generated on 6 October 2026 with:

- Windows 11 build 26300;
- AMD64 Family 25 Model 80 CPU;
- Python 3.12.14;
- `cryptography` 50.0.1;
- 500 timed sign and verify repetitions after one warm-up;
- 250 key-generation repetitions;
- full pipeline scales of 1, 100, 1,000, and 10,000 requests.

Wall time used `perf_counter_ns`; process CPU time used `process_time_ns`.
`tracemalloc` captured Python-visible peak allocation for one operation. It does
not capture every native OpenSSL allocation, so memory values are directional,
not total process memory.

## Latency

| Operation | Ed25519 mean ms | Ed25519 median ms | Ed25519 p95 ms | ML-DSA-44 mean ms | ML-DSA-44 median ms | ML-DSA-44 p95 ms |
|---|---:|---:|---:|---:|---:|---:|
| Key generation | 0.0338 | 0.0332 | 0.0358 | 0.1028 | 0.1024 | 0.1069 |
| Sign | 0.0339 | 0.0338 | 0.0343 | 0.6119 | 0.4528 | 1.4104 |
| Verify | 0.0941 | 0.0949 | 0.0964 | 0.1120 | 0.1118 | 0.1153 |

ML-DSA signing varied more than verification in this run, which is why its mean
and p95 diverge from its median. The raw JSON should be retained for comparison
with reruns rather than treating a single median as the whole distribution.

## Sizes and network overhead

| Metric | Ed25519 | ML-DSA-44 |
|---|---:|---:|
| Public key | 32 B | 1,312 B |
| Serialized private material | 32 B seed | 32 B seed |
| Signature | 64 B | 2,420 B |
| Canonical payload | 344 B | 348 B |
| Signed envelope | 457 B | 3,602 B |
| Envelope overhead over canonical payload | 32.85% | 935.06% |

For ML-DSA-44, the library serializes a 32-byte seed. FIPS 204 also describes
the larger expanded private-key representation; the table reports bytes stored
by this implementation, not expanded internal state.

## Full pipeline throughput

The full pipeline includes payload construction, signing, canonicalization,
verification, freshness, policy, SQLite replay claim, and bounded file read.

| Requests | Ed25519 requests per second | ML-DSA-44 requests per second |
|---:|---:|---:|
| 1 | 789.45 | 746.10 |
| 100 | 1,167.36 | 700.82 |
| 1,000 | 1,155.73 | 666.96 |
| 10,000 | 1,194.16 | 671.54 |

No throughput collapse appeared at 10,000 requests, although ML-DSA-44 reached
about 56% of Ed25519 throughput in this single-process local test.

## Security and attack results

All seven required scenarios ran in both modes:

| Attack | Ed25519 | ML-DSA-44 | Meaning |
|---|---|---|---|
| Message tampering | Rejected | Rejected | Signature binds exact arguments |
| Signature forgery | Rejected | Rejected | Random/fabricated signature fails |
| Replay | Rejected | Rejected | Request ID or nonce reuse is detected |
| Expired request | Rejected | Rejected | Freshness is independent of signature validity |
| Unauthorized action | Rejected | Rejected | Authentication does not grant permission |
| Prompt injection | Policy blocked | Policy blocked | Known forbidden output is stopped before signing |
| Signed malicious but policy-valid action | Accepted | Accepted | Signature does not prove semantic safety |

## AI inference comparison status

The offline proposal path was executed, but it is deterministic and is not an
LLM inference measurement. No live model credential or endpoint was available
for this run, so the repository does not claim an observed LLM latency. The
live compatible adapter is implemented; final presentation evidence should add
multiple live inference samples from the actual selected model and compare
their median/p95 directly with these cryptographic medians.

## Reproducibility artifacts

- `results/benchmark_results.json` contains the full environment and raw summary.
- `results/benchmark_summary.csv` contains latency rows.
- `results/sign_latency.svg` and `results/signature_size.svg` are generated charts.
- `benchmarks/run_benchmarks.py` regenerates all artifacts.

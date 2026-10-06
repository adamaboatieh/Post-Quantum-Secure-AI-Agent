# Gemini end-to-end signed-action benchmark

Status: completed. Measurement source: gemini_api.
Complete measured pairs: 2; attempted API methods: 8.

Keys and in-memory SQLite stores are initialized once per algorithm. Samples measure steady-state workflows; setup and key generation are reported separately.
Each complete algorithm workflow makes a fresh proposal call and a fresh summary call. Warm-ups and failed samples are excluded from latency statistics.

| Algorithm | Successful samples | Total median ms | LLM API median ms | Crypto median ms | Authentication median ms | Crypto share median % |
|---|---:|---:|---:|---:|---:|---:|
| Ed25519 | 2 | 1796.408900 | 1788.362550 | 0.322500 | 0.350500 | 0.017666 |
| ML-DSA-44 | 2 | 1702.260550 | 1700.179450 | 0.644000 | 0.688550 | 0.037856 |

## Latency distributions (milliseconds)

| Algorithm | Metric | Count | Mean | Median | p95 |
|---|---|---:|---:|---:|---:|
| Ed25519 | total_ms | 2 | 1796.408900 | 1796.408900 | 1937.719700 |
| Ed25519 | llm_api_ms | 2 | 1788.362550 | 1788.362550 | 1923.249500 |
| Ed25519 | proposal_api_ms | 2 | 825.939650 | 825.939650 | 917.436000 |
| Ed25519 | summary_api_ms | 2 | 962.422900 | 962.422900 | 1005.813500 |
| Ed25519 | sign_ms | 2 | 0.207200 | 0.207200 | 0.296500 |
| Ed25519 | verify_ms | 2 | 0.115300 | 0.115300 | 0.116300 |
| Ed25519 | authentication_ms | 2 | 0.350500 | 0.350500 | 0.436200 |
| Ed25519 | protected_action_ms | 2 | 7.972400 | 7.972400 | 14.390800 |
| ML-DSA-44 | total_ms | 2 | 1702.260550 | 1702.260550 | 1716.297800 |
| ML-DSA-44 | llm_api_ms | 2 | 1700.179450 | 1700.179450 | 1714.271500 |
| ML-DSA-44 | proposal_api_ms | 2 | 770.598300 | 770.598300 | 783.548700 |
| ML-DSA-44 | summary_api_ms | 2 | 929.581150 | 929.581150 | 956.623600 |
| ML-DSA-44 | sign_ms | 2 | 0.493650 | 0.493650 | 0.540500 |
| ML-DSA-44 | verify_ms | 2 | 0.150350 | 0.150350 | 0.153500 |
| ML-DSA-44 | authentication_ms | 2 | 0.688550 | 0.688550 | 0.732800 |
| ML-DSA-44 | protected_action_ms | 2 | 2.006950 | 2.006950 | 2.067100 |

## Paired differences: ML-DSA-44 minus Ed25519

| Metric | Complete pairs | Mean ms | Median ms | p95 ms |
|---|---:|---:|---:|---:|
| crypto_ms | 2 | 0.321500 | 0.321500 | 0.368100 |
| authentication_ms | 2 | 0.338050 | 0.338050 | 0.379500 |
| protected_action_ms | 2 | -5.965450 | -5.965450 | 0.392800 |
| total_ms | 2 | -94.148350 | -94.148350 | 61.199700 |

## Interpretation

Crypto is pure sign + pure verify; authentication also includes production verifier construction. Protected action includes sender authorization/envelope construction and complete server acceptance/execution.
API timing is client-observed request/response wall time, not pure model inference. Local processing is total minus both API phases.
Parent timings (total, protected action, authentication, crypto) are inclusive and must not be added to their child timings. Preparation/check/tool residuals include instrumentation and glue overhead, not isolated primitive measurements.
Paired differences are ML-DSA-44 minus Ed25519. Total differences are observational, not a causal estimate of crypto cost, because each workflow has independent Gemini/network variability.
The tool boundary is in-process: signed-envelope bytes measure size overhead, not actual remote-tool transfer latency. API/network time is measured only for Gemini calls.
Temperature zero does not guarantee deterministic model output. Summary correctness and semantic safety are not established by a non-empty response or a valid signature.
No API keys, private/public key material, raw task, file contents, proposals, envelopes, summaries, or raw exception messages are persisted.

- Fewer than 20 complete measured pairs: small-sample p95 and total-time comparisons are exploratory.

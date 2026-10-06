# Gemini end-to-end signed-action benchmark

Status: completed. Measurement source: gemini_api.
Complete measured pairs: 20; attempted API methods: 84.

Keys and in-memory SQLite stores are initialized once per algorithm. Samples measure steady-state workflows; setup and key generation are reported separately.
Each complete algorithm workflow makes a fresh proposal call and a fresh summary call. Warm-ups and failed samples are excluded from latency statistics.

| Algorithm | Successful samples | Total median ms | LLM API median ms | Crypto median ms | Authentication median ms | Crypto share median % |
|---|---:|---:|---:|---:|---:|---:|
| Ed25519 | 20 | 1664.280750 | 1662.749600 | 0.208300 | 0.226500 | 0.012343 |
| ML-DSA-44 | 20 | 1688.029200 | 1685.696450 | 0.761200 | 0.796100 | 0.041513 |

## Latency distributions (milliseconds)

| Algorithm | Metric | Count | Mean | Median | p95 |
|---|---|---:|---:|---:|---:|
| Ed25519 | total_ms | 20 | 1670.635600 | 1664.280750 | 1768.791600 |
| Ed25519 | llm_api_ms | 20 | 1669.089000 | 1662.749600 | 1767.182400 |
| Ed25519 | proposal_api_ms | 20 | 736.711820 | 736.503350 | 792.236300 |
| Ed25519 | summary_api_ms | 20 | 932.377180 | 922.537100 | 1018.708200 |
| Ed25519 | sign_ms | 20 | 0.094145 | 0.088150 | 0.151700 |
| Ed25519 | verify_ms | 20 | 0.123380 | 0.116650 | 0.153200 |
| Ed25519 | authentication_ms | 20 | 0.238440 | 0.226500 | 0.297900 |
| Ed25519 | protected_action_ms | 20 | 1.481410 | 1.441350 | 1.699100 |
| ML-DSA-44 | total_ms | 20 | 1732.445630 | 1688.029200 | 2035.545900 |
| ML-DSA-44 | llm_api_ms | 20 | 1730.302370 | 1685.696450 | 2033.440700 |
| ML-DSA-44 | proposal_api_ms | 20 | 800.139750 | 753.775800 | 961.422700 |
| ML-DSA-44 | summary_api_ms | 20 | 930.162620 | 924.530000 | 1049.049700 |
| ML-DSA-44 | sign_ms | 20 | 0.641805 | 0.614200 | 1.088900 |
| ML-DSA-44 | verify_ms | 20 | 0.145750 | 0.138150 | 0.183200 |
| ML-DSA-44 | authentication_ms | 20 | 0.824420 | 0.796100 | 1.318900 |
| ML-DSA-44 | protected_action_ms | 20 | 2.079020 | 2.103000 | 2.559400 |

## Paired differences: ML-DSA-44 minus Ed25519

| Metric | Complete pairs | Mean ms | Median ms | p95 ms |
|---|---:|---:|---:|---:|
| crypto_ms | 20 | 0.570030 | 0.542350 | 0.996300 |
| authentication_ms | 20 | 0.585980 | 0.550700 | 1.028600 |
| protected_action_ms | 20 | 0.597610 | 0.647350 | 1.114500 |
| total_ms | 20 | 61.810030 | 13.670400 | 374.677800 |

## Interpretation

Crypto is pure sign + pure verify; authentication also includes production verifier construction. Protected action includes sender authorization/envelope construction and complete server acceptance/execution.
API timing is client-observed request/response wall time, not pure model inference. Local processing is total minus both API phases.
Parent timings (total, protected action, authentication, crypto) are inclusive and must not be added to their child timings. Preparation/check/tool residuals include instrumentation and glue overhead, not isolated primitive measurements.
Paired differences are ML-DSA-44 minus Ed25519. Total differences are observational, not a causal estimate of crypto cost, because each workflow has independent Gemini/network variability.
The tool boundary is in-process: signed-envelope bytes measure size overhead, not actual remote-tool transfer latency. API/network time is measured only for Gemini calls.
Temperature zero does not guarantee deterministic model output. Summary correctness and semantic safety are not established by a non-empty response or a valid signature.
No API keys, private/public key material, raw task, file contents, proposals, envelopes, summaries, or raw exception messages are persisted.


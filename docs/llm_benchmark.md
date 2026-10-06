# Gemini End-to-End Benchmark

## What this experiment measures

This is a separate experiment from `benchmarks/run_benchmarks.py`. The original
crypto-only script, numerical results, CSV, and charts remain unchanged.

The completed [6 October 2026 run](../results/llm_e2e/20261006T103303092153Z-7d2cda94/llm_e2e_results.md)
used `gemini-3.5-flash-lite`: 20 measured pairs, one warm-up pair, 84 real API
calls, and no failures. [Experimental Results](results.md) gives the complete
comparison and the distinction between measured crypto cost and noisy total
workflow differences. The earlier two-pair smoke test remains separate.

Each workflow performs the real assignment sequence:

```text
Gemini tool proposal
  -> strict proposal validation
  -> trusted sender authorization
  -> canonical envelope creation and Ed25519/ML-DSA-44 signing
  -> production service verification, freshness, authorization, and replay checks
  -> bounded read_file execution
  -> Gemini summary of the original task and returned text
```

Both calls are actual API requests during a live run; there is no cached
proposal, reused summary, or deterministic fallback. The summary is untrusted
display-only text, never a new tool action. Signing keys and envelopes are not
sent to Gemini. The tool service runs in-process: this is not a benchmark of
remote tool transport or a distributed deployment.

## Before spending API calls

Use approved synthetic UTF-8 `.txt` data within the configured data root. The
provider receives the task and the entire bounded file content during summary
generation; signatures do not prevent that disclosure. The runner freezes the
selected file bytes for comparable samples and records their SHA-256 and byte
count. It does not persist raw task/file/summary text, credentials, keys, or
signed envelopes in benchmark artifacts.

The live command requires explicit `--live` and the existing process settings:

```dotenv
PQSA_LLM_URL=https://generativelanguage.googleapis.com/v1beta/openai/chat/completions
PQSA_LLM_MODEL=your-available-gemini-model
PQSA_LLM_API_KEY=your-key
```

It uses Google's HTTPS compatibility endpoint and a configured Gemini model.
Google documents this endpoint in its
[OpenAI compatibility guide](https://ai.google.dev/gemini-api/docs/openai).
Keep your working model setting; the benchmark does not automatically select
a model or load `.env`. Load only the three named settings using the PowerShell
example in the [README](../README.md#optional-live-model-demonstration), without
printing the key.

One algorithm workflow uses two API calls, so each complete comparison pair
uses four. The maximum planned call count is
`4 * (pairs + warmup_pairs)`: 20 measured pairs plus one warm-up pair require
up to 84 calls. Check the model/project's actual available quota and billing;
neither a model choice nor a one-second interval guarantees capacity or zero
cost. Google's [rate-limit documentation](https://ai.google.dev/gemini-api/docs/rate-limits)
explains that limits depend on model/project usage tier and that actual
capacity can vary.

## Run with the already working bundled Python

From PowerShell in the repository, after loading your existing environment:

```powershell
Set-Location "C:\Users\ADAM\Desktop\Post-Quantum-Secure-AI-Agent"
$pqsaPython = "C:\Users\ADAM\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
$env:PYTHONPATH = Join-Path (Get-Location) "src"
```

Start with two measured pairs and no warm-ups, at most 8 calls:

```powershell
& $pqsaPython -B -m benchmarks.run_llm_benchmark --live --pairs 2 --warmup-pairs 0 --max-api-calls 8 --task "Read report.txt and summarize it in one sentence."
```

To reproduce the completed research comparison, use 20 measured pairs and one warm-up pair,
at most 84 calls:

```powershell
& $pqsaPython -B -m benchmarks.run_llm_benchmark --live --pairs 20 --warmup-pairs 1 --max-api-calls 84 --task "Read report.txt and summarize it in one sentence."
```

With an installed project virtual environment, replace `& $pqsaPython -B` with
`.\.venv\Scripts\python.exe`. The original offline benchmark command remains:

```powershell
& $pqsaPython -B -m benchmarks.run_benchmarks --repetitions 500 --scales 1,100,1000,10000
```

## Controls and artifacts

| Option | Default | Purpose |
|---|---|---|
| `--live` | Not enabled | Explicit permission for real provider calls |
| `--pairs` | `20` | Measured Ed25519/ML-DSA-44 comparison pairs |
| `--warmup-pairs` | `1` | Separate warm-up pairs excluded from aggregate results |
| `--interval-seconds` | `1` | Delay between workflows; increase if quota requires it |
| `--max-api-calls` | `100` | Hard upper bound on attempted provider calls |
| `--data-root` | `data` | Trusted source directory |
| `--file` | `report.txt` | One approved file relative to that directory |
| `--task` | Runner's report-summary task | Same task for both algorithms; match it to `--file` |
| `--timeout-seconds` | `30` | Timeout for each model request |
| `--output-dir` | Unique directory under `results/llm_e2e/` | New run namespace |

The runner refuses to overwrite any of its four artifact names before paid
calls begin. It does not replace existing crypto evidence:

- `llm_e2e_results.json`: configuration, metadata, setup, samples, and status;
- `llm_e2e_samples.csv`: individual workflow timing samples;
- `llm_e2e_summary.csv`: aggregate comparison statistics;
- `llm_e2e_results.md`: readable run report and interpretation cautions.

It retries neither provider calls nor signed actions. At the first failure it
stops, records a sanitized error, and preserves partial artifacts. Warm-ups and
failures remain visible but are excluded from successful aggregate statistics.
Always report completion status, complete measured pair count, warm-up count,
failure count, and attempted API-call count. A partial run is not a completed
20-pair experiment. Credential-free tests identify their source as
`test_double`; only actual provider measurements use `gemini_api`.

Pacing is between workflows; proposal and summary within a workflow have no
artificial delay. This is not a requests-per-minute limiter. Each completed
sample is checkpointed outside its timed region. Force-killing the process
during artifact writing can still leave incomplete files.

## Timing definitions

Latency fields in each sample's `timing_ms` are milliseconds. Each algorithm
uses a long-lived key, trusted-key registry, policy, and in-memory SQLite replay
store. One-time key generation/setup is reported separately. `total_ms` measures
the steady-state workflow, not startup/setup, inter-call pacing, or artifact
writing. This intentionally differs from the demo CLI's fresh key generation
on every invocation.

| Metric | Meaning |
|---|---|
| `proposal_api_ms`, `summary_api_ms` | Separate provider round trips, including network and provider overhead |
| `llm_api_ms` | Sum of those two API durations |
| `proposal_validation_ms` | Strict parsing/schema validation after the proposal call |
| `sender_authorization_ms` | Sender's trusted policy decision before signing |
| `envelope_preparation_ms` | Request preparation/canonicalization around the sign operation |
| `sign_ms`, `verify_ms` | Direct cryptographic signing and signature-verification operations |
| `verifier_construction_ms` | Verifier/public-key construction, separate from pure verification |
| `crypto_ms` | `sign_ms + verify_ms` |
| `authentication_ms` | Cryptographic operations plus verifier construction |
| `receiver_authorization_ms`, `replay_ms` | Independent receiver policy and atomic replay claim |
| `server_other_checks_ms` | Remaining service validation/freshness/canonicalization checks |
| `tool_and_response_ms` | Bounded file read and response construction |
| `protected_action_ms` | Inclusive sender authorization/signing and complete service execution |
| `total_ms` | Proposal through returned summary, including local orchestration |
| `local_processing_ms` | Total minus both API round trips; includes protection and orchestration |

These fields are nested, not independent costs: do not add `crypto_ms`,
`authentication_ms`, `protected_action_ms`, and `local_processing_ms` together.
The report gives directly measured cryptographic, authentication, and protected
action percentages in `shares_percent`, relative to that sample's `total_ms`.
Small instrumentation overhead is part of this experimental implementation.
The server audit option is disabled in these benchmark stacks. Recorded runs
therefore exclude the durable audit I/O added to the CLI later. Do not claim
the historical numbers measure the new default audited demonstration.

## Interpret the comparison honestly

The runner makes adjacent algorithm pairs and alternates which algorithm goes
first. Every workflow makes fresh proposal and summary calls against the same
configured model/task/frozen data; no scheme receives a cached LLM result.

Report mean, median, and p95 for each algorithm, along with paired
ML-DSA-minus-Ed25519 differences. Those total-time differences are noisy,
noncausal observations: network, service load, model output, and provider
scheduling can dominate a single pair. Alternating order reduces an obvious
ordering bias but cannot isolate a cryptographic causal effect. Directly
measured sign/verify/authentication costs and their shares provide the narrower
overhead evidence.

With fewer than 20 complete measured pairs, label p95 exploratory; the
eight-call smoke test is a connectivity/correctness check, not a strong tail
latency study. Larger samples remain subject to provider variability and
quota/cost constraints. Report the actual input hash/size, configured model,
environment, source, sample counts, and failures with any conclusion. The JSON
also retains hashes of the executable source so a dirty working tree's HEAD
is not mistaken for the exact measured implementation.

Do not call API round-trip time pure inference, estimate provider CPU or memory
from local process measurements, or claim measured remote tool network latency
for the in-process service. A successful timed response also does not establish
summary accuracy or prompt-injection resistance. Twenty pairs are a modest
single-host/model sample even though the initial comparison is complete; p95
remains descriptive, not a deployment guarantee. These instructions provide
methodology. Both the completed comparison and prior connectivity smoke test
are documented in [Experimental Results](results.md).

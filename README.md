# Post-Quantum Secure AI Agent

A research prototype for authenticating AI-agent tool actions with **Ed25519**
or **ML-DSA-44**, independent authorization, freshness checks, and replay
protection. It includes a real Gemini proposal-and-summary workflow,
adversarial experiments, and separate cryptographic and end-to-end benchmarks.

> Is post-quantum authentication practical for AI-agent actions, and how much
> overhead does it add when real LLM calls are part of the workflow?

The executable tool is deliberately small: bounded `read_file` access to
UTF-8 `.txt` files inside a trusted data directory. This is a research
prototype, not a production security gateway or a general autonomous agent.

## Contents

- [Architecture and security model](#architecture-and-security-model)
- [Installation](#installation)
- [Offline demo](#offline-demo)
- [Gemini configuration and live demo](#gemini-configuration-and-live-demo)
- [Historical action verification](#historical-action-verification)
- [Tests and adversarial experiments](#tests-and-adversarial-experiments)
- [Benchmarks](#benchmarks)
- [Measured results](#measured-results)
- [Configuration and command reference](#configuration-and-command-reference)
- [Limitations and production recommendations](#limitations-and-production-recommendations)
- [Project structure and documentation](#project-structure-and-documentation)

## Architecture and security model

```text
User task
  -> untrusted AI tool proposal
  -> strict structured-request validation
  -> trusted authorization policy
  -> canonical request creation
  -> trusted Ed25519 or ML-DSA-44 signer
  -> signed action envelope
  -> tool service
  -> signature, freshness, authorization, and replay checks
  -> execute or reject
  -> live mode: display-only LLM summary of the authorized result
```

The LLM never receives the private signing key. The signer owns key use;
the receiving service owns its trusted-key registry and independently applies
policy. Summary text cannot enter the tool-proposal or signing path.

Signatures authenticate exact request bytes under a trusted key binding. They
do **not** encrypt content, grant authorization, establish user intent, or make
model decisions safe. Ed25519 is the compact classical baseline; ML-DSA-44
is the FIPS 204 post-quantum signature mode. Both use a common interface and
canonical payload profile through the maintained `cryptography` library;
no cryptographic mathematics is handwritten.

The signed payload covers protocol, audience, algorithm, agent/key identity,
request ID, nonce, issue/expiry times, tool, and arguments. Canonicalization
uses domain-separated, sorted compact UTF-8 JSON and rejects floating-point
values. The signature is outside the payload. The maximum request lifetime
is 60 seconds; SQLite atomically claims both request ID and nonce.

The file boundary rejects traversal, absolute/device paths, links, oversized
files, and invalid UTF-8. When audit is enabled, the accepted signed request
is durably retained before tool invocation. Cryptography does not solve prompt
injection: a manipulated but policy-valid action can still be signed and
executed. The attack suite deliberately demonstrates that limit.

## Installation

Requirements:

- Git and access to this repository.
- Python **3.11 or later** on a platform supported by `cryptography` **50.x**
  with ML-DSA-44 support. Dependencies are declared in `pyproject.toml`.
- A Gemini API key and an available Gemini model for live workflows only.

Offline demos, tests, and the cryptographic benchmark need no API key.
Live calls consume provider quota and may incur charges.

The implemented research prototype is on `feat/assignment-rebuild`. Clone
that branch, then use the setup commands for your operating system:

```bash
git clone --branch feat/assignment-rebuild https://github.com/admatieh/Post-Quantum-Secure-AI-Agent.git
cd Post-Quantum-Secure-AI-Agent
```

### Windows PowerShell

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
python -m pip check
```

If PowerShell blocks activation, use `.\.venv\Scripts\python.exe` in place
of `python` in the remaining commands. Activation is not required; changing
the machine's execution policy is unnecessary.

### Linux or macOS (Bash)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
python -m pip check
```

Without activation, use `.venv/bin/python` in place of `python`.

### Verify algorithm availability

```bash
python -c "from signing.schemes import get_scheme; print([get_scheme(a).generate().algorithm for a in ('ed25519', 'ml-dsa')])"
```

Expected output:

```text
['Ed25519', 'ML-DSA-44']
```

Run all commands below **from the repository root** with the virtual
environment's Python. Editable installation exposes the `src/` packages;
`attacks` and `benchmarks` are repository modules. No manual `PYTHONPATH`
setting or application-specific bundled runtime is needed.

## Offline demo

```bash
python -m agent.cli "Read report.txt and summarize it." --algorithm ed25519
python -m agent.cli "Read report.txt and summarize it." --algorithm ml-dsa
```

The default backend is deterministic. It converts the task into a strict tool
proposal, signs the authorized request, verifies it, and reads `data/report.txt`.
Its output is a local 240-character preview, **not an LLM-generated summary**.
The JSON report identifies the signature algorithm, server result, request ID,
summary source, and summary status.

The installed entry point is equivalent:

```bash
pqsa-demo "Read report.txt and summarize it." --algorithm ml-dsa
```

To select a different trusted data directory or disable audit retention:

```bash
python -m agent.cli "Read report.txt and summarize it." --algorithm ed25519 --data-root data --audit-db runtime/demo-audit.sqlite3
python -m agent.cli "Read report.txt and summarize it." --algorithm ed25519 --no-audit
```

Place approved UTF-8 `.txt` inputs inside the selected directory. Tool paths
are relative to that directory, not arbitrary system paths.

## Gemini configuration and live demo

Live mode makes two API calls: one proposes the action; a second summarizes
the file only after the signed, authorized read succeeds. The provider receives
the original task and complete bounded file contents. Use synthetic or
otherwise approved data, not confidential files you cannot send to Google.

| Variable | Value |
|---|---|
| `PQSA_LLM_URL` | `https://generativelanguage.googleapis.com/v1beta/openai/chat/completions` |
| `PQSA_LLM_MODEL` | A `gemini-*` model available to your API key |
| `PQSA_LLM_API_KEY` | Your Gemini API key |

The recorded experiment used `gemini-3.5-flash-lite`; this is a record of
that run, not a guarantee of model availability for every account.

### Windows PowerShell: local `.env`

For a fresh checkout, create the local configuration file:

```powershell
Copy-Item .env.example .env
```

If `.env` exists, edit it instead of overwriting it. Replace the example
endpoint/model/key placeholders with your settings:

```dotenv
PQSA_LLM_URL=https://generativelanguage.googleapis.com/v1beta/openai/chat/completions
PQSA_LLM_MODEL=YOUR_GEMINI_MODEL
PQSA_LLM_API_KEY=YOUR_API_KEY
```

The application does **not** load `.env` automatically. Load only the three
named settings into the current process without printing the key:

```powershell
Get-Content -LiteralPath .env | ForEach-Object {
    if ($_ -match '^\s*(PQSA_LLM_URL|PQSA_LLM_MODEL|PQSA_LLM_API_KEY)\s*=\s*(.*?)\s*$') {
        [Environment]::SetEnvironmentVariable(
            $Matches[1], $Matches[2].Trim().Trim('"').Trim("'"), "Process"
        )
    }
}
```

### Linux or macOS (Bash): process variables

Set the endpoint and your available model, then enter the key at the hidden
prompt so it is not written into shell history:

```bash
export PQSA_LLM_URL="https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
export PQSA_LLM_MODEL="YOUR_GEMINI_MODEL"
read -r -s -p "Gemini API key: " PQSA_LLM_API_KEY
printf '\n'
export PQSA_LLM_API_KEY
```

### Run both signature modes

These commands work in either shell after configuration:

```bash
python -m agent.cli "Read report.txt and summarize it in one sentence." --backend live --algorithm ed25519
python -m agent.cli "Read report.txt and summarize it in one sentence." --backend live --algorithm ml-dsa
```

Successful output includes `summary_source: llm`, `summary_status: completed`,
the actual model/endpoint host, and separate proposal/summary API timings.
API durations include network/provider processing, not pure inference.
If summarization fails, the completed read is not repeated: the summary is
null with an explicit failure status and a sanitized error. There is no silent
offline fallback.

Keep `.env` and API keys out of Git. Local credentials, private-key files, and
runtime databases are ignored. A summary remains untrusted display-only text;
successful generation does not prove accuracy or injection resistance.

## Historical action verification

The CLI retains audit records by default in `runtime/audit.sqlite3`.
Each invocation generates a fresh disposable private key. The database stores
the signed envelope and resolved public-key binding, not private keys, model
messages, summaries, or returned file contents.

Save the displayed `request_id` and `audit_public_key_sha256` separately from
the database. Reverify that request in a new process:

```bash
python -m server.audit --database runtime/audit.sqlite3 --request-id "REQUEST_ID_FROM_DEMO" --public-key-sha256 "FINGERPRINT_FROM_DEMO"
```

Use the matching database if the demo selected `--audit-db`. Pair the
fingerprint with its own request ID; different runs use different keys.
Look for `signature_valid`, `binding_consistent`, `pin_matches`, `key_pinned`,
and `historical_only: true`. Verification does not execute the tool again or
require the old request to be fresh now.

To inspect all records without supplying a key pin:

```bash
python -m server.audit --database runtime/audit.sqlite3
```

Without an independently trusted fingerprint, validity is established only
under the key stored with the record. The database is not tamper-evident;
outcomes and log completeness are not authenticated. See
[Historical Action Audit](docs/architecture.md#historical-action-audit).

## Tests and adversarial experiments

### Full test suite and HTTP boundary

The suite uses Python's standard-library test runner:

```bash
python -m unittest discover -s tests -v
```

The validated implementation passes 83 tests, including both signature modes,
canonicalization, malformed proposals, authorization, expiry/replay, audit
failures, historical verification, and benchmark behavior. The suite does not
spend Gemini quota; live model responses are mocked.

The localhost HTTP adapter is a library interface, not a standalone CLI
service. The demo uses the same `ToolServer` in-process. Test the HTTP boundary:

```bash
python -m unittest tests.test_http -v
```

### Deterministic attacks

```bash
python -m attacks.run_attacks --algorithm both
```

To run a single signature mode:

```bash
python -m attacks.run_attacks --algorithm ed25519
python -m attacks.run_attacks --algorithm ml-dsa
```

The seven scenarios cover tampering, signature forgery, replay, expiry,
unauthorized actions, prompt injection, and a signed malicious-but-policy-valid
action. The last scenario is intentionally **accepted**, demonstrating that
authentication does not establish semantic safety. This suite's deterministic
proposal model does not measure Gemini's injection resistance.

### Real Gemini injection experiment

After configuring Gemini, run the bounded synthetic experiment:

```bash
python -m attacks.run_live_injection --live --max-api-calls 10 --output-dir results/live_injection
```

It makes eight proposal calls and two summary calls across both algorithms.
Reads are confined to synthetic temporary fixtures; no real system files,
environment variables, or shell execution are exposed. Reports have unique
filenames and exclude raw model text and secrets. There are no retries.
To omit the two summary calls:

```bash
python -m attacks.run_live_injection --live --skip-summary --max-api-calls 8 --output-dir results/live_injection
```

Small constructed samples are not attack success-rate estimates or proof
of general immunity. See the [recorded experiment](docs/results.md#live-gemini-injection-evidence).

## Benchmarks

### Cryptographic comparison: no LLM calls

Quick smoke run:

```bash
python -m benchmarks.run_benchmarks --repetitions 20 --scales 1,10 --output-dir runtime/crypto_smoke
```

Full comparison:

```bash
python -m benchmarks.run_benchmarks --repetitions 500 --scales 1,100,1000,10000 --output-dir runtime/crypto_benchmark
```

This measures key generation, signing, verification, key/signature/envelope
sizes, protected-action throughput, process CPU time, and Python-visible
memory. It reports mean/median/p95 and writes `benchmark_results.json`,
`benchmark_summary.csv`, `sign_latency.svg`, and `signature_size.svg`.

The explicit ignored `runtime/` output directories preserve the checked-in
evidence under `results/`. The runner defaults to `results/` and overwrites
its fixed filenames; choose a separate output directory when retaining
an earlier run.

### Real Gemini end-to-end comparison

This is separate from the cryptographic benchmark. Each algorithm workflow
makes fresh proposal and summary calls around the production signed-action
pipeline, without cached model output or deterministic fallback.

Connectivity smoke test: two pairs, no warm-up, at most **8 API calls**:

```bash
python -m benchmarks.run_llm_benchmark --live --pairs 2 --warmup-pairs 0 --max-api-calls 8 --task "Read report.txt and summarize it in one sentence."
```

Research comparison: 20 measured pairs and one warm-up, at most **84 API calls**:

```bash
python -m benchmarks.run_llm_benchmark --live --pairs 20 --warmup-pairs 1 --interval-seconds 1 --timeout-seconds 30 --max-api-calls 84 --task "Read report.txt and summarize it in one sentence."
```

The budget is `4 * (pairs + warmup_pairs)`. Check quota and billing before
running. Pacing is between workflows, not a requests-per-minute limiter.
The selected task and bounded file contents are sent to Google.

Each run creates a unique directory under `results/llm_e2e/`, containing
`llm_e2e_results.json`, `llm_e2e_samples.csv`, `llm_e2e_summary.csv`, and
`llm_e2e_results.md`. An explicit output directory containing those files
is rejected rather than overwritten. The runner stops on the first failure
without retries and preserves safe partial evidence.

Pairs alternate algorithm order; setup and warm-ups are excluded from
steady-state aggregates. Crypto, authentication, protected-action, and total
times are nested measurements, not costs to add together. The tool service
is in-process and audit is disabled in benchmark stacks, so timings exclude
remote tool transport and audit I/O. See [Methodology](docs/llm_benchmark.md).

## Measured results

The checked-in experiments were recorded on 6 October 2026 with Python
3.12.14 and `cryptography` 50.0.1. Results are specific to the measured host,
input, model, and workload; they are not deployment guarantees.

### Cryptographic results

| Metric | Ed25519 | ML-DSA-44 |
|---|---:|---:|
| Keygen median | 0.0332 ms | 0.1024 ms |
| Sign median | 0.0338 ms | 0.4528 ms |
| Sign p95 | 0.0343 ms | 1.4104 ms |
| Verify median | 0.0949 ms | 0.1118 ms |
| Public key | 32 B | 1,312 B |
| Signature | 64 B | 2,420 B |
| Signed envelope | 457 B | 3,602 B |
| 10,000-request throughput | 1,194.16 req/s | 671.54 req/s |

See [Experimental Results](docs/results.md) and the
[raw cryptographic report](results/benchmark_results.json).

### Gemini results

The completed `gemini-3.5-flash-lite` experiment used 20 measured pairs,
one warm-up pair, 84 real API calls, and no failures:

| Mean latency | Ed25519 | ML-DSA-44 |
|---|---:|---:|
| Sign plus verify | 0.217525 ms | 0.787555 ms |
| Protected action | 1.481410 ms | 2.079020 ms |
| Two Gemini round trips | 1,669.089000 ms | 1,730.302370 ms |
| Complete workflow | 1,670.635600 ms | 1,732.445630 ms |

Paired extra ML-DSA crypto cost was **0.570030 ms mean**, 0.542350 ms median,
and 0.996300 ms p95: small relative to these roughly 1.7-second API round
trips, while signature/envelope sizes increased substantially.

The observed 61.810030 ms mean total difference is **not** cryptographic
overhead: independent API timing accounts for 61.213370 ms of it. Twenty
pairs are a modest sample; p95 is descriptive. Historical measurements exclude
audit I/O. See the [completed report](results/llm_e2e/20261006T103303092153Z-7d2cda94/llm_e2e_results.md).

## Configuration and command reference

| Setting or option | Default / purpose |
|---|---|
| `--algorithm ed25519` / `--algorithm ml-dsa` | Explicit signature selection |
| `SIGNATURE_SCHEME` | CLI fallback when `--algorithm` is omitted; default `ed25519` |
| `--backend deterministic` / `--backend live` | Offline proposal model or real API calls |
| `--data-root` | Trusted input directory; default `data` |
| `--audit-db` | Demo audit database; default `runtime/audit.sqlite3` |
| `--no-audit` | Disable retention; mutually exclusive with `--audit-db` |
| `PQSA_LLM_URL`, `PQSA_LLM_MODEL`, `PQSA_LLM_API_KEY` | Live process configuration |
| `--file` and `--task` | Live benchmark input/task; keep them consistent |
| `--max-api-calls` | Explicit live-experiment budget |
| `--output-dir` | Benchmark/experiment artifact destination |

The generic demo adapter accepts compatible chat-completions services. The
two live research runners require the official Google HTTPS endpoint and a
`gemini-*` model identifier. List all supported options with:

```bash
python -m agent.cli --help
python -m server.audit --help
python -m attacks.run_attacks --help
python -m attacks.run_live_injection --help
python -m benchmarks.run_benchmarks --help
python -m benchmarks.run_llm_benchmark --help
```

If application imports fail, confirm the virtual environment is active and
rerun `python -m pip install -e .`. If attack/benchmark modules cannot be found,
return to the repository root. For live errors, check the three process
variables without printing the key; `.env` alone is not loaded. If ML-DSA is
unavailable, check the interpreter, installed `cryptography` version, and
platform/backend support before running experiments.

## Limitations and production recommendations

- Signatures do not prevent prompt injection, malicious model choices,
  compromised policy, or stolen keys. Semantic safety is separate from authentication.
- Offline output is a preview; live summaries can be inaccurate or manipulated
  but have no tool privileges.
- Replay uses single-host SQLite, not distributed exactly-once execution.
  The default CLI creates fresh demo keys and replay state on each invocation;
  deployments need durable replay state and protected keys.
- Audit provides verifiable request bytes, not authenticated outcomes or a
  complete tamper-evident history. External key trust is required.
- The localhost HTTP adapter has no TLS; responses are not signed.
- Canonicalization is a restricted Python profile, not full RFC 8785.
- Filesystem checks do not replace OS protection against hostile concurrent
  mutation. Memory measurements do not capture all native allocations.
- Benchmarks and bounded injection observations are not production certification.

For production, isolate signing keys in a protected service, support
rotation/revocation, authenticate and encrypt transport, protect policy/data,
design durable replay and idempotency, and use tamper-evident audit. Apply
narrower data/risk policy and independent security review. These are deployment
recommendations, not implemented guarantees.

## Project structure and documentation

```text
src/
  agent/        proposal adapters, strict schema, orchestration, CLI
  policy/       trusted authorization
  signing/      base.py, ed25519.py, ml_dsa.py, canonical envelope signing
  tools/        bounded read_file
  server/       verification, freshness, replay, HTTP adapter, audit
tests/          security, algorithm parity, HTTP, audit, benchmark tests
benchmarks/     cryptographic and live Gemini workflow benchmarks
attacks/        deterministic scenarios and live Gemini injection experiments
data/           demonstration inputs
results/        recorded JSON, CSV, SVG, and Markdown evidence
presentation/  submission PowerPoint with editable charts
docs/          research, architecture, analysis, methodology, demo
README.md
pyproject.toml
.env.example
```

- [Cryptography Research](docs/crypto_research.md)
- [Threat Model](docs/threat_model.md)
- [Architecture](docs/architecture.md)
- [Security Analysis](docs/security_analysis.md)
- [Experimental Results](docs/results.md)
- [Gemini Benchmark Methodology](docs/llm_benchmark.md)
- [Presentation and Live Demo Script](docs/demo_script.md)
- [Submission PowerPoint](presentation/Post_Quantum_Secure_AI_Agent_Presentation_Submission.pptx)
- [Submission Evidence Checklist](docs/submission_checklist.md)

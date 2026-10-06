# Post-Quantum Secure AI Agent

A focused research prototype that authenticates AI-agent tool actions with
Ed25519 or ML-DSA-44, enforces independent authorization, rejects stale and
replayed requests, and measures the operational cost of post-quantum
authentication.

## Problem and research question

An LLM can propose a tool action, but model output is untrusted. A receiving
service needs a reliable way to determine that the exact request passed through
a trusted signing boundary, was not modified, is fresh, and is permitted.

> Is post-quantum cryptographic authentication practical for securing
> AI-agent actions today, and what operational trade-offs does it introduce?

This repository answers that question with one deliberately small action:
`read_file` for bounded UTF-8 `.txt` files beneath `data/`. It is the assignment
prototype, not the future Secure Agent Action Gateway product.

## Architecture

```text
User
  -> untrusted proposal model
  -> strict structured proposal validation
  -> trusted authorization policy
  -> trusted signer (Ed25519 or ML-DSA-44)
  -> signed action envelope
  -> tool service
  -> signature + freshness + replay + authorization checks
  -> execute or reject
  -> live mode: text-only LLM summary of the authorized file result
     offline mode: local text preview
```

The LLM/model adapter never receives the private key. The trusted signing
service owns key use. The tool service resolves verification keys from its own
registry and independently applies authorization after signature verification.
See [Architecture](docs/architecture.md) and [Threat Model](docs/threat_model.md).

## Why signatures instead of encryption

Encryption protects confidentiality. It does not, by itself, prove which agent
approved a request or whether the request was modified. Digital signatures bind
a private key to exact canonical request bytes, providing integrity and origin
authentication under the stated key-management assumptions. Payloads in this
prototype remain readable; use authenticated encryption or TLS separately when
confidentiality is required.

## Signature algorithms and agility

- **Ed25519** is the compact classical baseline: 32-byte public key and 64-byte
  signature in this implementation. It is not post-quantum secure.
- **ML-DSA-44** is the FIPS 204 post-quantum signature mode: 1,312-byte public
  key and 2,420-byte signature. The implementation uses the maintained
  `cryptography` library and does not implement cryptographic mathematics.

Both implement the interfaces in `src/signing/base.py`, use the same canonical
payload profile, and pass the same security suite. Choose a mode with
`--algorithm ed25519|ml-dsa` or `SIGNATURE_SCHEME`.

## Signed action envelope

The signature covers canonical, domain-separated bytes containing:

- protocol and audience;
- algorithm, agent ID, and trusted key ID;
- UUID request ID and a random nonce;
- issue and expiry timestamps;
- tool name and arguments.

Objects use sorted compact UTF-8 JSON. Floating-point values are forbidden in
the signed profile to avoid number-format ambiguity. The signature remains
outside the payload.

## Authorization, freshness, and replay protection

Authentication and authorization are separate. Even a correctly signed
`delete_database` request is denied because the assignment policy permits only
`read_file`. The server owns the allowed `data/` root and rejects absolute
paths, traversal, Windows drive/device forms, links/reparse points, hard links,
non-regular files, oversized files, and invalid UTF-8.

Freshness uses `issued_at`, `expires_at`, a 60-second maximum lifetime, and
limited clock skew. SQLite atomically claims both request ID and nonce, so a
captured valid request cannot be accepted twice while replay state is retained.

## Prompt-injection limitation

Cryptography does not solve prompt injection. An injected prompt can influence
the proposal before it is signed. Strict schema validation and policy can block
known forbidden outputs, but a manipulated action that remains policy-valid can
still be signed and executed. The seventh attack demonstrates this by accepting
a validly signed read of the synthetic `confidential.txt` fixture.

## Current status

| Area | Status |
|---|---|
| Ed25519 generation, signing, verification | Implemented and tested |
| ML-DSA-44 generation, signing, verification | Implemented and tested |
| Canonical signed envelope | Implemented and tested |
| Freshness, request-ID and nonce replay checks | Implemented and tested |
| Independent authorization and bounded `read_file` | Implemented and tested |
| Natural-language proposal layer | Deterministic offline demo implemented |
| Optional live LLM adapter | Actual Gemini proposal and summary completed in both modes, including audited CLI rehearsal |
| Seven required attack scenarios | All passed in both modes |
| Benchmark scales through 10,000 requests | Measured on this host |
| Separate Gemini end-to-end benchmark | Completed: 20 measured pairs, one warm-up pair, 84 real API calls, no failures |
| Historical action audit | Both audited live requests verified in a separate process with independent key fingerprints |
| Real Gemini injection experiment | Completed: 10 actual calls, no failures; forbidden path/shell proposals denied before signing |
| Submission presentation | All ten slides rendered and visually inspected; package, layout, charts and embedded workbooks validated |
| 15-minute presentation and demo plan | Commands rehearsed; script provided in `docs/demo_script.md` |

The technical assignment deliverables are complete. A human timed rehearsal
remains. Publication of `feat/assignment-rebuild` is authorized without merging.
The native PowerPoint
application has not been opened; deck validation used rendering and reimport.
See the [Submission Checklist](docs/submission_checklist.md) for evidence and
delivery status.

The deterministic backend is intentionally reproducible; it exercises the same
untrusted-output boundary but is not represented as a live LLM. The optional
OpenAI-compatible chat-completions adapter returns untrusted JSON that passes
through the same parser, policy, signer, and server. Only after a successful
authorized read does live mode make a second model call with the original task
and returned file text. That response is display-only: it cannot authorize,
sign, or execute another action.

## Quick start

Requirements: Python 3.11+ and a platform where `cryptography` 50 exposes
ML-DSA-44. On the demonstrated Windows host, the bundled Python already has
the required library. The commands below use that verified runtime:

```powershell
Set-Location "C:\Users\ADAM\Desktop\Post-Quantum-Secure-AI-Agent"
$pqsaPython = "C:\Users\ADAM\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
$env:PYTHONPATH = Join-Path (Get-Location) "src"
```

Run the complete offline demo with both algorithms:

```powershell
& $pqsaPython -B -m agent.cli "Read report.txt and summarize it." --algorithm ed25519
& $pqsaPython -B -m agent.cli "Read report.txt and summarize it." --algorithm ml-dsa
```

The output shows the natural-language task, strict proposal, selected signature
algorithm, request ID, server result, and `summary_source`. Offline mode uses
`local_preview`: whitespace-normalized text clipped to 240 characters, not an
LLM-generated summary. Live mode uses `llm` for the second API response. Private
keys are generated in memory for the demo and are never exposed to the model
backend. The CLI retains audit records by default in the ignored
`runtime/audit.sqlite3`; `--audit-db` selects a different local database and
`--no-audit` disables retention. Library/server audit is explicitly optional.

For another machine, install this package with `python -m pip install -e .`
inside a suitable virtual environment and substitute that environment's Python.

## Later action verification

Keep the displayed `request_id` and `audit_public_key_sha256` outside the audit
database if you need to pin the original public key. A new process can verify
the retained request without the private key or another tool execution:

```powershell
& $pqsaPython -B -m server.audit --database runtime/audit.sqlite3 --request-id "REQUEST-ID-FROM-DEMO" --public-key-sha256 "FINGERPRINT-FROM-DEMO"
```

Omit `--request-id` to inspect all retained records. Without a separately
trusted fingerprint, verification establishes validity under the key in the
record only. The database retains the signed envelope, resolved public-key
binding, and reported execution state. It excludes private keys, credentials,
model messages, summaries, and returned file text. Signed arguments can still
contain metadata such as file paths; protect the database accordingly.

Historical verification checks the signature and identity binding. It does not
reexecute the action or claim the request is fresh now. The ordinary local
database and outcome fields are not signed or tamper-evident; deleting records
or replacing an entire envelope/key pair is not detected without outside
trust. See [Architecture](docs/architecture.md#historical-action-audit).

## Tests and attacks

The suite uses the standard library test runner, so no additional test package
is required:

```powershell
& $pqsaPython -B -m unittest discover -s tests -v
& $pqsaPython -B -m attacks.run_attacks --algorithm both
```

Coverage includes valid and invalid signatures, changed messages, incorrect
public keys, malformed model output, expired and future requests, replay,
unauthorized actions, HTTP execution, both algorithm modes, and all seven
assignment attacks:

1. message tampering;
2. signature forgery;
3. replay;
4. expired request;
5. unauthorized action;
6. prompt injection;
7. signed malicious-but-valid action.

The updated assignment suite passed all 83 tests in both independent staged
validation and the actual target repository. The final target run completed in
3.675 seconds with no failures or skips. The seven deterministic scenarios also
passed in both modes.

The seven-case suite uses a deterministic proposal model. A separate bounded
Gemini experiment tests prompt and file-content injection against both signing
modes, using synthetic temporary data and at most ten provider calls:

```powershell
& $pqsaPython -B -m attacks.run_live_injection --live --max-api-calls 10 --output-dir results/live_injection
```

Load the existing live settings first. Read its actual recorded proposal,
policy, and execution outcomes; successful signatures do not establish
general injection resistance. Provider errors are reported separately. The
[recorded live run](results/live_injection/live_injection_20261006T111819_769178Z_1468a3ef0e684eef9bef372bdcfd5f2b.md)
completed all ten calls without failures or retries: forbidden absolute-path
and shell proposals were denied by trusted policy before signing. The model
selected the public fixture for the synthetic confidential-file lure; the
summary injection marker was absent. These are bounded observations, not a
general defense guarantee.

## Benchmark methodology and results

Regenerate the committed research artifacts:

```powershell
& $pqsaPython -B -m benchmarks.run_benchmarks --repetitions 500 --scales 1,100,1000,10000
```

The 6 October 2026 run used Python 3.12.14, `cryptography` 50.0.1, and an AMD64
Family 25 Model 80 processor on Windows 11.

| Metric | Ed25519 | ML-DSA-44 |
|---|---:|---:|
| Keygen median | 0.0332 ms | 0.1024 ms |
| Sign median | 0.0338 ms | 0.4528 ms |
| Sign p95 | 0.0343 ms | 1.4104 ms |
| Verify median | 0.0949 ms | 0.1118 ms |
| Verify p95 | 0.0964 ms | 0.1153 ms |
| Public key | 32 B | 1,312 B |
| Signature | 64 B | 2,420 B |
| Signed envelope | 457 B | 3,602 B |
| 10,000-request throughput | 1,194.16 req/s | 671.54 req/s |

ML-DSA-44 was fast enough for this interactive prototype, but its signature and
envelope were much larger. That crypto-only run did not measure live model
latency; the separate Gemini experiment below supplies actual API measurements.
See [Experimental Results](docs/results.md),
[`benchmark_results.json`](results/benchmark_results.json), and the generated
charts in `results/`.

### Separate Gemini end-to-end benchmark

The original crypto-only benchmark above is unchanged. The separate
`benchmarks.run_llm_benchmark` runner measures fresh Gemini proposal and summary
calls around the production signed `read_file` flow for both algorithms. It
reports mean/median/p95 for API round trips, signing, verification, protected
action processing, and steady-state end-to-end time, together with measured
cryptographic/authentication shares. Keys and replay stores are reused within
the run; one-time setup is reported separately.

After loading the three existing `PQSA_LLM_*` settings as described below, use
approved synthetic report data. A small smoke test uses up to **8 API calls**:

```powershell
& $pqsaPython -B -m benchmarks.run_llm_benchmark --live --pairs 2 --warmup-pairs 0 --max-api-calls 8 --task "Read report.txt and summarize it in one sentence."
```

The completed research comparison used 20 measured pairs and one warm-up pair,
or up to **84 API calls**:

```powershell
& $pqsaPython -B -m benchmarks.run_llm_benchmark --live --pairs 20 --warmup-pairs 1 --max-api-calls 84 --task "Read report.txt and summarize it in one sentence."
```

Each run creates a separate directory under `results/llm_e2e/`; it does not
overwrite `benchmark_results.json`, its CSV, or the old charts. It stops at the
first failure without retries and retains safe partial artifacts. Fewer than
20 complete pairs give only exploratory p95 values. Adjacent algorithm pairs
alternate order to reduce time-order bias, but differences in total latency
remain noisy observations, not causal estimates of ML-DSA overhead.

The provider receives your task and full bounded report text. API durations
include network/provider overhead, not pure inference or remote tool transport.
The 6 October completed run used `gemini-3.5-flash-lite`: 20 successful measured
workflows per algorithm, one warm-up pair, 84 real API calls, and no failures.
Mean sign-plus-verify time was 0.217525 ms for Ed25519 and 0.787555 ms for
ML-DSA-44. The paired extra crypto time was 0.570030 ms mean, 0.542350 ms
median, and 0.996300 ms p95. Mean protected-action time was 1.481410 versus
2.079020 ms, while the two Gemini round trips averaged 1,669.089000 versus
1,730.302370 ms. Median crypto shares of total time were 0.012343% and
0.041513% respectively.

The observed mean total difference was 61.810030 ms, of which 61.213370 ms
was the independent API timing difference and 0.596660 ms was local processing.
It is not a causal estimate of cryptographic overhead. Twenty pairs are a
modest single-host/model sample; p95 is descriptive, not a performance guarantee.
Historical benchmark runs had server audit disabled, so these timings exclude
the new audit database I/O. See the
[completed run](results/llm_e2e/20261006T103303092153Z-7d2cda94/llm_e2e_results.md) and
[Gemini Benchmark Methodology](docs/llm_benchmark.md) for safety, timing
definitions, full options, and the bundled-Python commands.

## Optional live-model demonstration

Use a compatible chat-completions endpoint that supports JSON object output
for proposals and plain text for summaries. For Gemini, save these settings in
your local, ignored `.env`; use a model available to your Google API key:

```dotenv
PQSA_LLM_URL=https://generativelanguage.googleapis.com/v1beta/openai/chat/completions
PQSA_LLM_MODEL=your-gemini-model
PQSA_LLM_API_KEY=your-key
```

The project does not automatically load `.env`. In PowerShell, load only these
three settings into the current process without printing the key, then run:

```powershell
Get-Content -LiteralPath .env | ForEach-Object {
    if ($_ -match '^\s*(PQSA_LLM_URL|PQSA_LLM_MODEL|PQSA_LLM_API_KEY)\s*=\s*(.*?)\s*$') {
        [Environment]::SetEnvironmentVariable(
            $Matches[1], $Matches[2].Trim().Trim('"').Trim("'"), "Process"
        )
    }
}
& $pqsaPython -B -m agent.cli "Read report.txt and summarize it, make it one sentence long." --backend live --algorithm ed25519
& $pqsaPython -B -m agent.cli "Read report.txt and summarize it, make it one sentence long." --backend live --algorithm ml-dsa
```

Each successful live run uses two API calls: a tool proposal, then a summary.
The second call sends the entire bounded file result and your original task to
the configured cloud provider. Use synthetic or otherwise approved demo data;
signatures do not make that disclosure confidential.

The output identifies `llm_model` and `llm_endpoint_host`. `timing_ms` separates
`proposal_api`, `summary_api`, and `total`; API durations include network and
provider overhead, so they are not pure inference timings. On summary failure,
`server_status` remains `completed`, but `summary` is null and
`summary_status` is `failed` with a safe `summary_error`. There is no silent
preview fallback or repeat tool execution.

Do not commit `.env`, API keys, or private keys. File text is supplied as
untrusted data, not instructions. Both model responses remain untrusted: a
summary is not evidence of factual accuracy or successful injection defense.

## Known limitations

- The default demonstration is a deterministic proposal model, not a live LLM.
- Offline output is a local preview, not semantic summarization. Live summaries
  can be inaccurate or influenced by malicious file text; their output is
  display-only and does not receive tool execution privileges.
- The local HTTP adapter has no TLS; production transport must be authenticated
  and encrypted.
- Replay state is single-host SQLite and does not provide distributed
  exactly-once execution.
- The response is not signed, and logs are not tamper-evident.
- Retained request signatures can be checked later; stored keys and unsigned
  outcomes require independent trust, and local audit does not prove completeness.
- Canonicalization is a restricted Python profile, not full RFC 8785.
- Filesystem containment narrows but does not eliminate hostile concurrent
  mutation risk; the trusted data directory needs OS protection.
- Python-visible memory measurements do not include every native allocation.
- Cryptographic authentication does not prevent prompt injection, malicious
  model choices, compromised policy, or stolen keys.

## Production recommendations

Use an HSM, cloud KMS, TPM-backed service, or isolated signer; implement key
rotation and revocation; add TLS and response authentication; use durable
distributed replay state and idempotent execution; protect policy and data with
OS permissions; add tamper-evident audit; risk-tier actions; require approval
for high-impact operations; test the selected live model against prompt and
tool-content injection; and independently review the complete system.

## Project structure

```text
src/
  agent/       untrusted proposal adapters, strict schema, orchestration
  policy/      trusted assignment authorization
  signing/     base.py, ed25519.py, ml_dsa.py, canonical envelope signer
  tools/       bounded read_file implementation
  server/      verifier, freshness, replay, authorization, HTTP, historical audit
tests/         algorithm-parity, security, agent, HTTP, attack, benchmark tests
benchmarks/    reproducible latency, size, throughput, CPU, memory measurements
attacks/       seven deterministic attacks and bounded live Gemini injection
results/       JSON, CSV, and SVG evidence
presentation/  validated 10-slide PowerPoint deck with editable charts
docs/
  crypto_research.md
  threat_model.md
  architecture.md
  security_analysis.md
  results.md
  llm_benchmark.md
  demo_script.md
  submission_checklist.md
data/          harmless demonstration fixtures
README.md
pyproject.toml
```

## Deeper documentation

- [Cryptography Research](docs/crypto_research.md)
- [Threat Model](docs/threat_model.md)
- [Architecture](docs/architecture.md)
- [Security Analysis](docs/security_analysis.md)
- [Experimental Results](docs/results.md)
- [Gemini Benchmark Methodology](docs/llm_benchmark.md)
- [Presentation and Live Demo Script](docs/demo_script.md)
- [Submission PowerPoint Deck](presentation/Post_Quantum_Secure_AI_Agent_Presentation_Submission.pptx)
- [Submission Checklist](docs/submission_checklist.md)

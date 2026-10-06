# Fifteen Minute Presentation and Live Demo

Use `presentation/Post_Quantum_Secure_AI_Agent_Presentation_Submission.pptx`
with this script. Keep the completed benchmark and injection evidence open
before presenting; rerunning paid research experiments during the talk is
unnecessary.

## Prepare before the talk

Open PowerShell in the repository root and use the project virtual environment:

```powershell
Set-Location "C:\Users\ADAM\Desktop\Post-Quantum-Secure-AI-Agent"
$pqsaPython = Join-Path (Get-Location) ".venv\Scripts\python.exe"
$env:PYTHONPATH = Join-Path (Get-Location) "src"
```

For live Gemini, load only the three existing settings without printing keys:

```powershell
Get-Content -LiteralPath .env | ForEach-Object {
    if ($_ -match '^\s*(PQSA_LLM_URL|PQSA_LLM_MODEL|PQSA_LLM_API_KEY)\s*=\s*(.*?)\s*$') {
        [Environment]::SetEnvironmentVariable(
            $Matches[1], $Matches[2].Trim().Trim('"').Trim("'"), "Process"
        )
    }
}
```

The provider receives the task and bounded file contents. Use only the
approved demonstration data already stored under `data/`.
Each normal live workflow uses two API calls. Have the offline commands ready
in case provider access is unavailable, and label their preview accurately.

## 0:00–2:00 — Problem and research question

“An AI agent can propose a tool action, but model output is untrusted. The
receiving service must verify the exact request, its origin under a trusted
key, its freshness, and whether the action is permitted.” State the research
question: is post-quantum authentication practical for AI-agent actions today,
and what operational trade-offs does it introduce?

The experiment deliberately executes one small action: a bounded UTF-8
`read_file` beneath `data/`. This makes the security and timing comparison
inspectable.

## 2:00–4:00 — Cryptography and trust boundaries

Distinguish hashing, encryption, and signing. Signatures authenticate exact
bytes under a trusted key binding; they do not encrypt requests or establish
semantic safety. Ed25519 is the classical baseline; ML-DSA-44 provides the
post-quantum signature comparison. ML-KEM concerns key establishment, not the
signed-action task implemented here.

Show the architecture: untrusted proposal → strict schema → independent policy
→ trusted signer → server verification/freshness/policy/replay → bounded read.
The model never receives the private key. A returned summary is display-only
and cannot issue another tool action.

## 4:00–7:00 — Normal requests in both modes

Run the two live requests if provider access is available:

```powershell
& $pqsaPython -B -m agent.cli "Read report.txt and summarize it in one sentence." --backend live --algorithm ed25519 --audit-db runtime/demo-audit.sqlite3
& $pqsaPython -B -m agent.cli "Read report.txt and summarize it in one sentence." --backend live --algorithm ml-dsa --audit-db runtime/demo-audit.sqlite3
```

Point out `signed_algorithm`, `server_status: completed`, `summary_source: llm`,
`summary_status`, the configured model, and separate proposal/summary timings.
The first API call proposes; the second summarizes only after the authorized
read succeeds. Summary accuracy is still model-dependent. If the second call
fails, the read remains completed; show the null summary and failure status
without repeating the tool.

The rehearsable offline alternative is:

```powershell
& $pqsaPython -B -m agent.cli "Read report.txt and summarize it." --algorithm ed25519 --audit-db runtime/demo-audit.sqlite3
& $pqsaPython -B -m agent.cli "Read report.txt and summarize it." --algorithm ml-dsa --audit-db runtime/demo-audit.sqlite3
```

Its `summary_source: local_preview` is a local preview, not an LLM summary.

## 7:00–9:00 — Tampering, replay, and authorization

```powershell
& $pqsaPython -B -m attacks.run_attacks --algorithm both
```

Read the recorded outcomes: modified arguments and fabricated signatures fail;
a second execution of the same signed envelope is `REPLAY_DETECTED`; expiry
fails independently of signature validity. A correctly signed forbidden
`delete_database` request is `AUTHORIZATION_DENIED`, demonstrating receiver
policy even when authentication succeeds.

Pause on `signed_malicious_but_valid_action: ACCEPTED_AS_EXPECTED`. The
synthetic `confidential.txt` read fits this policy and therefore executes.
A signature does not prove that an action matches user intent or is harmless.
The seven-case suite's injection proposal is deterministic. Show the separate
recorded Gemini experiment from
`results/live_injection/live_injection_20261006T111819_769178Z_1468a3ef0e684eef9bef372bdcfd5f2b.md`
for actual model
behavior and distinguish model refusal, schema/policy blocking, and authorized
execution. Read the observed outcomes; do not infer universal resistance from
this bounded sample.

In that completed ten-call run, both algorithms saw forbidden absolute-path
and shell proposals denied before signing. Both confidential-file lures
selected the public fixture instead; both summary injection markers were
absent. Distinguish the observed policy protection from a general claim that
the model or signatures defeat prompt injection.

For a separate rehearsal rerun, the bounded live experiment uses at most ten
provider calls and synthetic temporary files:

```powershell
& $pqsaPython -B -m attacks.run_live_injection --live --max-api-calls 10 --output-dir results/live_injection
```

## 9:00–10:30 — Verify a retained request in a new process

Copy one displayed `request_id` and its `audit_public_key_sha256`. The signing
process has ended; its disposable private key is gone. Run:

```powershell
& $pqsaPython -B -m server.audit --database runtime/demo-audit.sqlite3 --request-id "REQUEST-ID-FROM-DEMO" --public-key-sha256 "FINGERPRINT-FROM-DEMO"
```

Show `signature_valid`, `binding_consistent`, `key_pinned`, `pin_matches`, and
`historical_only: true`. Running that verification again is safe: it reads
history without executing the tool. Omit `--request-id` to inspect all records.

Explain the limit: without an outside fingerprint, the signature is valid under
the stored key only. `log_integrity` and `outcome_integrity` are explicitly
`not_authenticated`; unsigned outcomes and deleted records are not proven.
Audit tampering experiments must use a copied test database, preserving the
original. The signature detects changed request bytes, while complete key and
envelope replacement needs outside key trust to detect.

## 10:30–13:00 — Results

Show the original `sign_latency.svg` and `signature_size.svg`. Report crypto-only
medians and the 2,420-byte ML-DSA signature versus 64 bytes for Ed25519. At
10,000 requests the measured local pipeline reached 671.54 versus 1,194.16
requests/second. Retain this evidence separately from the live benchmark.

Then show the completed Gemini comparison: 20 measured pairs, one warm-up
pair, 84 API calls, no failures, `gemini-3.5-flash-lite`. Direct sign-plus-verify
means were 0.217525 ms and 0.787555 ms; paired extra crypto was 0.570030 ms
mean, 0.542350 ms median, 0.996300 ms p95. The two API round trips averaged
1669.089000 ms and 1730.302370 ms. Authentication occupied a small fraction
of this host/model workflow.

The observed mean total difference was 61.810030 ms, comprising 61.213370 ms
of API timing difference and 0.596660 ms of local processing. It is not the
causal crypto overhead. Twenty pairs remain a modest sample, API timing includes
network/provider overhead, and the tool ran in-process. Historical audit was
disabled during benchmarking, so these numbers exclude new audit I/O.

## 13:00–15:00 — Conclusion and questions

“ML-DSA-44 was practical for this bounded interactive prototype. Its measured
cryptographic latency was small relative to these actual Gemini round trips;
its signature and envelope sizes were substantially larger. Signatures prove
request integrity under trusted keys, while authorization and semantic safety
remain separate.”

For production, discuss isolated key storage, rotation/revocation, authenticated
transport and responses, durable distributed replay/idempotency, narrower
data policy, tamper-evident audit, and broader model-specific injection testing.
These are deployment recommendations, not assignment completion gates.
Use `docs/crypto_research.md`, `docs/threat_model.md`, and
`docs/security_analysis.md` to answer questions.

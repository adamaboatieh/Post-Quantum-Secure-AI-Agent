# Security Analysis

## What the signatures provide

Ed25519 and ML-DSA-44 provide integrity and origin authentication for the exact
canonical request bytes under a trusted public-key binding. They do not encrypt
the request, prove that a model reasoned correctly, establish user intent, grant
authorization, or make a destructive request safe. Non-repudiation is limited
because key holders, key sharing, compromise, and operational controls affect
who could actually have produced a signature.

## Research questions

### Is ML-DSA practical for signing AI-agent actions today

For this local prototype, yes. ML-DSA-44 integrated behind the same interface,
passed the same positive and negative tests, and sustained about 672 complete
signed `read_file` requests per second at 10,000 requests on the measured host.
That is sufficient for an interactive single-agent demonstration. Practicality
does not imply production readiness: protocol size, backend support, key
management, interoperability, and implementation maturity still matter.

### What overhead does post-quantum authentication introduce

On the measured host, median ML-DSA-44 signing was about 0.453 ms compared with
0.034 ms for Ed25519. Median verification was about 0.112 ms versus 0.095 ms.
The larger operational difference was size: a 2,420-byte ML-DSA-44 signature
versus 64 bytes for Ed25519, producing a 3,602-byte signed envelope instead of
457 bytes for the benchmark payload.

### Is that overhead important relative to LLM inference latency

The original crypto-only measurements have sub-millisecond medians, but that
run did not have a configured live model endpoint. It does not establish a
measured comparison with LLM latency. The separate
[Gemini end-to-end experiment](llm_benchmark.md) now measures both API round
trips and the protected action, including direct sign/verify timings and their
observed share of steady-state total time. The completed run made 20 measured
comparison pairs, one warm-up pair, and 84 real `gemini-3.5-flash-lite` API calls
with no failures. Mean sign-plus-verify cost was 0.217525 ms for Ed25519 and
0.787555 ms for ML-DSA-44. Mean API round-trip totals were 1669.089000 and
1730.302370 ms. Paired extra crypto cost was 0.570030 ms mean, 0.542350 ms
median, and 0.996300 ms p95. Median crypto shares of total were 0.012343%
and 0.041513%. The evidence supports a narrow observation:
authentication was a small fraction of total time on this host/input/model.
Twenty pairs remain a modest sample rather than a deployment tail-latency
guarantee. See [Experimental Results](results.md) for raw evidence and timing
definitions.

Fresh calls in alternating adjacent algorithm pairs reduce some ordering bias,
but network and provider jitter remain. Do not attribute an observed total
ML-DSA-minus-Ed25519 difference solely to cryptography. Report the directly
measured cryptographic and authentication cost alongside total/API statistics,
and label API round trips accurately rather than calling them pure inference.
The observed mean total difference of 61.810030 ms contains 61.213370 ms of
API timing difference and 0.596660 ms of local processing difference. This is
not the measured 0.570030 ms mean crypto increment. One-time key/setup cost is
separate; the benchmark's key reuse differs from the demonstration CLI, which
creates fresh disposable keys on each run. Historical server audit was disabled,
so the reported benchmarks exclude later audit database I/O.

### How does prompt injection interact with signatures

Injection can change the proposal before signing. A signature then faithfully
authenticates that manipulated proposal. Independent policy blocks known
forbidden tools and paths, but the signed-malicious-action experiment proves
that a policy-valid harmful request can still execute. Cryptography protects
the transport and identity boundary, not semantic safety.

The live benchmark also sends the successfully read document to a cloud model
for summarization. The summary remains untrusted display-only text with no
route to another signed action. Use only approved synthetic data: signatures
do not prevent cloud disclosure or model hallucinations. Benchmark artifacts
exclude raw prompts, file text, summaries, credentials, keys, and envelopes,
but hashes and operational metadata can still identify the experiment. Timing
success does not establish summary quality or injection resistance.

The separate [ten-call live injection experiment](results.md#live-gemini-injection-evidence)
completed with Gemini in both signature modes. The model proposed a forbidden
absolute-path read and a shell action; trusted policy denied both before
signing. It selected the public fixture for the synthetic confidential-file
lure, and the summary injection marker was absent. These few constructed
responses do not establish an attack success rate or general immunity. The
deterministic signed-but-policy-valid confidential read still demonstrates
that a valid signature cannot repair an overly permissive semantic policy.

### Can a signed action be checked later

The CLI retains the exact signed request and the verifier's resolved
public-key/identity binding in local SQLite. A later read-only process can
check the request signature after the disposable private key is gone. A
public-key SHA-256 saved outside the database can pin the expected key.

A self-contained record proves validity under its stored key, not that this
key belongs to an independently trusted person or service. The database,
execution outcomes, and record completeness are not authenticated. An attacker
can delete records or replace an entire envelope/key pair; a pin detects key
replacement but does not sign the outcome. Historical verification also does
not recheck current freshness/replay or execute the action. This meets basic
research auditability, with tamper-evident logging remaining future work.

Both normal audited Gemini CLI workflows completed, then separate processes
successfully verified the retained request signatures and identity bindings
against independently saved fingerprints. This demonstrates later request
verification after the original signing processes exit, without tool execution.

### What happens if the key is compromised and where should keys live

Compromise destroys trustworthy attribution for that key. Production keys
should live in an HSM, cloud KMS, TPM-backed service, or isolated signing
service with a narrow authenticated API. The application should support key
IDs, overlapping rotation, revocation, audit, and incident response. Demo keys
are disposable and must never be committed.

### Should every action be signed

Every action that crosses a trust boundary and has security, financial,
privacy, or audit impact should be authenticated. Very low-risk local UI actions
may not justify the same cost. A risk-tiered design can reserve stronger
authorization, human approval, and possibly hybrid signatures for high-impact
operations while keeping low-risk actions lightweight.

### Would hybrid signatures make sense today

A classical-plus-post-quantum hybrid can hedge migration and implementation
risk when both ecosystems must be trusted. It also increases keys, signatures,
bandwidth, verification logic, downgrade handling, and operational complexity.
This prototype measures individual schemes to keep the comparison fair; hybrid
mode is a production recommendation, not an implemented claim.

### What must change before production

- isolate keys and protect policy/configuration with operating-system controls;
- use authenticated encrypted transport and signed or authenticated responses;
- design distributed replay state and idempotent execution semantics;
- add key rotation, revocation, audit integrity, monitoring, and incident response;
- narrow policy by data classification and risk, with approval for high-impact actions;
- test model and tool-content injection with the selected live model;
- validate the chosen cryptographic backend on every deployment platform;
- perform security review, fuzzing, dependency governance, and load testing.

## Main conclusion

ML-DSA-44 was operationally practical in this bounded experiment. Its latency
cost was measurable but small in absolute terms; its signature and envelope
size cost was substantial. The architecture is defensible only when its claim
stays narrow: signatures authenticate bytes and identity under protected keys,
while independent policy, replay state, key management, and AI-safety controls
remain separate requirements.

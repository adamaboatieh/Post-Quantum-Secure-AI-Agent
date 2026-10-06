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

The cryptographic measurements are sub-millisecond medians, but this run did
not have a configured live model endpoint and therefore did not measure LLM
inference. The repository deliberately reports that gap instead of substituting
an assumed 1-3 second figure. The live adapter can be measured in the final
environment before presentation.

### How does prompt injection interact with signatures

Injection can change the proposal before signing. A signature then faithfully
authenticates that manipulated proposal. Independent policy blocks known
forbidden tools and paths, but the signed-malicious-action experiment proves
that a policy-valid harmful request can still execute. Cryptography protects
the transport and identity boundary, not semantic safety.

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

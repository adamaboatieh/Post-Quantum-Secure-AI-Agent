# Fifteen Minute Presentation and Live Demo Script

## 0:00 to 2:00 Problem and research question

Explain that an AI agent can propose an action, but a receiving service needs
evidence that the exact action came through a trusted approval path, was not
modified, is fresh, and is authorized. State the research question: is
post-quantum authentication practical for AI-agent actions today, and what does
it cost operationally?

## 2:00 to 4:00 Cryptography foundation

Distinguish hashing, encryption, and signing. Signatures provide integrity and
origin authentication; they do not provide confidentiality. Explain why RSA
and elliptic-curve signatures face a future Shor-algorithm threat, why ML-KEM
is for key establishment, and why this project uses ML-DSA for signatures.

## 4:00 to 6:00 Architecture and trust boundaries

Show `docs/architecture.md`. Emphasize:

- the LLM and its output are untrusted;
- policy is trusted and independent;
- the signing service is highly trusted and owns the private key;
- the tool service independently verifies, authorizes, and replay-checks;
- request-supplied keys are never trusted.

## 6:00 to 9:00 Live successful requests

Run:

```powershell
pqsa-demo "Read report.txt and summarize it." --algorithm ed25519
pqsa-demo "Read report.txt and summarize it." --algorithm ml-dsa
```

Point out that only the algorithm changes. The structured proposal, canonical
payload, policy, replay check, and tool are identical.

## 9:00 to 11:30 Adversarial demonstration

Run:

```powershell
python -m attacks.run_attacks --algorithm both
```

Highlight tampering, forgery, replay, expiry, and unauthorized-action
rejections. Then pause on `signed_malicious_but_valid_action` being accepted.
Explain that this is the most important limitation: a signature proves which
trusted key approved exact bytes, not that the action was wise or harmless.

## 11:30 to 13:30 Results

Show `results/sign_latency.svg` and `results/signature_size.svg`. Report the
measured median sign/verify latencies, 2,420-byte ML-DSA signature, and
10,000-request throughput. State clearly that live LLM inference was not
measured in this environment and should be added before making a relative
latency claim.

## 13:30 to 15:00 Conclusion and questions

Conclude that ML-DSA-44 was practical for the bounded interactive prototype,
with modest absolute cryptographic latency and substantial message-size cost.
Recommend isolated key storage, TLS, distributed replay state, key rotation,
revocation, narrow risk-tiered policy, approvals for high-impact actions, and
model-specific injection testing before production.

Be ready to answer the questions listed in the assignment using
`docs/crypto_research.md`, `docs/threat_model.md`, and
`docs/security_analysis.md`.

# Threat Model

## Security claim

Under the assumptions that the signing key, trusted policy, trusted key
registry, tool service, and replay database remain uncompromised, the prototype
detects modification and forgery of signed requests, rejects expired or reused
requests, and denies actions outside the `read_file` policy.

This is a scoped claim. It does not promise confidentiality, safe model
reasoning, correct user intent, tamper-evident logs, operating-system sandboxing,
or safety after key or policy compromise.

## Assets

- Ed25519 and ML-DSA private keys;
- the binding between key ID, agent ID, algorithm, and public key;
- authorization policy and `data/` root;
- action payloads, tool results, and replay records;
- evidence used for the research conclusions.

## Adversary capabilities

The attacker may:

- modify an action or arguments in transit;
- fabricate signatures or present an untrusted public key;
- replay a captured valid request;
- delay a request until it is expired;
- ask the model for an unauthorized tool or unsafe path;
- inject instructions into user prompts or future tool-returned content;
- induce a policy-valid but semantically harmful request;
- modify unprotected application logs.

The initial model assumes the attacker cannot read or replace the private key,
trusted policy, trusted key registry, running verifier, or replay database.

## Threats, controls, and residual risk

| Threat | Implemented control | Expected result | Residual risk |
|---|---|---|---|
| Message or argument tampering | Signature over canonical payload | `INVALID_SIGNATURE` | Compromised signer can sign altered data |
| Signature forgery | Ed25519 or ML-DSA verification with trusted key | `INVALID_SIGNATURE` | Library/backend or key compromise |
| Fake agent identity | Server-owned key-to-agent binding | `UNTRUSTED_KEY` | Registry compromise |
| Replay | Freshness plus atomic request-ID and nonce claims | `REPLAY_DETECTED` | Replay state loss or split-brain deployments |
| Expired/future request | UTC issue/expiry checks and lifetime cap | `EXPIRED` or `NOT_YET_VALID` | Clock quality and synchronization |
| Unauthorized tool | Sender and receiver policy checks | `AUTHORIZATION_DENIED` | Policy may be too broad |
| Path escape | Restricted relative `.txt` path plus containment checks | Denied | Hostile concurrent filesystem mutation is not fully eliminated |
| Prompt injection | Strict proposal schema and independent policy | Known forbidden request blocked | Policy-valid harmful actions remain possible |
| Signed malicious action | No cryptographic prevention | Accepted if valid and authorized | Requires better semantic policy, approvals, or human review |
| Log modification | None beyond ordinary filesystem controls | Not detected | Logs are not tamper-evident |

## Authentication is not authorization

A valid signature answers who approved these exact bytes under a particular
key. It does not answer whether the requested action is permitted. The server
therefore verifies first and then applies its own policy. The attack suite signs
an unauthorized `delete_database` request with a real trusted key and confirms
that the server still denies it.

## Prompt injection

Digital signatures do not prevent prompt injection. Injection occurs before a
signature exists: it may influence the model's proposal. Schema validation can
reject malformed output and policy can reject known forbidden capabilities, but
a manipulated proposal can still be valid under both. The signed
`confidential.txt` experiment intentionally succeeds to demonstrate this limit.

## Private-key compromise

If a private key leaks, an attacker can produce signatures indistinguishable
from the legitimate signer. Freshness, replay, and authorization still constrain
what the stolen key can request, but authenticity for that identity is lost.
Production systems need hardware-backed or isolated key storage, least-privilege
signing APIs, key identifiers, rotation, rapid revocation, monitoring, and a
recovery procedure.

## Out of scope

- encryption or confidential transport;
- ML-KEM or a key-establishment protocol;
- general shell, write, delete, network, or database tools;
- MCP, multi-tenant gateway, dashboard, or enterprise policy features;
- a claim that cryptography makes AI decisions safe;
- production hardening or certification.

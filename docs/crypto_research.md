# Cryptography Research for the Post-Quantum Secure AI Agent

## Why this project uses cryptography

The agent will propose actions such as reading a file or calling a service. The
language model is not trusted to approve or authenticate those actions. A
trusted component therefore converts an approved action into deterministic
bytes and signs those bytes. The receiving service uses a trusted public key to
detect alteration and identify the approved signer before it separately checks
freshness and authorization.

The signature answers two narrow questions:

1. Were these exact bytes signed by the holder of the expected private key?
2. Have the signed bytes changed since signing?

It does **not** make an action safe, hide its contents, stop prompt injection,
or prove that the policy which approved it was correct.

## Cryptographic hash functions

A cryptographic hash function maps an input of any practical length to a
fixed-length digest. SHA-256 always produces 256 output bits. It is designed so
that an attacker cannot feasibly:

- recover an input from a chosen digest (**preimage resistance**);
- find a different input with the digest of a given input
  (**second-preimage resistance**); or
- find any two different inputs with the same digest
  (**collision resistance**).

Hashing is not encryption. Encryption is reversible with the correct key;
hashing has no decryption operation. A plain hash also does not authenticate
the sender because anyone can hash a replacement message.

### Small SHA-256 experiment

Changing only the uppercase `R` produces a completely different digest:

```text
SHA-256("Read report.txt")
= cb41d7b6d88ed309f4793d1fbfb92bd6860a0806f9b9857a5f26cbbc454f7d86

SHA-256("Read Report.txt")
= 82471b00692729234aba675423578bd2cf00a2e8f1016f0e8d8ee3743bdec51e
```

This avalanche behavior is useful for detecting changes, but the project uses
a digital signature—not a bare digest—to authenticate each action. SHA-256 is
specified by [NIST FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).

## Symmetric and asymmetric cryptography

**Symmetric cryptography** uses the same secret, or efficiently related secret,
for both directions of an operation. AES-GCM, for example, can provide
confidentiality and integrity when both parties already share a secret key. It
is fast, but securely distributing and attributing a shared key can be hard.

**Asymmetric cryptography** uses a key pair:

- a private key, which must remain secret; and
- a public key, which can be distributed to verifiers through a trusted
  identity-to-key registry.

Encryption and signing use keys for different purposes. Encryption protects
confidentiality. A signature protects message integrity and authenticates the
signing key. This project needs signatures because the tool service must verify
who approved an action. Transport encryption such as TLS remains useful, but
encryption alone does not create a durable signature over the action.

## Digital signatures

The basic flow is:

```text
KeyGen -> private key + public key
private key + message -> Sign -> signature
public key + message + signature -> Verify -> valid or invalid
```

The private key creates signatures. The public key verifies them but cannot
normally create them. Verification binds the signature to both the message and
the key.

Calling this “non-repudiation” requires care. A valid signature is strong
technical evidence about a key, but attribution to a person or organization
also depends on key issuance, custody, access controls, revocation, clocks,
audit records, and legal context. A stolen or shared private key weakens that
claim.

## Classical signature algorithms

### RSA

RSA security is based on the difficulty of factoring a large composite
integer on classical computers. Modern signatures should use a defined
signature encoding such as RSA-PSS; “raw RSA” is not a safe signature scheme.
NIST permits RSA signature moduli of at least 2048 bits in FIPS 186-5. A
2048-bit RSA signature occupies 256 bytes because its encoded size follows the
modulus size. RSA remains common in certificates, document/code signing, and
legacy protocols, but large-scale quantum computers running Shor's algorithm
would break its underlying mathematical assumption. See
[NIST FIPS 186-5](https://csrc.nist.gov/pubs/fips/186-5/final).

### ECDSA

ECDSA is based on the elliptic-curve discrete-logarithm problem. It provides
much smaller keys than RSA at comparable classical security levels, but it is
sensitive to implementation details, especially nonce generation. ECDSA is
widely used in TLS, software signing, hardware tokens, and cryptocurrencies.
Like RSA, it is not post-quantum safe because Shor's algorithm also applies to
elliptic-curve discrete logarithms.

### Ed25519

Ed25519 is an EdDSA signature scheme over Curve25519-related Edwards-curve
arithmetic. It uses deterministic signing, compact keys, compact signatures,
and a high-level API that avoids several common ECDSA nonce mistakes. Its raw
private seed and public key are each 32 bytes; a signature is 64 bytes. RFC 8032
places it around the 128-bit classical security level and explicitly notes that
a sufficiently large quantum computer would break it. See
[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032).

Ed25519 is the project's classical baseline because it is fast, compact, and
available through mature libraries. We use the library implementation rather
than implementing its mathematics ourselves.

## Why post-quantum cryptography exists

A cryptographically relevant quantum computer would change which mathematical
problems are practical to solve:

- **Shor's algorithm** can solve integer factorization and discrete logarithms
  efficiently on such a machine. That threatens RSA, Diffie-Hellman, ECDSA,
  Ed25519, and related public-key systems.
- **Grover's algorithm** provides a quadratic speedup for brute-force search.
  It affects symmetric key and hash security differently from Shor's complete
  break of common public-key assumptions. Larger symmetric keys and hash
  outputs can compensate for much of Grover's effect.

“Harvest now, decrypt later” most directly concerns encrypted data captured
today and decrypted after quantum capability arrives. For signatures, the
related future risk is forgery: an attacker who can derive a classical private
key may create signatures that appear to come from that key while it remains
trusted.

**Post-quantum cryptography (PQC)** consists of algorithms designed to run on
ordinary computers while resisting both classical and known quantum attacks.
It is not the same as **quantum cryptography**, which uses quantum physical
systems such as quantum key distribution.

## NIST post-quantum standards

NIST finalized its first three PQC standards in 2024. The two most relevant to
this project are:

- **ML-KEM**, standardized in
  [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), derives from
  CRYSTALS-Kyber. It establishes shared secret material for later symmetric
  encryption. It does not sign an agent action.
- **ML-DSA**, standardized in
  [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), derives from
  CRYSTALS-Dilithium. It generates and verifies digital signatures, so it is
  the relevant post-quantum replacement in this project.

ML-DSA's security is based on module-lattice problems rather than factoring or
elliptic-curve discrete logarithms. Its trade-off is much larger keys and
signatures. FIPS 204 defines three parameter sets:

| Parameter set | Private key | Public key | Signature |
| --- | ---: | ---: | ---: |
| ML-DSA-44 | 2,560 B | 1,312 B | 2,420 B |
| ML-DSA-65 | 4,032 B | 1,952 B | 3,309 B |
| ML-DSA-87 | 4,896 B | 2,592 B | 4,627 B |

FIPS 204 also permits retaining a 32-byte seed from which the expanded private
key can be regenerated. Comparisons must therefore state whether they measure
the seed, expanded key, DER/PEM encoding, or raw algorithm value.

The prototype uses ML-DSA-44 because it has the smallest standard
ML-DSA keys and signatures and is appropriate for measuring the minimum PQ
overhead. That is an engineering choice, not a claim that one parameter set is
correct for every production system.

## Required comparison

Sizes below are raw algorithm values for a representative parameter choice,
not PEM/DER files or base64 text.

| Algorithm | Type | Quantum-Safe? | Approx. Key Size | Signature Size | Typical Use |
| --- | --- | --- | --- | --- | --- |
| RSA-2048 | Signature | No | 2,048-bit public modulus (256 B); encoded public/private keys are larger | 256 B | Certificates, document/code signing, and legacy protocols |
| Ed25519 | Signature | No | 32 B public key; 32 B private seed | 64 B | Modern application signatures, SSH, package/protocol authentication |
| ML-DSA-44 | Signature | Yes, against known quantum attacks | 1,312 B public; 2,560 B expanded private, or 32 B retained seed | 2,420 B | Post-quantum software, protocol, document, and agent-action authentication |

“Quantum-safe” means designed against known classical and quantum attacks. It
does not mean mathematically proven unbreakable, correctly implemented, or
safe from key theft and policy errors.

## Canonical serialization

Signatures operate on bytes, not abstract JSON objects. These objects are
semantically equivalent but have different ordinary encodings:

```json
{"a": 1, "b": 2}
```

```json
{"b": 2, "a": 1}
```

The classical prototype therefore uses one canonicalization function for both
signing and verification. The MVP profile:

- sorts object keys;
- removes insignificant whitespace;
- encodes as UTF-8;
- forbids floating-point values; and
- prepends the domain separator `PQSA-ACTION-V1\0` before signing.

This is intentionally narrower than full
[RFC 8785 JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785).
The restriction reduces ambiguity for the first Python-only prototype. Before
cross-language interoperability, the project should adopt full RFC 8785 or
publish equivalent normative rules and shared golden-byte test vectors.

## What this means for the agent

- The LLM proposes only a structured action; it never receives the private key.
- A trusted policy decides whether the proposal is eligible for signing.
- Every field affecting identity, destination, action, or freshness is signed.
- The tool service obtains public keys from a trusted registry, never from the
  request itself.
- The tool service verifies the signature and then performs independent
  freshness, replay, and authorization checks.
- Ed25519 and ML-DSA use the same payload and tests so benchmark results
  isolate the change in signature algorithm.

## Primary technical sources

- [NIST FIPS 180-4 — Secure Hash Standard](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)
- [NIST FIPS 186-5 — Digital Signature Standard](https://csrc.nist.gov/pubs/fips/186-5/final)
- [RFC 8032 — EdDSA and Ed25519](https://www.rfc-editor.org/rfc/rfc8032)
- [NIST FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [`cryptography` ML-DSA API](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/mldsa/)
- [NIST announcement of the first finalized PQC standards](https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards)
- [RFC 8785 — JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785)

# Architecture

## Research boundary

This repository implements the assignment's signed AI-action prototype. It is
not a general agent gateway, an MCP platform, an approval dashboard, or a broad
document-processing system. Its only executable tool is a bounded `read_file`
operation for UTF-8 `.txt` files beneath the trusted `data/` directory.

## Data flow

```text
User task
   |
   v
Untrusted proposal model
   |  {"tool": "read_file", "arguments": {"path": "report.txt"}}
   v
Strict schema validation
   |
   v
Trusted authorization policy
   |
   v
Trusted signing service (Ed25519 or ML-DSA-44)
   |
   v
Signed action envelope
   |
   v
Tool service
   |-- exact envelope validation
   |-- server-owned key lookup
   |-- canonicalization and signature verification
   |-- timestamp freshness check
   |-- independent authorization
   |-- atomic request-ID and nonce claim
   `-- bounded tool execution or rejection
```

The HTTP adapter in `src/server/http_server.py` exposes the tool service on a
local service boundary. The default CLI demo uses the same `ToolServer` in one
process so it can run without managing background processes.

## Trust boundaries

| Component | Trust level | May do | Must not do |
|---|---|---|---|
| User input and model output | Untrusted | Propose a tool and arguments | Authorize, sign, or choose verification keys |
| Proposal parser | Trusted validation | Enforce the two-field proposal schema | Decide policy |
| Policy | Trusted | Allow one agent to use bounded `read_file` | Treat a signature as permission |
| Signing service | Highly trusted | Hold the private key and sign authorized structured actions | Give the key to the model |
| Tool service | Trusted | Verify, check freshness/replay/policy, execute | Trust request-supplied keys |
| Replay store | Trusted state | Atomically claim request IDs and nonces | Fail open |

The model backend receives only the natural-language task and a proposal
instruction. It is never passed the policy object, signer, private key, replay
store, or tool service.

## Signed protocol

The signature covers domain-separated canonical UTF-8 JSON containing:

- protocol and audience;
- algorithm, agent ID, and key ID;
- request ID and at least 128 bits of nonce;
- issue and expiry timestamps;
- tool and arguments.

The signature is outside the payload. Mapping keys are sorted, whitespace is
removed, floating-point values are forbidden, and the bytes are prefixed with
`PQSA-ACTION-V1\0`. This is a deliberately restricted profile, not a claim of
full RFC 8785 compatibility.

## Algorithm agility

`signing.base` defines common signer, verifier, and scheme contracts.
`signing.schemes` maps configuration values to `Ed25519Scheme` or
`MLDSA44Scheme`. Both algorithms sign exactly the same canonical payload and
pass the same security tests. The server binds the declared algorithm to a
server-owned trusted key record, preventing the request from registering its
own key or silently changing algorithms.

## Execution order

The server deliberately performs checks in this order:

1. Validate exact envelope and payload fields.
2. Resolve the server-owned trusted key and identity binding.
3. Recreate canonical bytes and verify the signature.
4. Check issue time, expiry, and maximum lifetime.
5. Apply server-side authorization.
6. Atomically claim request ID and nonce.
7. Execute the bounded tool.

The sender also authorizes before signing, but receiver-side authorization is
mandatory because clients and models are untrusted.

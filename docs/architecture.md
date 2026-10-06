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
   |-- optional durable audit before tool execution
   `-- bounded tool execution or rejection
             |
             v
Successful authorized file result
   |-- live: original task + file text -> untrusted text-only LLM summary
   `-- offline: local 240-character preview
             |
             v
Display only (no route back to signing or tool execution)
```

The HTTP adapter in `src/server/http_server.py` exposes the tool service on a
local service boundary. The default CLI demo uses the same `ToolServer` in one
process so it can run without managing background processes.

## Trust boundaries

| Component | Trust level | May do | Must not do |
|---|---|---|---|
| User input and model output | Untrusted | Propose a tool and arguments | Authorize, sign, or choose verification keys |
| File content and summary model output | Untrusted | Supply data and a display-only summary | Trigger further tools or change trusted policy |
| Proposal parser | Trusted validation | Enforce the two-field proposal schema | Decide policy |
| Policy | Trusted | Allow one agent to use bounded `read_file` | Treat a signature as permission |
| Signing service | Highly trusted | Hold the private key and sign authorized structured actions | Give the key to the model |
| Tool service | Trusted | Verify, check freshness/replay/policy, execute | Trust request-supplied keys |
| Replay store | Trusted state | Atomically claim request IDs and nonces | Fail open |
| Local audit store | Historical evidence with outside trust required | Retain requests and public-key bindings for later checks | Claim unsigned outcomes or log completeness are proven |

For the proposal call, the model backend receives only the natural-language
task and a proposal instruction. After the service successfully reads the
authorized file, live mode makes a separate summary call with a JSON-encoded
data object containing `task` and `file_content`. The complete bounded returned
text is included, and the original task preserves requests such as "make it
one sentence long." The summary system instruction marks file text as
untrusted data and requests plain text, not tool proposals.

Neither call is passed the policy object, signer, private key, signed envelope,
replay store, or tool service. The summary response is never parsed as an
action, signed, or executed. Treating file text as data and removing tool
privileges limits impact; it does not prove immunity to prompt injection or
guarantee an accurate summary. The configured provider receives file content,
so cloud disclosure must be acceptable for the chosen demo data.

Offline mode retains its deterministic local 240-character preview and labels
it `summary_source: local_preview`; it does not make a summary API call. Live
mode labels the summary `summary_source: llm` and identifies the model and
endpoint host. It records proposal and summary API round-trip durations
separately from total CLI processing; these are not pure inference timings.
If summarization fails, the completed tool result is not retried: the CLI
returns a null summary and an explicit failed summary status with a safe error.

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
`MLDSA44Scheme`. Both algorithms use the same canonical payload profile and
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
7. If audit is enabled, durably retain the accepted signed request.
8. Execute the bounded tool and record its outcome when audit is enabled.

The sender also authorizes before signing, but receiver-side authorization is
mandatory because clients and models are untrusted.

## Historical action audit

The demonstration CLI enables a local SQLite audit database by default at
`runtime/audit.sqlite3`. Select another path with `--audit-db` or disable
retention with `--no-audit`. `run_demo(..., audit_db=Path(...))` and the
`ToolServer` audit integration are optional, so historical benchmark runs and
existing library callers retain their original execution/timing behavior.

After acceptance checks and before tool execution, the service stores the
exact signed envelope and the server-resolved key ID, agent ID, algorithm, and
public key. It then records the reported execution state and time. Private
keys, API credentials, model messages, summaries, and returned file text are
excluded. Signed arguments remain in the envelope, so paths and other action
metadata may be sensitive. The ignored local database needs OS protection.

An initial audit write failure prevents tool execution. A failure to finalize
the outcome occurs after the tool may already have run; the durable outcome
is uncertain and the caller must not automatically retry that action.

`python -B -m server.audit --database runtime/audit.sqlite3` reads the database
in a new process and reports signature validity and identity-binding consistency
without private keys or tool execution. `--request-id` selects one historical
record. `--public-key-sha256` compares against a fingerprint saved outside the
database; the demo prints it as `audit_public_key_sha256`.

Historical verification reports `historical_only: true`: it does not require
the old request to be fresh now, recheck replay state, or authorize/reexecute
it. Success under a stored key alone does not establish independently trusted
identity. `log_integrity` and `outcome_integrity` are explicitly
`not_authenticated`. The database is ordinary local storage, outcomes are
unsigned, and missing/deleted records are not detectable. A pin narrows key
replacement risk but does not authenticate the log or outcome.

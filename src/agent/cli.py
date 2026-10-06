"""Run the complete assignment demo with Ed25519 or ML-DSA-44."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from time import perf_counter
from urllib.parse import urlsplit

from agent.agent import SecureActionAgent
from agent.backends import DeterministicDemoModel, ModelAPIError, OpenAICompatibleModel
from policy.policy import Policy
from server.audit import AuditStore, public_key_sha256
from server.replay import ReplayStore
from server.tool_server import ToolServer, TrustedKey
from signing.schemes import get_scheme
from signing.service import TrustedSigningService


def summarize_text(text: str, limit: int = 240) -> str:
    """Offline preview only; live mode uses the model's genuine summary."""
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 1].rstrip() + "…"


def run_demo(
    task: str,
    *,
    algorithm: str,
    data_root: Path,
    backend="deterministic",
    audit_db: Path | None = None,
) -> dict:
    started = perf_counter()
    if backend not in {"deterministic", "live"}:
        raise ValueError("unknown model backend")
    scheme = get_scheme(algorithm)
    signer = scheme.generate()
    signing_service = TrustedSigningService(signer)
    policy = Policy(data_root=data_root.resolve())
    if backend == "live":
        required = ("PQSA_LLM_URL", "PQSA_LLM_MODEL", "PQSA_LLM_API_KEY")
        if any(not os.getenv(name, "").strip() for name in required):
            raise ValueError("live mode requires PQSA_LLM_URL, PQSA_LLM_MODEL, and PQSA_LLM_API_KEY")
        model_backend = OpenAICompatibleModel(
            endpoint=os.environ["PQSA_LLM_URL"],
            model=os.environ["PQSA_LLM_MODEL"],
            api_key=os.environ["PQSA_LLM_API_KEY"],
        )
    else:
        model_backend = DeterministicDemoModel()
    agent = SecureActionAgent(model_backend, policy, signing_service)
    trusted_key = TrustedKey(
        agent_id=signing_service.agent_id,
        algorithm=signer.algorithm,
        public_key=signer.public_key_bytes(),
    )
    replay = ReplayStore()
    audit = None
    try:
        if audit_db is not None:
            audit = AuditStore(audit_db)
        server = ToolServer({signing_service.key_id: trusted_key}, replay, policy, audit_store=audit)
        proposal_started = perf_counter()
        proposal = agent.propose(task)
        proposal_ms = (perf_counter() - proposal_started) * 1000
        envelope = agent.authorize_and_sign(proposal)
        response = server.execute(envelope)
    finally:
        replay.close()
        if audit is not None:
            audit.close()
    content = response["result"].get("content", "")
    summary_ms = None
    summary_error = None
    if backend == "live":
        summary_started = perf_counter()
        try:
            summary = model_backend.summarize(task, content)
            summary_status = "completed"
        except ModelAPIError as exc:
            summary = None
            summary_status = "failed"
            summary_error = str(exc)
        finally:
            summary_ms = (perf_counter() - summary_started) * 1000
        summary_source = "llm"
    else:
        summary = summarize_text(content)
        summary_status = "local_preview"
        summary_source = "local_preview"
    report = {
        "task": task,
        "backend": backend,
        "proposal": proposal.as_dict(),
        "signed_algorithm": envelope["payload"]["algorithm"],
        "request_id": envelope["payload"]["request_id"],
        "server_status": response["status"],
        "summary": summary,
        "summary_source": summary_source,
        "summary_status": summary_status,
        "timing_ms": {
            "proposal_api": round(proposal_ms, 3) if backend == "live" else None,
            "summary_api": round(summary_ms, 3) if summary_ms is not None else None,
            "total": round((perf_counter() - started) * 1000, 3),
        },
    }
    if backend == "live":
        report["llm_model"] = model_backend.model
        report["llm_endpoint_host"] = urlsplit(model_backend.endpoint).hostname
    if summary_error is not None:
        report["summary_error"] = summary_error
    if audit_db is not None:
        report["audit_database"] = str(audit_db)
        report["audit_public_key_sha256"] = public_key_sha256(trusted_key.public_key)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("task", nargs="?", default="Read report.txt and summarize it.")
    parser.add_argument("--algorithm", choices=("ed25519", "ml-dsa"), default=None)
    parser.add_argument("--backend", choices=("deterministic", "live"), default="deterministic")
    parser.add_argument("--data-root", type=Path, default=Path("data"))
    audit_options = parser.add_mutually_exclusive_group()
    audit_options.add_argument("--audit-db", type=Path, default=Path("runtime/audit.sqlite3"))
    audit_options.add_argument("--no-audit", action="store_true", help="skip durable demo audit retention")
    args = parser.parse_args()
    report = run_demo(
        args.task,
        algorithm=args.algorithm or os.getenv("SIGNATURE_SCHEME", "ed25519"),
        data_root=args.data_root,
        backend=args.backend,
        audit_db=None if args.no_audit else args.audit_db,
    )
    print(json.dumps(report, indent=2, ensure_ascii=False))
    if report["summary_status"] == "failed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()

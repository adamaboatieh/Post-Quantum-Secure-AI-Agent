"""Run the complete assignment demo with Ed25519 or ML-DSA-44."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from agent.agent import SecureActionAgent
from agent.backends import DeterministicDemoModel, OpenAICompatibleModel
from policy.policy import Policy
from server.replay import ReplayStore
from server.tool_server import ToolServer, TrustedKey
from signing.schemes import get_scheme
from signing.service import TrustedSigningService


def summarize_text(text: str, limit: int = 240) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 1].rstrip() + "…"


def run_demo(task: str, *, algorithm: str, data_root: Path, backend="deterministic") -> dict:
    scheme = get_scheme(algorithm)
    signer = scheme.generate()
    signing_service = TrustedSigningService(signer)
    policy = Policy(data_root=data_root.resolve())
    if backend == "live":
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
    try:
        server = ToolServer({signing_service.key_id: trusted_key}, replay, policy)
        proposal = agent.propose(task)
        envelope = agent.authorize_and_sign(proposal)
        response = server.execute(envelope)
    finally:
        replay.close()
    content = response["result"].get("content", "")
    return {
        "task": task,
        "backend": backend,
        "proposal": proposal.as_dict(),
        "signed_algorithm": envelope["payload"]["algorithm"],
        "request_id": envelope["payload"]["request_id"],
        "server_status": response["status"],
        "summary": summarize_text(content),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("task", nargs="?", default="Read report.txt and summarize it.")
    parser.add_argument("--algorithm", choices=("ed25519", "ml-dsa"), default=None)
    parser.add_argument("--backend", choices=("deterministic", "live"), default="deterministic")
    parser.add_argument("--data-root", type=Path, default=Path("data"))
    args = parser.parse_args()
    report = run_demo(
        args.task,
        algorithm=args.algorithm or os.getenv("SIGNATURE_SCHEME", "ed25519"),
        data_root=args.data_root,
        backend=args.backend,
    )
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

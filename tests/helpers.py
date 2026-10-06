from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from agent.agent import SecureActionAgent
from agent.backends import DeterministicDemoModel
from policy.policy import Policy
from server.replay import ReplayStore
from server.tool_server import ToolServer, TrustedKey
from signing.schemes import get_scheme
from signing.service import TrustedSigningService

ALGORITHMS = ("ed25519", "ml-dsa")
FIXED_NOW = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)


def build_stack(algorithm: str, data_root: Path):
    signer = get_scheme(algorithm).generate()
    signing = TrustedSigningService(signer)
    policy = Policy(data_root=data_root)
    replay = ReplayStore()
    server = ToolServer(
        {signing.key_id: TrustedKey(signing.agent_id, signer.algorithm, signer.public_key_bytes())},
        replay,
        policy,
    )
    agent = SecureActionAgent(DeterministicDemoModel(), policy, signing)
    return signer, signing, policy, replay, server, agent

"""Untrusted proposal -> trusted validation/policy -> trusted signer."""

from __future__ import annotations

from datetime import datetime

from agent.backends import ProposalBackend
from agent.proposal import ToolProposal
from policy.policy import Policy
from signing.service import TrustedSigningService


class SecureActionAgent:
    def __init__(
        self,
        proposal_backend: ProposalBackend,
        policy: Policy,
        signing_service: TrustedSigningService,
    ) -> None:
        self._proposal_backend = proposal_backend
        self._policy = policy
        self._signing_service = signing_service

    def propose(self, task: str) -> ToolProposal:
        if not isinstance(task, str) or not task.strip():
            raise ValueError("task must be non-empty text")
        return ToolProposal.parse(self._proposal_backend.propose(task))

    def authorize_and_sign(self, proposal: ToolProposal, *, now: datetime | None = None) -> dict:
        self._policy.authorize(
            self._signing_service.agent_id,
            proposal.tool,
            proposal.arguments,
        )
        return self._signing_service.create_envelope(
            proposal.tool,
            proposal.arguments,
            now=now,
        )

    def create_envelope(self, task: str, *, now: datetime | None = None) -> dict:
        return self.authorize_and_sign(self.propose(task), now=now)

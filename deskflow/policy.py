"""Policy engine: deterministic, outside the model (design doc section 9).

Decides act / ask / escalate from the action's risk tier and the agent's
confidence, then issues HMAC-signed authorizations that the tool gateway checks.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from importlib import resources

from .models import Authorization, Decision, PolicyDecision, Risk

# (high confidence, low confidence), straight from the risk tier table in section 9.
MATRIX = {
    Risk.READ_ONLY: (Decision.ACT, Decision.ACT_THEN_ASK),
    Risk.LOW: (Decision.ACT, Decision.ASK),
    Risk.MEDIUM: (Decision.ACT_AFTER_IDENTITY, Decision.ESCALATE),
    Risk.HIGH: (Decision.NEED_APPROVAL, Decision.ESCALATE),
    Risk.PROHIBITED: (Decision.DENY, Decision.DENY),
}


def load_policy() -> dict:
    return json.loads(resources.files("deskflow").joinpath("data/policy.json").read_text())


class PolicyEngine:
    def __init__(self, policy: dict | None = None, secret: bytes | None = None):
        self.policy = policy or load_policy()
        self._secret = secret or secrets.token_bytes(32)

    @property
    def version(self) -> str:
        return self.policy["version"]

    @property
    def confidence_threshold(self) -> float:
        return self.policy["confidence_threshold"]

    def tier(self, tool: str) -> Risk:
        # Unknown tools are treated as prohibited: nothing runs outside policy.
        return Risk(self.policy["tools"].get(tool, "prohibited"))

    def evaluate(self, tool: str, confidence: float) -> PolicyDecision:
        tier = self.tier(tool)
        high, low = MATRIX[tier]
        decision = high if confidence >= self.confidence_threshold else low
        reason = f"{tool} is {tier.value} risk; confidence {confidence:.2f} -> {decision.value}"
        return PolicyDecision(tool, tier, decision, reason, self.version)

    def authorize(self, d: PolicyDecision, ticket_id: str, identity_verified: bool = False,
                  approver: str | None = None) -> Authorization | None:
        """Return a signed Authorization, or None if the preconditions are unmet."""
        ok = (
            d.decision in (Decision.ACT, Decision.ACT_THEN_ASK)
            or (d.decision is Decision.ACT_AFTER_IDENTITY and identity_verified)
            or (d.decision is Decision.NEED_APPROVAL and bool(approver))
        )
        if not ok:
            return None
        nonce = secrets.token_hex(8)
        return Authorization(d.tool, ticket_id, d.tier, d.policy_version, nonce,
                             self._sign(d.tool, ticket_id, d.policy_version, nonce), approver)

    def verify_auth(self, auth: Authorization | None, tool: str, ticket_id: str) -> bool:
        if auth is None or auth.tool != tool or auth.ticket_id != ticket_id:
            return False
        return hmac.compare_digest(
            auth.sig, self._sign(auth.tool, auth.ticket_id, auth.policy_version, auth.nonce))

    def _sign(self, *parts: str) -> str:
        return hmac.new(self._secret, "|".join(parts).encode(), hashlib.sha256).hexdigest()

    def peer_allowed(self, peer: str, task: str, fields: list[str]) -> tuple[bool, str]:
        rule = self.policy["a2a_peers"].get(peer)
        if not rule:
            return False, f"peer {peer} is not on the allow-list"
        if task not in rule["tasks"]:
            return False, f"task {task} is not allowed for {peer}"
        extra = sorted(set(fields) - set(rule["fields"]))
        if extra:
            return False, f"fields not allowed to be shared with {peer}: {extra}"
        return True, "allowed"

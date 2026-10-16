"""Agent2Agent collaboration (design doc section 5).

Discover -> authorise -> send -> track -> (verify, record: done by the workflow).
The transport here is an in-process JSON-RPC style envelope; the shapes follow the
A2A flow (agent card, scoped short-lived token, task states) so a real HTTPS peer can
replace the handler without changing the dispatcher.
"""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Callable

from .audit import AuditLog
from .policy import PolicyEngine
from .world import World


class PeerTimeout(Exception):
    pass


@dataclass
class AgentCard:
    name: str
    description: str
    skills: list[str]
    endpoint: str
    auth: str = "oauth2-service-token"


@dataclass
class Registry:
    cards: dict[str, AgentCard] = field(default_factory=dict)
    handlers: dict[str, Callable[[dict], dict]] = field(default_factory=dict)

    def register(self, card: AgentCard, handler: Callable[[dict], dict]) -> None:
        self.cards[card.name] = card
        self.handlers[card.name] = handler


# Task states from the peer map to ticket states
STATE_MAP = {"working": "in_progress", "input-required": "waiting_user",
             "completed": "resolved_pending_verify", "failed": "escalate"}


class HROnboardingPeer:
    """Mock HR agent. Owns its tools; DeskFlow only sees its agent card and results."""
    card = AgentCard("hr-onboarding", "Creates accounts and orders laptops for new hires",
                     ["onboard_new_hire"], "https://hr-agent.example.internal/a2a")

    def __init__(self, world: World, timeouts_before_success: int = 0, now=time.time):
        self.world, self._timeouts, self._now = world, timeouts_before_success, now
        self.calls = 0

    def handle(self, envelope: dict) -> dict:
        self.calls += 1
        p, tok = envelope["params"], envelope["auth"]
        if tok["scope"] != "hr-onboarding:onboard_new_hire" or tok["expires"] < self._now():
            return {"jsonrpc": "2.0", "id": envelope["id"], "result": {"state": "failed", "error": "invalid token"}}
        if self._timeouts > 0:
            self._timeouts -= 1
            raise PeerTimeout("peer did not answer in time")
        if not p.get("role"):
            return {"jsonrpc": "2.0", "id": envelope["id"],
                    "result": {"state": "input-required", "question": "What is the new hire's role?"}}
        uid, dev = p["user_id"], f"dev-{900 + len(self.world.devices)}"
        self.world.users[uid] = dict(name=p["name"], email=f"{uid}@example.com", locked=False, groups=[],
                                     apps=[], device=dev, manager="bob",
                                     password_reset_pending=False, mfa_reset_pending=False)
        self.world.devices[dev] = dict(os="windows", owner=uid, software=[])
        return {"jsonrpc": "2.0", "id": envelope["id"], "result": {
            "state": "completed", "artifact": {"accounts_created": [uid], "laptop_order": f"PO-{dev}", "device": dev}}}


class A2ADispatcher:
    def __init__(self, registry: Registry, policy: PolicyEngine, audit: AuditLog,
                 max_retries: int = 2, token_ttl_s: int = 300, now=time.time):
        self.registry, self.policy, self.audit = registry, policy, audit
        self.max_retries, self.ttl, self.now = max_retries, token_ttl_s, now

    def delegate(self, ticket_id: str, peer: str, task: str, payload: dict) -> dict:
        card = self.registry.cards.get(peer)
        if not card or task not in card.skills:
            return self._fail(ticket_id, peer, f"no peer {peer} with skill {task}")
        ok, why = self.policy.peer_allowed(peer, task, list(payload))
        if not ok:
            return self._fail(ticket_id, peer, why)
        token = {"value": secrets.token_hex(12), "scope": f"{peer}:{task}", "expires": self.now() + self.ttl}
        self.audit.append(ticket_id, "a2a", "a2a.send", {"peer": peer, "task": task, "fields": sorted(payload)})
        envelope = {"jsonrpc": "2.0", "id": secrets.token_hex(4), "method": "tasks/send",
                    "auth": token, "params": payload}
        for attempt in range(self.max_retries + 1):
            try:
                reply = self.registry.handlers[peer](envelope)
                break
            except PeerTimeout:
                self.audit.append(ticket_id, "a2a", "a2a.timeout", {"peer": peer, "attempt": attempt + 1})
        else:
            return self._fail(ticket_id, peer, "peer timed out after bounded retries")
        result = reply["result"]
        self.audit.append(ticket_id, "a2a", "a2a.result", {"peer": peer, "state": result["state"],
                                                           "ticket_state": STATE_MAP[result["state"]]})
        return result

    def _fail(self, ticket_id: str, peer: str, why: str) -> dict:
        self.audit.append(ticket_id, "a2a", "a2a.refused", {"peer": peer, "why": why})
        return {"state": "failed", "error": why}

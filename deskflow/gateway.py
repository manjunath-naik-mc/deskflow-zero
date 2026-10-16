"""Tool gateway (design doc sections 4, 8 and 9).

Every tool call from an agent goes through here. The gateway enforces: per-agent
allow-lists (least privilege), a signed policy authorization on every write, per-user
write caps, a global kill switch, idempotency keys, undo steps and audit logging.
"""
from __future__ import annotations

import json
import time
from collections import defaultdict

from .audit import AuditLog
from .connectors import TOOLS
from .models import Authorization, Risk
from .policy import PolicyEngine
from .world import World


class GatewayError(Exception):
    pass


AGENT_TOOLS = {
    "orchestrator": {"get_ticket"},
    "identity": {"get_user", "unlock_account", "reset_password", "reset_mfa", "grant_app_access"},
    "device": {"get_device", "run_diagnostic", "push_software"},
    "communicator": {"send_message", "verify_identity", "request_approval", "add_comment", "close_ticket"},
    "verifier": {"get_user", "get_device", "run_diagnostic"},  # read-only by construction
    "escalation": {"add_comment", "set_state"},
}


class ToolGateway:
    def __init__(self, world: World, policy: PolicyEngine, audit: AuditLog,
                 per_user_write_cap: int = 10, window_s: int = 3600, clock=time.time):
        self.world, self.policy, self.audit = world, policy, audit
        self.cap, self.window, self.clock = per_user_write_cap, window_s, clock
        self.kill_switch = False
        self._idem: dict[str, dict] = {}
        self._undo: dict[str, list[tuple[str, dict]]] = defaultdict(list)
        self._writes_by_user: dict[str, list[float]] = defaultdict(list)
        self.writes: dict[str, list[tuple[str, str]]] = defaultdict(list)

    def _is_write(self, tool: str) -> bool:
        return self.policy.tier(tool) is not Risk.READ_ONLY

    def call(self, agent: str, tool: str, args: dict, ticket_id: str,
             auth: Authorization | None = None) -> dict:
        spec = TOOLS.get(tool)
        if spec is None or spec.internal or tool not in AGENT_TOOLS.get(agent, set()):
            self.audit.append(ticket_id, agent, "tool.denied", {"tool": tool, "why": "not in allow-list"})
            raise GatewayError(f"{agent} may not call {tool}")
        write = self._is_write(tool)
        if write:
            if self.kill_switch:
                self.audit.append(ticket_id, agent, "tool.denied", {"tool": tool, "why": "kill switch"})
                raise GatewayError("kill switch is on: agents are read-only")
            if not self.policy.verify_auth(auth, tool, ticket_id):
                self.audit.append(ticket_id, agent, "tool.denied", {"tool": tool, "why": "no valid policy authorization"})
                raise GatewayError(f"{tool} requires a policy authorization")
            key = f"{ticket_id}:{tool}:{json.dumps(args, sort_keys=True)}"
            if key in self._idem:  # a retry never repeats a change
                self.audit.append(ticket_id, agent, "tool.idempotent_replay", {"tool": tool})
                return self._idem[key]
            target = args.get("user")
            if target:
                now = self.clock()
                recent = [t for t in self._writes_by_user[target] if now - t < self.window]
                if len(recent) >= self.cap:
                    self.audit.append(ticket_id, agent, "tool.denied", {"tool": tool, "why": "blast-radius cap"})
                    raise GatewayError(f"write cap reached for {target}")
                self._writes_by_user[target] = recent + [now]
        try:
            result, undo = spec.handler(self.world, {**args, "ticket_id": args.get("ticket_id", ticket_id)})
        except (KeyError, ValueError) as exc:
            self.audit.append(ticket_id, agent, "tool.error", {"tool": tool, "error": str(exc)})
            raise GatewayError(f"{tool} failed: {exc}") from exc
        self.audit.append(ticket_id, agent, "tool.write" if write else "tool.read",
                          {"tool": tool, "args": args, "result": result,
                           "policy": auth.policy_version if auth else None,
                           "approver": auth.approver if auth else None})
        if write:
            self._idem[key] = result
            self.writes[ticket_id].append((tool, spec.system))
            if undo:
                self._undo[ticket_id].append(undo)
        return result

    def rollback(self, ticket_id: str) -> list[str]:
        """Undo recorded changes in reverse order. Allowed even when the kill switch is on."""
        undone = []
        while self._undo[ticket_id]:
            tool, args = self._undo[ticket_id].pop()
            TOOLS[tool].handler(self.world, args)
            self.audit.append(ticket_id, "gateway", "tool.rollback", {"tool": tool, "args": args})
            undone.append(tool)
        return undone

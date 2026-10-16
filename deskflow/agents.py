"""Specialist agents (design doc section 5).

The prototype's reasoning is rule-based so it runs offline and deterministically.
Each agent keeps a narrow job and a narrow tool allow-list (see gateway.AGENT_TOOLS);
swap `Orchestrator.classify` or any agent body for an ADK/Gemini agent without
touching the gateway, policy or verifier.
"""
from __future__ import annotations

from .gateway import GatewayError, ToolGateway
from .models import Authorization, Evidence, Ticket
from .policy import PolicyEngine
from .rag import KnowledgeIndex, extract_error_codes, retrieve, rewrite_queries
from .world import World

RULES = {
    "account_unlock": [("locked out", 2), ("account is locked", 2), ("unlock", 2), ("locked", 1)],
    "password_reset": [("reset my password", 2), ("password", 1), ("forgot", 1)],
    "mfa_reset": [("mfa", 2), ("authenticator", 2), ("verification code", 1), ("new phone", 1)],
    "access_request": [("need access", 2), ("add me to", 2), ("access to", 1), ("permission", 1)],
    "vpn_issue": [("vpn", 1), ("can't connect", 1), ("cannot connect", 1), ("remote computer", 1)],
    "software_install": [("install", 2), ("software", 1), ("licence", 1), ("license", 1)],
    "onboarding": [("new hire", 2), ("onboard", 2), ("starts monday", 1)],
    "prohibited_request": [("delete account", 3), ("delete the account", 3), ("delete all", 3), ("bulk", 2)],
}
ALLOWED_CODES = {
    "account_unlock": {"UNLOCK_ACCOUNT"}, "password_reset": {"RESET_PASSWORD"}, "mfa_reset": {"RESET_MFA"},
    "access_request": {"GRANT_ACCESS"}, "vpn_issue": {"PUSH_VPN_PROFILE", "UNLOCK_ACCOUNT"},
    "software_install": {"INSTALL_SOFTWARE"},
}
PLAN = {  # resolution code -> (tool, specialist agent)
    "UNLOCK_ACCOUNT": ("unlock_account", "identity"), "RESET_PASSWORD": ("reset_password", "identity"),
    "RESET_MFA": ("reset_mfa", "identity"), "GRANT_ACCESS": ("grant_app_access", "identity"),
    "PUSH_VPN_PROFILE": ("push_software", "device"), "INSTALL_SOFTWARE": ("push_software", "device"),
}
STEP_UP_TOOLS = {"unlock_account", "reset_password", "reset_mfa", "grant_app_access"}


class Orchestrator:
    """Classifies and plans. Never calls a write tool itself."""

    def classify(self, text: str, attachment_texts: list[str]) -> tuple[str, float]:
        blob = " ".join([text, *attachment_texts]).lower()
        scores = {c: sum(w for kw, w in kws if kw in blob) for c, kws in RULES.items()}
        ranked = sorted(scores.items(), key=lambda kv: -kv[1])
        (best, bs), (_, second) = ranked[0], ranked[1]
        if bs == 0:
            return "unknown", 0.3
        conf = min(0.95, 0.5 + 0.15 * bs)
        if second >= bs * 0.8:  # ambiguous between two categories
            conf -= 0.2
        return best, round(conf, 2)

    def params_for(self, code: str, t: Ticket, world: World) -> dict | str:
        """Return tool params, or a question for the user when something cannot be looked up."""
        user = world.users[t.requester]
        text = t.text.lower()
        if code == "GRANT_ACCESS":
            apps = [a for a in world.apps if a in text]
            return {"user": t.requester, "app": apps[0]} if apps else "Which application do you need access to?"
        if code == "INSTALL_SOFTWARE":
            pk = [p for p in world.approved_packages if p in text]
            return {"device": user["device"], "package": pk[0]} if pk else "Which application should I install?"
        if code == "PUSH_VPN_PROFILE":
            return {"device": user["device"], "package": "vpn-profile"}
        return {"user": t.requester}


class KnowledgeAgent:
    def __init__(self, index: KnowledgeIndex, world: World, max_steps: int = 2):
        self.index, self.world, self.max_steps = index, world, max_steps

    def find(self, t: Ticket, category: str, attachment_texts: list[str]) -> tuple[list[Evidence], int]:
        os_ = self.world.devices[self.world.users[t.requester]["device"]]["os"]
        hint = None
        for step in range(1, self.max_steps + 1):  # agentic retrieval: refine once if evidence is thin
            queries = rewrite_queries(t.text, attachment_texts, hint)
            ev = retrieve(self.index, queries, ALLOWED_CODES[category], os_)
            if ev:
                return ev, step
            hint = category
        return [], self.max_steps


class Communicator:
    def __init__(self, gw: ToolGateway, policy: PolicyEngine):
        self.gw, self.policy = gw, policy

    def _auth(self, tool: str, tid: str) -> Authorization | None:
        return self.policy.authorize(self.policy.evaluate(tool, 1.0), tid)

    def call(self, tool: str, args: dict, tid: str) -> dict:
        return self.gw.call("communicator", tool, args, tid, self._auth(tool, tid))

    def verify_identity(self, user: str, tid: str) -> bool:
        return bool(self.call("verify_identity", {"user": user}, tid)["verified"])

    def request_approval(self, user: str, app: str, approver: str, tid: str) -> bool:
        return bool(self.call("request_approval", {"user": user, "app": app, "approver": approver}, tid)["approved"])

    def close(self, tid: str, user: str, explanation: str) -> None:
        self.call("add_comment", {"ticket_id": tid, "text": explanation}, tid)
        self.call("send_message", {"user": user, "text": explanation}, tid)
        self.call("close_ticket", {"ticket_id": tid}, tid)


class Verifier:
    """Independent of the actor: re-reads live state through read-only tools."""

    def __init__(self, gw: ToolGateway):
        self.gw = gw

    def check(self, code: str, params: dict, tid: str) -> tuple[bool, str]:
        try:
            if code in ("UNLOCK_ACCOUNT", "RESET_PASSWORD", "RESET_MFA", "GRANT_ACCESS"):
                u = self.gw.call("verifier", "get_user", {"user": params["user"]}, tid)
                if code == "UNLOCK_ACCOUNT":
                    return (not u["locked"]), f"account locked={u['locked']}"
                if code == "RESET_PASSWORD":
                    return u["password_reset_pending"], f"password reset pending={u['password_reset_pending']}"
                if code == "RESET_MFA":
                    return u["mfa_reset_pending"], f"MFA reset pending={u['mfa_reset_pending']}"
                return params["app"] in u["apps"], f"apps={u['apps']}"
            d = self.gw.call("verifier", "get_device", {"device": params["device"]}, tid)
            if params["package"] not in d["software"]:
                return False, f"{params['package']} not on device"
            if code == "PUSH_VPN_PROFILE":
                diag = self.gw.call("verifier", "run_diagnostic", {"device": params["device"], "check": "vpn"}, tid)
                return diag["ok"], f"vpn diagnostic ok={diag['ok']}"
            return True, f"{params['package']} present on device"
        except GatewayError as exc:
            return False, str(exc)


class EscalationAgent:
    def __init__(self, gw: ToolGateway, policy: PolicyEngine):
        self.gw, self.policy = gw, policy

    def package(self, t: Ticket, category: str, conf: float, reason: str, evidence: list[Evidence],
                proposed: dict | None, tid: str) -> dict:
        summary = {
            "ticket": tid, "requester": t.requester, "category": category, "confidence": conf,
            "reason": reason, "evidence": [e.doc_id for e in evidence], "proposed_action": proposed,
            "request": t.text[:300],
        }
        note = f"Escalated to service desk. Reason: {reason}. Proposed: {proposed or 'none'}."
        try:
            for tool, args in (("add_comment", {"ticket_id": tid, "text": note}),
                               ("set_state", {"ticket_id": tid, "state": "escalated", "assignee": "service-desk"})):
                auth = self.policy.authorize(self.policy.evaluate(tool, 1.0), tid)
                self.gw.call("escalation", tool, args, tid, auth)
        except GatewayError as exc:  # e.g. kill switch: summary is still returned to the caller
            summary["handoff_note"] = f"could not update ticket: {exc}"
        return summary


__all__ = ["Orchestrator", "KnowledgeAgent", "Communicator", "Verifier", "EscalationAgent",
           "PLAN", "STEP_UP_TOOLS", "ALLOWED_CODES", "extract_error_codes"]

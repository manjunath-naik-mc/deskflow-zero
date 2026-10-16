"""Ticket resolution workflow (design doc section 6).

perceive -> screen -> classify -> retrieve evidence -> policy gate -> act / ask / escalate
-> verify (roll back on failure) -> close -> write a decision trace.
"""
from __future__ import annotations

import json
import statistics
import time
from importlib import resources

from .a2a import A2ADispatcher, HROnboardingPeer, Registry
from .agents import (ALLOWED_CODES, PLAN, STEP_UP_TOOLS, Communicator, EscalationAgent, KnowledgeAgent,
                     Orchestrator, Verifier)
from .audit import AuditLog
from .gateway import GatewayError, ToolGateway
from .memory import GraphMemory
from .models import Decision, Evidence, Ticket, TicketResult
from .policy import PolicyEngine
from .rag import KnowledgeIndex, extract_error_codes
from .safety import screen_text
from .world import World


def load_json(name: str):
    return json.loads(resources.files("deskflow").joinpath(f"data/{name}").read_text())


class DeskFlow:
    def __init__(self, world: World | None = None, audit_path: str | None = None, hr_timeouts: int = 0):
        self.world = world or World()
        self.policy = PolicyEngine()
        self.audit = AuditLog(audit_path)
        self.gateway = ToolGateway(self.world, self.policy, self.audit)
        self.memory = GraphMemory()
        incidents, kb = load_json("incidents.json"), load_json("kb.json")
        self.memory.seed_incidents(incidents)
        self.orchestrator = Orchestrator()
        self.knowledge = KnowledgeAgent(KnowledgeIndex(kb, incidents, self.memory), self.world)
        self.comm = Communicator(self.gateway, self.policy)
        self.verifier = Verifier(self.gateway)
        self.escalation = EscalationAgent(self.gateway, self.policy)
        self.registry = Registry()
        self.hr_peer = HROnboardingPeer(self.world, timeouts_before_success=hr_timeouts)
        self.registry.register(HROnboardingPeer.card, self.hr_peer.handle)
        self.a2a = A2ADispatcher(self.registry, self.policy, self.audit)
        self.results: list[TicketResult] = []

    # ---------------------------------------------------------------- public
    def run(self, t: Ticket) -> TicketResult:
        t0 = time.perf_counter()
        t.id = t.id or self.world.new_ticket_id()
        self.world.tickets[t.id] = {"state": "open", "comments": []}
        self.audit.append(t.id, "orchestrator", "ticket.received",
                          {"requester": t.requester, "source": t.source, "channel": t.channel,
                           "attachments": [a.kind for a in t.attachments]})
        res = self._run(t)
        res.writes = list(self.gateway.writes[t.id])
        res.elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
        self.audit.append(t.id, "orchestrator", "ticket.result",
                          {"outcome": res.outcome, "category": res.category, "reason": res.reason})
        self.results.append(res)
        return res

    def metrics(self) -> dict:
        n = len(self.results) or 1
        closed = [r for r in self.results if r.outcome == "closed"]
        return {
            "tickets": len(self.results),
            "touchless_rate": round(len(closed) / n, 2),
            "escalated": sum(r.outcome == "escalated" for r in self.results),
            "waiting_user": sum(r.outcome == "waiting_user" for r in self.results),
            "median_ms_to_resolve": round(statistics.median([r.elapsed_ms for r in closed]), 2) if closed else None,
            "audit_entries": len(self.audit),
            "audit_chain_valid": self.audit.verify(),
        }

    # --------------------------------------------------------------- internals
    def _run(self, t: Ticket) -> TicketResult:
        steps: list[str] = []
        if t.requester not in self.world.users:
            return self._escalate(t, "unknown", 0.0, "requester is not a known user", [], None, steps)

        # 1. Untrusted input: screen the text and everything extracted from attachments.
        att_texts = [a.text for a in t.attachments]
        findings = screen_text(t.text) + [f for a in att_texts for f in screen_text(a)]
        if findings:
            self.audit.append(t.id, "safety", "input.blocked", {"patterns": findings})
            steps.append("input screened: prompt-injection pattern found, no tools will run")
            return self._escalate(t, "blocked_input", 0.0, "possible prompt injection in ticket or attachment",
                                  [], None, steps)

        # 2. Classify.
        category, conf = self.orchestrator.classify(t.text, att_texts)
        steps.append(f"classified as {category} (confidence {conf})")
        self.audit.append(t.id, "orchestrator", "ticket.classified", {"category": category, "confidence": conf})
        if category == "onboarding":
            return self._onboard(t, conf, steps)
        if category == "prohibited_request":
            d = self.policy.evaluate("delete_account", conf)
            steps.append(f"policy: {d.reason}")
            self.audit.append(t.id, "policy", "policy.decision", {"tool": d.tool, "decision": d.decision.value})
            return self._escalate(t, category, conf, "action is prohibited for autonomous agents", [], None, steps,
                                  decision=d.decision.value)
        if category == "unknown":
            return self._escalate(t, category, conf, "low confidence: could not classify the request", [], None, steps)

        # 3. Retrieve grounded evidence (policy first, then live state, then precedent, then knowledge).
        evidence, rounds = self.knowledge.find(t, category, att_texts)
        if not evidence:
            return self._escalate(t, category, conf, "no grounded evidence found; uncited steps are dropped",
                                  [], None, steps)
        best = evidence[0]
        steps.append(f"evidence: {best.doc_id} '{best.title}' -> {best.resolution_code} (retrieval rounds: {rounds})")
        code = best.resolution_code
        tool, specialist = PLAN[code]
        params = self.orchestrator.params_for(code, t, self.world)
        if isinstance(params, str):
            steps.append("ask the user once, for what cannot be looked up")
            return TicketResult(t.id, "waiting_user", category, conf, "missing information", question=params,
                                decision=Decision.ASK.value, steps=steps, citations=[e.doc_id for e in evidence[:2]])
        proposed = {"tool": tool, "args": params, "code": code}

        # 4. Policy gate.
        d = self.policy.evaluate(tool, conf)
        steps.append(f"policy {d.policy_version}: {d.reason}")
        self.audit.append(t.id, "policy", "policy.decision",
                          {"tool": tool, "tier": d.tier.value, "decision": d.decision.value, "confidence": conf})
        if d.decision in (Decision.ESCALATE, Decision.DENY, Decision.ASK):
            return self._escalate(t, category, conf, d.reason, evidence, proposed, steps, decision=d.decision.value)

        try:
            verified, approver = False, None
            if d.decision is Decision.ACT_AFTER_IDENTITY or tool in STEP_UP_TOOLS:
                verified = self.comm.verify_identity(t.requester, t.id)
                steps.append(f"step-up identity check: {'passed' if verified else 'failed'}")
                if not verified:
                    return self._escalate(t, category, conf, "identity check failed", evidence, proposed, steps,
                                          decision=d.decision.value)
            if d.decision is Decision.NEED_APPROVAL:
                approver = self.world.users[t.requester]["manager"]
                if not self.comm.request_approval(t.requester, params["app"], approver, t.id):
                    return self._escalate(t, category, conf, f"approval from {approver} was not granted",
                                          evidence, proposed, steps, decision=d.decision.value)
                steps.append(f"named approval received from {approver}")
            auth = self.policy.authorize(d, t.id, identity_verified=verified, approver=approver)

            # 5. Act through the gateway as the specialist agent.
            self.gateway.call(specialist, tool, params, t.id, auth)
            steps.append(f"{specialist} agent called {tool}")

            # 6. Verify independently; roll back on failure.
            ok, detail = self.verifier.check(code, params, t.id)
            steps.append(f"verifier: {detail}")
            if not ok:
                undone = self.gateway.rollback(t.id)
                steps.append(f"verification failed; rolled back {undone or 'nothing to undo'}")
                self._trace(t, category, code, "escalated", evidence, params)
                return self._escalate(t, category, conf, "verification failed after action", evidence, proposed,
                                      steps, decision=d.decision.value, trace=False)

            # 7. Close with an explanation and write the decision trace.
            explanation = self._explain(code, params, best)
            self.comm.close(t.id, t.requester, explanation)
            self._trace(t, category, code, "confirmed", evidence, params, approver)
            steps.append("ticket closed and decision trace written")
            return TicketResult(t.id, "closed", category, conf, "resolved and verified", explanation,
                                d.decision.value, steps, [e.doc_id for e in evidence[:2]])
        except GatewayError as exc:
            self.gateway.rollback(t.id)
            steps.append(f"gateway refused: {exc}")
            return self._escalate(t, category, conf, f"tool gateway refused the action: {exc}", evidence, proposed,
                                  steps, decision=d.decision.value)

    def _onboard(self, t: Ticket, conf: float, steps: list[str]) -> TicketResult:
        payload = {k: t.meta[k] for k in ("name", "user_id", "role", "start_date") if k in t.meta}
        if not {"name", "user_id"} <= payload.keys():
            return TicketResult(t.id, "waiting_user", "onboarding", conf, "missing information",
                                question="Who is the new hire (name and user id)?", decision=Decision.ASK.value, steps=steps)
        steps.append("delegating to hr-onboarding over A2A")
        reply = self.a2a.delegate(t.id, "hr-onboarding", "onboard_new_hire", payload)
        if reply["state"] == "input-required":
            return TicketResult(t.id, "waiting_user", "onboarding", conf, "peer needs more input",
                                question=reply["question"], decision=Decision.ASK.value, steps=steps)
        if reply["state"] != "completed":
            return self._escalate(t, "onboarding", conf, f"peer agent failed: {reply.get('error')}", [], None, steps)
        # The peer's report is untrusted input: check the system of record before closing.
        art = reply["artifact"]
        try:
            u = self.gateway.call("verifier", "get_user", {"user": payload["user_id"]}, t.id)
            dev = self.gateway.call("verifier", "get_device", {"device": art["device"]}, t.id)
            ok = u["device"] == art["device"] and dev["id"] == art["device"]
        except GatewayError:
            ok = False
        steps.append(f"verifier re-checked accounts and device in the system of record: {'ok' if ok else 'mismatch'}")
        if not ok:
            return self._escalate(t, "onboarding", conf, "peer result did not match the system of record", [], None, steps)
        explanation = f"Onboarding complete: account {payload['user_id']} created and laptop ordered ({art['laptop_order']})."
        self.comm.close(t.id, t.requester, explanation)
        self.memory.add_node(f"dec-{t.id}", "Decision", outcome="confirmed", code="A2A_ONBOARD", peer="hr-onboarding")
        return TicketResult(t.id, "closed", "onboarding", conf, "resolved by peer and verified", explanation,
                            Decision.ACT.value, steps)

    def _escalate(self, t: Ticket, category: str, conf: float, reason: str, evidence: list[Evidence],
                  proposed: dict | None, steps: list[str], decision: str = Decision.ESCALATE.value,
                  trace: bool = True) -> TicketResult:
        pkg = self.escalation.package(t, category, conf, reason, evidence, proposed, t.id)
        steps.append(f"escalated to service desk: {reason}")
        if trace and proposed and t.requester in self.world.users:
            self._trace(t, category, proposed["code"], "escalated", evidence, proposed["args"])
        return TicketResult(t.id, "escalated", category, conf, reason, decision=decision, steps=steps,
                            citations=[e.doc_id for e in evidence[:2]], escalation=pkg)

    def _trace(self, t: Ticket, category: str, code: str, outcome: str, evidence: list[Evidence],
               params: dict, approver: str | None = None) -> None:
        user = self.world.users[t.requester]
        codes = extract_error_codes(" ".join([t.text, *[a.text for a in t.attachments]]))
        self.memory.write_trace(
            ticket_id=t.id, user=t.requester, device=user["device"], category=category, code=code,
            outcome=outcome, policy_version=self.policy.version, citations=[e.doc_id for e in evidence[:2]],
            error_code=codes[0] if codes else None, app=params.get("app"), approver=approver)

    @staticmethod
    def _explain(code: str, params: dict, ev: Evidence) -> str:
        what = {
            "UNLOCK_ACCOUNT": "Your account has been unlocked.",
            "RESET_PASSWORD": "Your password was reset; the temporary credential went to your registered device.",
            "RESET_MFA": "Your MFA was reset; you can enrol your new device now.",
            "PUSH_VPN_PROFILE": "A fresh VPN profile was pushed to your device and the connection test passed.",
            "INSTALL_SOFTWARE": f"{params.get('package')} was installed on your device.",
            "GRANT_ACCESS": f"You now have access to {params.get('app')}, approved by your manager.",
        }[code]
        return f"{what} (Based on {ev.doc_id}: {ev.title}.)"

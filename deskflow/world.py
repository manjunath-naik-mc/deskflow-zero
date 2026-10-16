"""In-memory 'systems of record' standing in for the ITSM, IdP and MDM (design doc section 8).

Seeded with sample data. Scenario hooks (step_up, approvals, faults) simulate human
and system behaviour so the demo and tests are deterministic.
"""
from __future__ import annotations

import copy


class World:
    def __init__(self):
        self.users = {
            "alice": dict(name="Alice Rao", email="alice@example.com", locked=True, groups=["vpn-users"],
                          apps=[], device="dev-001", manager="bob",
                          password_reset_pending=False, mfa_reset_pending=False),
            "bob": dict(name="Bob Mehta", email="bob@example.com", locked=False, groups=["vpn-users", "managers"],
                        apps=["github"], device="dev-002", manager="carol",
                        password_reset_pending=False, mfa_reset_pending=False),
            "carol": dict(name="Carol Singh", email="carol@example.com", locked=False, groups=["vpn-users"],
                          apps=[], device="dev-003", manager="bob",
                          password_reset_pending=False, mfa_reset_pending=False),
            "dave": dict(name="Dave Iyer", email="dave@example.com", locked=False, groups=["vpn-users"],
                         apps=[], device="dev-004", manager="bob",
                         password_reset_pending=False, mfa_reset_pending=False),
        }
        self.devices = {
            "dev-001": dict(os="windows", owner="alice", software=["office"]),
            "dev-002": dict(os="macos", owner="bob", software=["office", "vpn-profile"]),
            "dev-003": dict(os="windows", owner="carol", software=["office", "vpn-profile"]),
            "dev-004": dict(os="windows", owner="dave", software=["office"]),
        }
        self.apps = ["github", "salesforce", "slack-admin"]
        self.approved_packages = ["zoom", "slack", "vscode", "office", "vpn-profile"]
        self.tickets: dict[str, dict] = {}
        # Scenario hooks
        self.step_up: dict[str, bool] = {}            # user -> passes step-up verification
        self.approvals: dict[tuple[str, str], bool] = {}  # (user, app) -> manager approves
        self.faults: set[str] = set()                 # tools that report success but change nothing
        self.messages: list[tuple[str, str]] = []
        self._seq = 1000

    def new_ticket_id(self) -> str:
        self._seq += 1
        return f"T-{self._seq}"

    def consume_fault(self, tool: str) -> bool:
        if tool in self.faults:
            self.faults.discard(tool)
            return True
        return False

    def snapshot(self) -> dict:
        return copy.deepcopy({"users": self.users, "devices": self.devices})

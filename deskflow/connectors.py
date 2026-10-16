"""Connectors, each a typed tool with a risk tier (design doc section 8).

In production each system is an MCP server. Here they are plain functions with the
same shape (name, JSON-like args, structured result, undo step), so the gateway
interface does not change when real MCP servers replace them.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .world import World


@dataclass
class ToolSpec:
    name: str
    system: str  # itsm | idp | mdm | chat
    handler: Callable[[World, dict], tuple[dict, tuple[str, dict] | None]]
    internal: bool = False  # undo-only tools are never in an agent allow-list


def _user(w: World, args: dict) -> dict:
    return w.users[args["user"]]


# ---- ITSM
def get_ticket(w, a):
    return dict(w.tickets.get(a["ticket_id"], {})), None

def add_comment(w, a):
    w.tickets.setdefault(a["ticket_id"], {"comments": []}).setdefault("comments", []).append(a["text"])
    return {"ok": True}, None

def set_state(w, a):
    t = w.tickets.setdefault(a["ticket_id"], {})
    t["state"] = a["state"]
    if a.get("assignee"):
        t["assignee"] = a["assignee"]
    return {"ok": True}, None

def close_ticket(w, a):
    w.tickets.setdefault(a["ticket_id"], {})["state"] = "closed"
    return {"ok": True}, None


# ---- Identity (IdP)
def get_user(w, a):
    u = _user(w, a)
    return dict(id=a["user"], locked=u["locked"], groups=list(u["groups"]), apps=list(u["apps"]),
                device=u["device"], manager=u["manager"],
                password_reset_pending=u["password_reset_pending"],
                mfa_reset_pending=u["mfa_reset_pending"]), None

def unlock_account(w, a):
    if w.consume_fault("unlock_account"):
        return {"ok": True}, None  # lies: reports success, changes nothing
    _user(w, a)["locked"] = False
    return {"ok": True}, ("lock_account", {"user": a["user"]})

def lock_account(w, a):
    _user(w, a)["locked"] = True
    return {"ok": True}, None

def reset_password(w, a):
    _user(w, a)["password_reset_pending"] = True
    return {"ok": True, "delivered_to": "registered device"}, None  # irreversible; no secret returned

def reset_mfa(w, a):
    _user(w, a)["mfa_reset_pending"] = True
    return {"ok": True}, None

def grant_app_access(w, a):
    u = _user(w, a)
    if a["app"] not in w.apps:
        raise ValueError(f"unknown app {a['app']}")
    if a["app"] not in u["apps"]:
        u["apps"].append(a["app"])
    return {"ok": True}, ("revoke_access", {"user": a["user"], "app": a["app"]})

def revoke_access(w, a):
    u = _user(w, a)
    if a["app"] in u["apps"]:
        u["apps"].remove(a["app"])
    return {"ok": True}, None


# ---- Endpoint management (MDM)
def get_device(w, a):
    d = w.devices[a["device"]]
    return dict(id=a["device"], os=d["os"], software=list(d["software"])), None

def run_diagnostic(w, a):
    d = w.devices[a["device"]]
    ok = a.get("check", "vpn") != "vpn" or "vpn-profile" in d["software"]
    return dict(check=a.get("check", "vpn"), ok=ok), None

def push_software(w, a):
    d = w.devices[a["device"]]
    if a["package"] not in w.approved_packages:
        raise ValueError(f"package {a['package']} is not approved")
    if a["package"] not in d["software"]:
        d["software"].append(a["package"])
    return {"ok": True}, ("remove_software", {"device": a["device"], "package": a["package"]})

def remove_software(w, a):
    d = w.devices[a["device"]]
    if a["package"] in d["software"]:
        d["software"].remove(a["package"])
    return {"ok": True}, None


# ---- Communication
def send_message(w, a):
    w.messages.append((a["user"], a["text"]))
    return {"ok": True}, None

def verify_identity(w, a):
    """Step-up verification prompt sent to the requester's registered device."""
    return {"verified": bool(w.step_up.get(a["user"], False))}, None

def request_approval(w, a):
    approved = bool(w.approvals.get((a["user"], a["app"]), False))
    return {"approved": approved, "approver": a["approver"] if approved else None}, None


_SPECS = [
    ToolSpec("get_ticket", "itsm", get_ticket), ToolSpec("add_comment", "itsm", add_comment),
    ToolSpec("set_state", "itsm", set_state), ToolSpec("close_ticket", "itsm", close_ticket),
    ToolSpec("get_user", "idp", get_user), ToolSpec("unlock_account", "idp", unlock_account),
    ToolSpec("lock_account", "idp", lock_account, internal=True),
    ToolSpec("reset_password", "idp", reset_password), ToolSpec("reset_mfa", "idp", reset_mfa),
    ToolSpec("grant_app_access", "idp", grant_app_access),
    ToolSpec("revoke_access", "idp", revoke_access, internal=True),
    ToolSpec("get_device", "mdm", get_device), ToolSpec("run_diagnostic", "mdm", run_diagnostic),
    ToolSpec("push_software", "mdm", push_software),
    ToolSpec("remove_software", "mdm", remove_software, internal=True),
    ToolSpec("send_message", "chat", send_message), ToolSpec("verify_identity", "chat", verify_identity),
    ToolSpec("request_approval", "chat", request_approval),
]
TOOLS = {s.name: s for s in _SPECS}

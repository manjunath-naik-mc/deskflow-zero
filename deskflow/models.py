"""Shared data types (design doc sections 5, 6 and 9)."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Risk(str, Enum):
    READ_ONLY = "read-only"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    PROHIBITED = "prohibited"


class Decision(str, Enum):
    ACT = "act"
    ACT_THEN_ASK = "act_then_ask"
    ACT_AFTER_IDENTITY = "act_after_identity_check"
    NEED_APPROVAL = "act_only_with_named_approval"
    ASK = "ask"
    ESCALATE = "escalate"
    DENY = "never_autonomous"


@dataclass
class Attachment:
    """A multimodal input. `text` is what the vision/speech model extracted
    (OCR text, error code, transcript). The prototype takes it as given."""
    kind: str  # screenshot | voice | document
    name: str
    text: str


@dataclass
class Ticket:
    requester: str
    text: str
    channel: str = "chat"
    source: str = "reactive"  # reactive | proactive | scheduled | peer-initiated
    attachments: list[Attachment] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    id: str = ""


@dataclass
class Evidence:
    doc_id: str
    kind: str  # kb | incident
    title: str
    resolution_code: str
    score: float
    snippet: str


@dataclass
class PolicyDecision:
    tool: str
    tier: Risk
    decision: Decision
    reason: str
    policy_version: str


@dataclass
class Authorization:
    """Signed by the policy engine; the tool gateway refuses writes without one."""
    tool: str
    ticket_id: str
    tier: Risk
    policy_version: str
    nonce: str
    sig: str
    approver: str | None = None


@dataclass
class TicketResult:
    ticket_id: str
    outcome: str  # closed | escalated | waiting_user
    category: str
    confidence: float
    reason: str
    explanation: str = ""
    decision: str = ""
    steps: list[str] = field(default_factory=list)
    citations: list[str] = field(default_factory=list)
    writes: list[tuple[str, str]] = field(default_factory=list)  # (tool, system)
    escalation: dict[str, Any] | None = None
    question: str | None = None
    elapsed_ms: float = 0.0

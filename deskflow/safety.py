"""Input screening and privacy masking (design doc section 9).

The injection screen is a heuristic stand-in for a service such as Model Armor.
Ticket text and anything extracted from attachments are data, never instructions.
"""
from __future__ import annotations

import re

INJECTION_PATTERNS = [
    r"ignore (all |any |the )?(previous|prior|above) (instructions|rules)",
    r"disregard (the |your )?(policy|policies|rules|instructions)",
    r"you are now",
    r"system prompt",
    r"(disable|bypass|skip|override) (the )?(policy|policy engine|approval|identity check|verification)",
    r"grant (me |yourself )?(admin|root|privileged)",
    r"act as (an? )?(admin|administrator|root)",
    r"reveal (the |your )?(secret|password|token|credentials)",
]
_INJECTION = [re.compile(p, re.I) for p in INJECTION_PATTERNS]
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_PHONE = re.compile(r"(?<!\w)\+?\d[\d\s().-]{8,}\d(?!\w)")


def screen_text(text: str) -> list[str]:
    """Return the patterns matched; empty list means clean."""
    return [p.pattern for p in _INJECTION if p.search(text or "")]


def mask_pii(text: str) -> str:
    return _PHONE.sub("[phone]", _EMAIL.sub("[email]", text))

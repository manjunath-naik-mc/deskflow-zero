"""Append-only, hash-chained audit log (tamper-evident; design doc sections 2 and 9)."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from .safety import mask_pii

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: str | None = None, clock=time.time):
        self._entries: list[dict] = []
        self._path = Path(path) if path else None
        self._clock = clock

    def append(self, ticket_id: str, actor: str, event: str, data: dict | None = None) -> dict:
        prev = self._entries[-1]["hash"] if self._entries else GENESIS
        body = {
            "seq": len(self._entries),
            "ts": round(self._clock(), 3),
            "ticket": ticket_id,
            "actor": actor,
            "event": event,
            "data": json.loads(mask_pii(json.dumps(data or {}, default=str))),
            "prev": prev,
        }
        body["hash"] = self._digest(body)
        self._entries.append(body)
        if self._path:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(body) + "\n")
        return body

    @staticmethod
    def _digest(body: dict) -> str:
        payload = {k: v for k, v in body.items() if k != "hash"}
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

    def verify(self) -> bool:
        prev = GENESIS
        for e in self._entries:
            if e["prev"] != prev or e["hash"] != self._digest(e):
                return False
            prev = e["hash"]
        return True

    def entries(self, ticket_id: str | None = None) -> list[dict]:
        return [e for e in self._entries if ticket_id in (None, e["ticket"])]

    def __len__(self) -> int:
        return len(self._entries)

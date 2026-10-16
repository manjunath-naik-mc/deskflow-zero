"""Multimodal RAG over knowledge and past incidents (design doc section 7).

Implements the retrieval techniques from the doc with stdlib only:
query understanding (error-code extraction), hybrid search (char-trigram vector +
keyword, fused with reciprocal rank fusion), small-to-big chunking, and graph-aware
rerank. Images and audio arrive as text already extracted by a vision/speech model;
swap `embed` for a real multimodal embedding to go further.
"""
from __future__ import annotations

import math
import zlib
import re
from collections import Counter, defaultdict

from .memory import GraphMemory
from .models import Evidence

STOP = {"the", "a", "an", "to", "of", "and", "or", "is", "in", "on", "for", "my", "i", "me", "it", "with",
        "this", "that", "be", "are", "was", "have", "has", "can", "t", "s", "after", "then", "when", "needs"}
ERROR_CODE = re.compile(r"\b(?:error|code|err)\s*[:#]?\s*(0x[0-9a-f]+|\d{3,5})\b", re.I)


def tokens(text: str) -> list[str]:
    return [t for t in re.findall(r"[a-z0-9]+", text.lower()) if t not in STOP]


def embed(text: str, dim: int = 512) -> dict[int, float]:
    """Hashed character-trigram vector: a stand-in for a multimodal embedding model."""
    t = f"  {' '.join(tokens(text))}  "
    vec: Counter = Counter(zlib.crc32(t[i:i + 3].encode()) % dim for i in range(len(t) - 2))
    norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
    return {k: v / norm for k, v in vec.items()}


def cosine(a: dict[int, float], b: dict[int, float]) -> float:
    return sum(v * b.get(k, 0.0) for k, v in a.items())


def extract_error_codes(text: str) -> list[str]:
    return [m.lower() for m in ERROR_CODE.findall(text or "")]


class KnowledgeIndex:
    def __init__(self, kb: list[dict], incidents: list[dict], memory: GraphMemory):
        self.memory = memory
        self.docs: dict[str, dict] = {}
        self.chunks: list[tuple[str, str]] = []  # (parent doc id, small chunk)
        for d in kb:
            self._add(d, "kb")
        for d in incidents:
            self._add(d, "incident")
        self.vecs = [embed(c) for _, c in self.chunks]
        self.toks = [set(tokens(c)) for _, c in self.chunks]
        df: Counter = Counter(t for ts in self.toks for t in ts)
        n = len(self.chunks)
        self.idf = {t: math.log(1 + n / c) for t, c in df.items()}

    def _add(self, d: dict, kind: str) -> None:
        self.docs[d["id"]] = {**d, "kind": kind}
        # Small-to-big: index sentence-sized chunks (with the title for context),
        # but always return the parent document.
        for sent in re.split(r"(?<=[.!?])\s+", d["text"]):
            if sent.strip():
                self.chunks.append((d["id"], f"{d['title']}. {sent}"))

    def _rank_chunks(self, query: str) -> tuple[list[int], list[int]]:
        qv, qt = embed(query), set(tokens(query))
        vec = sorted(range(len(self.chunks)), key=lambda i: -cosine(qv, self.vecs[i]))
        kw = sorted(range(len(self.chunks)), key=lambda i: -sum(self.idf.get(t, 0) for t in qt & self.toks[i]))
        return vec, kw

    def coverage(self, query: str, doc_id: str) -> float:
        """Share of the query's term weight found in the doc: a thin-evidence signal."""
        qt = set(tokens(query))
        total = sum(self.idf.get(t, 1.0) for t in qt) or 1.0
        dt = set().union(*(self.toks[i] for i, (d, _) in enumerate(self.chunks) if d == doc_id))
        return sum(self.idf.get(t, 1.0) for t in qt & dt) / total

    def search(self, queries: list[str], k: int = 60, top_n: int = 8) -> list[tuple[str, float]]:
        """Hybrid search over several query rewrites; returns (parent doc id, fused score)."""
        fused: dict[str, float] = defaultdict(float)
        for q in queries:
            for ranking in self._rank_chunks(q):
                seen: set[str] = set()
                for rank, ci in enumerate(ranking[:20]):
                    doc = self.chunks[ci][0]
                    if doc not in seen:  # best chunk per parent only
                        seen.add(doc)
                        fused[doc] += 1.0 / (k + rank)
        ranked = sorted(fused.items(), key=lambda kv: -kv[1])[:top_n]
        top = ranked[0][1] if ranked else 1.0
        return [(d, s / top) for d, s in ranked]


def rewrite_queries(text: str, attachment_texts: list[str], category_hint: str | None = None) -> list[str]:
    """Query understanding: read error codes from images first, then widen the query."""
    full = " ".join([text, *attachment_texts])
    queries = [full]
    for code in extract_error_codes(full):
        queries.append(f"error {code}")
    if category_hint:
        queries.append(category_hint.replace("_", " "))
    return queries


def retrieve(index: KnowledgeIndex, queries: list[str], allowed_codes: set[str], device_os: str | None,
             min_coverage: float = 0.2) -> list[Evidence]:
    """Graph-aware rerank with filters; returns cited evidence, best first."""
    out: list[Evidence] = []
    base = queries[0]
    for doc_id, score in index.search(queries):
        d = index.docs[doc_id]
        if d["resolution_code"] not in allowed_codes or d.get("superseded"):
            continue  # demote superseded runbooks and off-category fixes
        if d["kind"] == "incident":
            if d.get("outcome") != "confirmed" or not index.memory.fix_succeeded(doc_id):
                continue  # prefer precedent with a confirmed good outcome
            score += 0.25
            if device_os and d.get("device_os") == device_os:
                score += 0.15
        if index.coverage(base, doc_id) < min_coverage:
            continue
        out.append(Evidence(doc_id, d["kind"], d["title"], d["resolution_code"], round(score, 3), d["text"][:140]))
    return sorted(out, key=lambda e: -e.score)

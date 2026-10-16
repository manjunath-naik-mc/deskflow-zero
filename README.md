# DeskFlow Zero (prototype)

A runnable prototype of the **DeskFlow Zero Design Document v2**: a governed team of agents that
resolves IT service-desk tickets end to end, and escalates only when risk or ambiguity demands it.

It uses only the Python standard library (3.10+), runs offline and is deterministic, so the whole
loop can be demonstrated, tested and evaluated without any cloud account.

```bash
python -m deskflow demo     # the demo script: happy, screenshot, approval, A2A, escalation, safety, control room
python -m deskflow eval     # golden set + adversarial set (zero unsafe actions required)
python -m deskflow ticket --user alice --text "I forgot my password"
python -m deskflow ticket --user dave --text "I can't connect to VPN" \
       --screenshot-text "Error 619: A connection to the remote computer could not be established"
python -m deskflow serve    # JSON API: POST /tickets, GET /metrics
pip install -e ".[dev]" && pytest
```

## What is implemented, mapped to the design

| Design section | Module | What it does |
|---|---|---|
| 4 MVC, policy gate on every write | `gateway.py`, `policy.py` | Writes need an HMAC-signed authorization from the policy engine; the View (CLI/API) never touches systems of record |
| 5 Orchestrator and specialists | `agents.py`, `workflow.py` | Orchestrator (classify, plan; no write tools), identity, device, knowledge, communicator, verifier, escalation agents, each with a least-privilege tool allow-list |
| 5 A2A | `a2a.py` | Agent card, registry, allow-listed tasks and fields, short-lived scoped token, bounded retries, task-state mapping, mock HR onboarding peer; peer results re-checked by the verifier |
| 6 Workflow and durability | `workflow.py`, `gateway.py` | Act / ask / escalate branches, independent verification, rollback on failure, idempotency keys |
| 7 Multimodal RAG | `rag.py` | Query understanding (error codes from screenshots), hybrid search (trigram vectors + keyword, rank fusion), small-to-big chunking, graph-aware rerank, grounded citations, agentic re-query |
| 7 Contextual graph memory | `memory.py` | SQLite edge tables: 8 node types, 7 edge types, decision traces, precedent with confirmed outcomes only |
| 8 Tool gateway and connectors | `connectors.py`, `gateway.py` | Typed tools with risk tiers (ITSM, identity, MDM, chat), per-agent scopes, undo steps |
| 9 Trust and safety | `policy.py`, `safety.py`, `audit.py` | Risk-tier x confidence matrix, step-up identity check, named approval, prompt-injection screen on text and attachment text, PII masking, per-user write cap, global kill switch, tamper-evident hash-chained audit log |
| 10 Evaluation | `scenarios.py`, `cli.py eval` | Layer 1 golden replay and layer 2 adversarial set, run in CI as gates |
| 11 MVP scope | `scenarios.py` | Unlock, password and MFA reset, access request with manager approval, VPN and software issues incl. screenshots, onboarding via A2A |

## What is simulated (be aware before relying on results)

- **No LLM.** Classification and planning are rule-based, so results are reproducible. Replace
  `Orchestrator.classify` and the specialist bodies with ADK / Gemini agents; the gateway, policy engine,
  verifier and audit log do not change.
- **Vision and speech are stubbed.** A screenshot or voice note arrives with its extracted text
  (`Attachment.text`). Plug a Gemini vision / speech call in front of `Ticket` creation.
- **Embeddings are hashed character trigrams**, not a multimodal embedding model. `rag.embed` is the seam.
- **Systems of record are in memory** (`world.py`, `connectors.py`). Each connector has the shape of an MCP
  tool (name, typed args, structured result, undo step) so real MCP servers can replace them.
- **A2A transport is in-process** with the same message shapes (JSON-RPC envelope, agent card, token).
- **Autonomy triggers:** reactive tickets and peer-initiated onboarding are implemented; monitoring-driven and
  scheduled sweeps are not yet.
- The 60% / 95% / under-5-minute targets in the design are hypotheses; this prototype's metrics come from a
  small seeded set and prove the mechanics, not production accuracy.

## Safety properties that are tested

- An agent cannot write without a policy authorization bound to that tool and ticket (`tests/test_core.py`).
- Prohibited and unknown tools are never executed; low confidence escalates instead of acting.
- Identity failure, denied approval, prompt injection (in text or in a screenshot) and unknown requesters all
  end in escalation with zero identity or device writes.
- The verifier re-reads live state: an actor that reports success without changing anything is caught and the
  ticket escalates, and that trace is never used as precedent.
- The kill switch drops agents to read-only; the audit chain detects tampering.

## Layout

```
deskflow/        engine (policy, gateway, agents, workflow, rag, memory, a2a, safety, audit, cli)
deskflow/data/   policy.json, kb.json, incidents.json (seed knowledge and past incidents)
tests/           unit and workflow tests
.github/workflows/ci.yml   tests + evaluation gates on every push
```

## Next steps toward the roadmap

1. Swap in ADK agents with Gemini for classification and planning; keep the policy engine outside the model.
2. Add a vision/speech extraction step and a real multimodal embedding index (Vertex AI Search or Vector Search).
3. Wrap ServiceNow/Jira, Entra/Okta and Intune/Jamf as MCP servers behind `ToolGateway`.
4. Move working state to a durable workflow store (checkpoints, approval waits of hours).
5. Add proactive monitoring and scheduled-sweep triggers; shadow-mode evaluation (layer 3).

"""Command line: `deskflow demo | eval | ticket | serve`."""
from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

from .models import Attachment, Ticket
from .scenarios import ADVERSARIAL, DEMO, GOLDEN, evaluate
from .workflow import DeskFlow
from .world import World


def _print_result(r) -> None:
    print(f"  outcome : {r.outcome.upper()}  (category={r.category}, confidence={r.confidence})")
    for s in r.steps:
        print(f"    - {s}")
    if r.explanation:
        print(f"  to user : {r.explanation}")
    if r.question:
        print(f"  asks    : {r.question}")
    if r.escalation:
        print(f"  handoff : {r.escalation['reason']} | proposed={r.escalation['proposed_action']}")


def cmd_demo(_args) -> int:
    df = DeskFlow(World())
    for case in DEMO:
        print(f"\n== {case.id}: {case.ticket.text[:70]}")
        df.world.step_up.update(case.step_up)
        df.world.approvals.update(case.approvals)
        _print_result(df.run(case.ticket))
    print("\n== 7 control room")
    for k, v in df.metrics().items():
        print(f"  {k}: {v}")
    last = next(r for r in df.results if r.category == "vpn_issue")
    print(f"  decision trace for {last.ticket_id}:")
    for line in df.memory.trace_summary(last.ticket_id):
        print(f"    {line}")
    return 0


def cmd_eval(_args) -> int:
    ok = True
    for title, cases in (("Layer 1: golden set", GOLDEN), ("Layer 2: adversarial set", ADVERSARIAL)):
        rows = evaluate(cases)
        passed = sum(r["ok"] for r in rows)
        print(f"\n{title}: {passed}/{len(rows)} passed")
        for r in rows:
            print(f"  [{'PASS' if r['ok'] else 'FAIL'}] {r['id']:<22} {r['outcome']:<13} {r['category']:<18}"
                  f" sensitive writes={r['sensitive_writes']}")
        ok &= passed == len(rows)
        if cases is ADVERSARIAL:
            unsafe = sum(r["sensitive_writes"] for r in rows)
            print(f"  unsafe actions: {unsafe} (pass bar: 0)")
            ok &= unsafe == 0
    return 0 if ok else 1


def cmd_ticket(args) -> int:
    df = DeskFlow(World())
    df.world.step_up[args.user] = not args.fail_identity
    for app in df.world.apps:
        df.world.approvals[(args.user, app)] = args.approve
    atts = [Attachment("screenshot", "attachment", a) for a in args.screenshot_text]
    r = df.run(Ticket(args.user, args.text, attachments=atts))
    _print_result(r)
    return 0


def cmd_serve(args) -> int:
    df = DeskFlow(World())
    for u in df.world.users:
        df.world.step_up[u] = True

    class H(BaseHTTPRequestHandler):
        def _send(self, code, body):
            data = json.dumps(body, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/metrics":
                return self._send(200, df.metrics())
            self._send(404, {"error": "not found"})

        def do_POST(self):
            if self.path != "/tickets":
                return self._send(404, {"error": "not found"})
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
                t = Ticket(body["requester"], body["text"],
                           attachments=[Attachment(a.get("kind", "screenshot"), a.get("name", "file"), a["text"])
                                        for a in body.get("attachments", [])])
            except (KeyError, ValueError):
                return self._send(400, {"error": "need JSON with requester and text"})
            self._send(200, df.run(t).__dict__)

        def log_message(self, *a):
            pass

    print(f"DeskFlow Zero listening on http://127.0.0.1:{args.port}  (POST /tickets, GET /metrics)")
    HTTPServer(("127.0.0.1", args.port), H).serve_forever()
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="deskflow", description="DeskFlow Zero prototype")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("demo", help="run the five-minute demo script").set_defaults(fn=cmd_demo)
    sub.add_parser("eval", help="run the golden and adversarial sets").set_defaults(fn=cmd_eval)
    t = sub.add_parser("ticket", help="resolve one ticket")
    t.add_argument("--user", required=True)
    t.add_argument("--text", required=True)
    t.add_argument("--screenshot-text", action="append", default=[], help="text extracted from a screenshot")
    t.add_argument("--fail-identity", action="store_true")
    t.add_argument("--approve", action="store_true", help="manager approves access requests")
    t.set_defaults(fn=cmd_ticket)
    s = sub.add_parser("serve", help="tiny JSON API")
    s.add_argument("--port", type=int, default=8080)
    s.set_defaults(fn=cmd_serve)
    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())

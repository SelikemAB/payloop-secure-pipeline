#!/usr/bin/env python3
"""Deterministically generate synthetic log scenarios for the detection suite (fictional data only)."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).parent / "samples"
OUT.mkdir(exist_ok=True)
T0 = datetime(2026, 10, 30, 10, 0, 0, tzinfo=timezone.utc)


def ev(t, event, srcip="203.0.113.50", user=None, **kw):
    d = {"ts": (T0 + timedelta(seconds=t)).strftime("%Y-%m-%dT%H:%M:%SZ"), "app": "payloop", "event": event,
         "srcip": srcip, "rid": f"r{t:05d}"}
    if user:
        d["user"] = user
    d.update(kw)
    return json.dumps(d)


def req(t, path, query="", status=200, **kw):
    return ev(t, "request", method="GET", path=path, query=query, status=status, **kw)


def write(name, lines):
    (OUT / f"{name}.jsonl").write_text("\n".join(lines) + "\n")


write("brute-force", [ev(i * 3, "login_failed", username="dave", reason="bad_password") for i in range(10)])
write("spray-distinct-users", [ev(i * 4, "login_failed", username=f"user{i}", reason="unknown_user") for i in range(10)])
write("success-after-failures", [ev(i * 5, "login_failed", srcip="198.51.100.7", username="carol") for i in range(6)]
      + [ev(40, "login_success", srcip="198.51.100.7", username="carol", user="carol")])
write("throttled", [ev(i * 10, "login_rate_limited", username="dave") for i in range(4)])
write("sqli-request", [req(1, "/statement", "wallet=1&q=zzz%' UNION SELECT id,1,1,1,username||':'||pass_hash,'x' FROM users--", user="alice")])
write("traversal-request", [req(1, "/receipt", "file=../internal/notes.txt", user="alice")])
write("ssrf-internal", [ev(1, "webhook_fetch", user="alice", target_host="127.0.0.1")])
write("ssrf-metadata", [ev(1, "webhook_fetch", user="alice", target_host="169.254.169.254")])
write("ssrf-blocked", [ev(1, "ssrf_blocked", user="alice", target_host="10.0.0.5", reason="host_not_allowlisted")])
write("idor-enumeration", [ev(i * 2, "wallet_view", user="alice", wallet_id=i + 2) for i in range(6)])
write("same-wallet-repeat", [ev(i * 2, "wallet_view", user="alice", wallet_id=1) for i in range(8)])
write("authz-probing", [ev(i * 5, "authz_denied", user="bob", resource="wallet", wallet_id=i + 1) for i in range(3)])
write("transfer-negative", [ev(1, "transfer", user="alice", from_wallet=1, to_wallet=2, amount=-5000, idem_key="k-0001")])
write("transfer-negative-rejected", [ev(1, "transfer_rejected", user="alice", reason="invalid_amount", amount="-5000")])
write("transfer-duplicate-key", [ev(1, "transfer", user="carol", from_wallet=3, to_wallet=1, amount=1000, idem_key="dup-0001"),
                                 ev(2, "transfer", user="carol", from_wallet=3, to_wallet=1, amount=1000, idem_key="dup-0001")])
write("transfer-distinct-keys", [ev(i, "transfer", user="carol", from_wallet=3, to_wallet=1, amount=1000, idem_key=f"ok-{i:04d}") for i in range(4)])
write("forged-tokens", [ev(i, "auth_token_invalid", reason="bad_signature") for i in range(6)])
write("server-errors", [req(i, "/login", status=500) for i in range(6)])
write("benign-day", [
    ev(0, "login_success", srcip="198.51.100.30", username="alice", user="alice"),
    req(1, "/wallet", "id=1", user="alice"), ev(1, "wallet_view", user="alice", wallet_id=1),
    req(5, "/statement", "wallet=1&q=rent", user="alice"),
    ev(9, "transfer", user="alice", from_wallet=1, to_wallet=2, amount=2500, idem_key="rent-oct-0001"),
    ev(30, "login_failed", srcip="198.51.100.31", username="bob", reason="bad_password"),
    ev(41, "login_success", srcip="198.51.100.31", username="bob", user="bob"),
    req(50, "/receipt", "file=receipt-1001.txt", user="bob"),
    req(60, "/health"),
])

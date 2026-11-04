#!/usr/bin/env python3
"""ruletest: lint and replay-test Wazuh rules offline (detection-as-code).

This is a *simulator* of the Wazuh rule engine subset used by this repository:
  decoded_as json, <field type="pcre2">, if_sid, if_matched_sid, frequency/timeframe,
  same_field, different_field, $(field) interpolation in descriptions, MITRE ids.
It is fast and deterministic, so it suits pre-commit and CI. It is NOT a replacement for
`wazuh-logtest` against a real manager, which remains the final authority (see docs).
Differences worth knowing: timeframes use the event's own "ts" (Wazuh uses receipt time) and
events that fired a child rule still count towards their ancestors' frequency windows.

  ruletest.py lint   RULES.xml
  ruletest.py replay RULES.xml EVENTS.jsonl [--min-level 3]
  ruletest.py suite  SUITE.yml
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import yaml

MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
ID_RANGE = (100000, 120000)


@dataclass
class Rule:
    id: int
    level: int
    frequency: int = 0
    timeframe: int = 0
    decoded_as: str | None = None
    if_sid: list[int] = field(default_factory=list)
    if_matched_sid: int | None = None
    same_field: list[str] = field(default_factory=list)
    different_field: list[str] = field(default_factory=list)
    fields: list[tuple[str, str, str]] = field(default_factory=list)  # (name, type, pattern)
    description: str = ""
    mitre: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)


@dataclass
class Alert:
    ts: str
    rule: Rule
    text: str
    event: dict


def load_rules(path: str | Path) -> dict[int, Rule]:
    root = ET.fromstring("<root>" + Path(path).read_text() + "</root>")
    rules: dict[int, Rule] = {}
    for el in root.iter("rule"):
        r = Rule(id=int(el.get("id")), level=int(el.get("level", "0")),
                 frequency=int(el.get("frequency", "0")), timeframe=int(el.get("timeframe", "0")))
        for c in el:
            t, v = c.tag, (c.text or "").strip()
            if t == "decoded_as":
                r.decoded_as = v
            elif t == "if_sid":
                r.if_sid = [int(x) for x in v.split(",") if x.strip()]
            elif t == "if_matched_sid":
                r.if_matched_sid = int(v)
            elif t == "same_field":
                r.same_field.append(v)
            elif t == "different_field":
                r.different_field.append(v)
            elif t == "field":
                r.fields.append((c.get("name", ""), c.get("type", "osregex"), v))
            elif t == "description":
                r.description = v
            elif t == "mitre":
                r.mitre += [(i.text or "").strip() for i in c.iter("id")]
            elif t == "group":
                r.groups += [g for g in v.split(",") if g]
        if r.id in rules:
            raise ValueError(f"duplicate rule id {r.id}")
        rules[r.id] = r
    return rules


# ---------------------------------------------------------------- lint
def lint(rules: dict[int, Rule]) -> list[str]:
    errs = []
    for r in rules.values():
        p = f"rule {r.id}"
        if not ID_RANGE[0] <= r.id <= ID_RANGE[1]:
            errs.append(f"{p}: id outside custom range {ID_RANGE}")
        if not 0 <= r.level <= 15:
            errs.append(f"{p}: level {r.level} not in 0..15")
        if not r.description:
            errs.append(f"{p}: missing description")
        parents = list(r.if_sid) + ([r.if_matched_sid] if r.if_matched_sid else [])
        for pid in parents:
            if pid not in rules:
                errs.append(f"{p}: parent {pid} does not exist")
            elif pid >= r.id and pid != r.id:
                pass  # ordering is not required by Wazuh, only by readability
        if not parents and r.decoded_as is None:
            errs.append(f"{p}: root rule needs decoded_as or a parent")
        if r.frequency and not (r.timeframe and r.if_matched_sid):
            errs.append(f"{p}: frequency needs timeframe and if_matched_sid")
        if (r.same_field or r.different_field) and not r.frequency:
            errs.append(f"{p}: same_field/different_field only make sense on frequency rules")
        for name, _typ, pat in r.fields:
            try:
                re.compile(pat)
            except re.error as e:
                errs.append(f"{p}: field {name} regex does not compile: {e}")
        for m in r.mitre:
            if not MITRE_RE.match(m):
                errs.append(f"{p}: malformed MITRE id {m!r}")
        for m in re.findall(r"\$\(([^)]+)\)", r.description):
            pass
    return errs


# ---------------------------------------------------------------- engine
class Engine:
    def __init__(self, rules: dict[int, Rule]):
        self.rules = rules
        self.children: dict[int, list[Rule]] = {}
        self.roots: list[Rule] = []
        for r in sorted(rules.values(), key=lambda x: x.id):
            parent_ids = r.if_sid or ([r.if_matched_sid] if r.if_matched_sid else [])
            if not parent_ids:
                self.roots.append(r)
            for pid in parent_ids:
                self.children.setdefault(pid, []).append(r)
        self.history: list[tuple[float, dict, set[int]]] = []

    @staticmethod
    def _ts(ev: dict, idx: int) -> float:
        raw = ev.get("ts")
        if isinstance(raw, str):
            try:
                return datetime.fromisoformat(raw.replace("Z", "+00:00")).timestamp()
            except ValueError:
                pass
        return float(idx)

    def _own(self, r: Rule, ev: dict, now: float, chain: list[int]) -> bool:
        if r.decoded_as and r.decoded_as != "json":
            return False
        for name, _t, pat in r.fields:
            val = ev.get(name)
            if val is None or re.search(pat, str(val)) is None:
                return False
        if r.frequency:
            x = r.if_matched_sid
            prior = [(t, e) for t, e, ch in self.history if x in ch and now - t <= r.timeframe]
            for f in r.same_field:                      # only events sharing the field value count
                if ev.get(f) is None:
                    return False
                prior = [(t, e) for t, e in prior if e.get(f) == ev.get(f)]
            for f in r.different_field:                 # only events with distinct, new values count
                seen, kept = {ev.get(f)}, []
                for t, e in prior:
                    if e.get(f) is not None and e.get(f) not in seen:
                        seen.add(e.get(f))
                        kept.append((t, e))
                prior = kept
            count = len(prior) + (1 if x in chain else 0)
            if count < r.frequency:
                return False
        return True

    def _walk(self, r: Rule, ev: dict, now: float, chain: list[int]) -> list[int] | None:
        if not self._own(r, ev, now, chain):
            return None
        chain = chain + [r.id]
        for child in self.children.get(r.id, []):
            sub = self._walk(child, ev, now, chain)
            if sub:
                return sub
        return chain

    def feed(self, ev: dict, idx: int) -> Alert | None:
        now = self._ts(ev, idx)
        self.history = [h for h in self.history if now - h[0] <= 3600]
        for root in self.roots:
            chain = self._walk(root, ev, now, [])
            if chain:
                self.history.append((now, ev, set(chain)))
                final = self.rules[chain[-1]]
                text = re.sub(r"\$\(([^)]+)\)", lambda m: str(ev.get(m.group(1), "")), final.description)
                return Alert(str(ev.get("ts", idx)), final, text, ev)
        return None


def replay(rules: dict[int, Rule], lines: list[str]) -> list[Alert]:
    eng, out = Engine(rules), []
    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            continue
        a = eng.feed(ev, i)
        if a:
            out.append(a)
    return out


# ---------------------------------------------------------------- suite
def run_suite(path: Path) -> int:
    spec = yaml.safe_load(path.read_text())
    base = path.parent
    rules = load_rules((base / spec["rules"]).resolve())
    errs = lint(rules)
    failures = [f"lint: {e}" for e in errs]
    for case in spec["cases"]:
        lines = (base / case["events"]).read_text().splitlines()
        alerts = replay(rules, lines)
        fired = {a.rule.id for a in alerts}
        top = max((a.rule.level for a in alerts), default=0)
        bad = []
        for rid in case.get("expect", []):
            if rid not in fired:
                bad.append(f"expected rule {rid} did not fire")
        for rid in case.get("expect_absent", []):
            if rid in fired:
                bad.append(f"rule {rid} fired but must not")
        if top < case.get("min_level", 0):
            bad.append(f"highest level {top} < required {case['min_level']}")
        if "max_level" in case and top > case["max_level"]:
            bad.append(f"highest level {top} > allowed {case['max_level']} (false positive?)")
        status = "PASS" if not bad else "FAIL"
        print(f"[{status}] {case['name']}  (fired: {sorted(fired)}, max level {top})")
        failures += [f"{case['name']}: {b}" for b in bad]
    for f in failures:
        print("  -", f)
    print(f"\n{len(spec['cases'])} cases, {len(failures)} problem(s)")
    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("lint").add_argument("rules")
    rp = sub.add_parser("replay")
    rp.add_argument("rules")
    rp.add_argument("events")
    rp.add_argument("--min-level", type=int, default=3)
    sub.add_parser("suite").add_argument("suite")
    a = ap.parse_args()

    if a.cmd == "lint":
        rules = load_rules(a.rules)
        errs = lint(rules)
        print(f"{len(rules)} rules, {len(errs)} problem(s)")
        for e in errs:
            print(" -", e)
        return 1 if errs else 0
    if a.cmd == "replay":
        rules = load_rules(a.rules)
        alerts = replay(rules, Path(a.events).read_text().splitlines())
        for al in alerts:
            if al.rule.level >= a.min_level:
                print(f"{al.ts}  L{al.rule.level:<2} {al.rule.id}  {al.text}  {','.join(al.rule.mitre)}")
        return 0
    return run_suite(Path(a.suite))


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Security gate: read scanner reports, apply one policy, decide pass/fail.

  gate.py --policy policy/gate-policy.yml --reports reports/ [--today 2026-10-30] [--json out.json]

Design rules (see docs/pipeline-design.md):
  * Fail closed: a required report that is missing or unparseable fails the build (exit 2). A scanner that silently did not run
    must never look like a clean result.
  * One place decides severity and blocking, so scanners stay swappable.
  * Waivers must have an owner, a reason and an expiry no more than max_exception_days away. An expired waiver FAILS the build
    until someone renews or fixes it, so exceptions cannot rot.

Exit codes: 0 pass, 1 blocking findings or invalid/expired waivers, 2 missing or unreadable required reports.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path

import yaml

SEVERITIES = ["critical", "high", "medium", "low", "info"]


@dataclass
class Finding:
    tool: str
    rule: str
    severity: str
    title: str
    location: str
    waived_by: str | None = None


@dataclass
class Outcome:
    findings: list[Finding] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)


_ALIASES = {"error": "high", "warning": "medium", "moderate": "medium", "unknown": "low", "negligible": "info"}


def norm(sev: str | None, default: str = "medium") -> str:
    s = _ALIASES.get((sev or "").strip().lower(), (sev or "").strip().lower())
    return s if s in SEVERITIES else default


# ------------------------------------------------------------------ parsers (one per scanner format)
def parse_semgrep(data: dict, key: str) -> list[Finding]:
    out = []
    for r in data.get("results", []):
        meta = r.get("extra", {}).get("metadata", {}) or {}
        sev = norm(meta.get("severity") or r.get("extra", {}).get("severity"))
        out.append(Finding(key, r["check_id"], sev, r.get("extra", {}).get("message", "").split(". ")[0][:120],
                           f"{r['path']}:{r.get('start', {}).get('line', '?')}"))
    return out


def parse_gitleaks(data: list, key: str) -> list[Finding]:
    return [Finding(key, f.get("RuleID", "secret"), "critical", f.get("Description", "Secret detected"),
                    f"{f.get('File', '?')}:{f.get('StartLine', '?')}") for f in (data or [])]


def parse_trivy(data: dict, key: str) -> list[Finding]:
    out = []
    for res in data.get("Results") or []:
        tgt = res.get("Target", "?")
        for v in res.get("Vulnerabilities") or []:
            out.append(Finding(key, v["VulnerabilityID"], norm(v.get("Severity")), f"{v.get('PkgName')} {v.get('InstalledVersion')}: {v.get('Title', '')}"[:120], tgt))
        for m in res.get("Misconfigurations") or []:
            out.append(Finding(key, m.get("ID", "misconfig"), norm(m.get("Severity")), m.get("Title", ""), tgt))
        for s in res.get("Secrets") or []:
            out.append(Finding(key, s.get("RuleID", "secret"), "critical", s.get("Title", "Secret"), tgt))
    return out


def parse_checkov(data, key: str) -> list[Finding]:
    blocks = data if isinstance(data, list) else [data]
    out = []
    for b in blocks:
        for c in (b.get("results") or {}).get("failed_checks", []):
            out.append(Finding(key, c["check_id"], norm(c.get("severity"), "medium"), c.get("check_name", ""), c.get("file_path", "?").lstrip("/")))
    return out


PARSERS = {"semgrep": parse_semgrep, "gitleaks": parse_gitleaks, "trivy": parse_trivy, "checkov": parse_checkov}


def load_reports(reports: Path, policy: dict, out: Outcome) -> None:
    required = policy.get("required_reports", [])
    keys = set(required) | {p.stem for p in reports.glob("*.json")}
    for key in sorted(keys):
        path = reports / f"{key}.json"
        parser = next((fn for prefix, fn in PARSERS.items() if key.startswith(prefix)), None)
        if parser is None:
            out.problems.append(f"no parser for report '{key}'")
            continue
        if not path.exists():
            if key in required:
                out.missing.append(f"{key}: report missing (scanner did not run?)")
            continue
        try:
            data = json.loads(path.read_text() or "null")
            if data is None:
                data = [] if parser is parse_gitleaks else {}
            out.findings += parser(data, key)
        except Exception as e:  # unreadable or unexpected format counts as missing for required reports
            (out.missing if key in required else out.problems).append(f"{key}: cannot parse ({type(e).__name__}: {e})")


# ------------------------------------------------------------------ policy
def apply_overrides(findings: list[Finding], policy: dict) -> None:
    """Policy can pin the severity of a specific rule id (exact, or the trailing part of a dotted semgrep id)."""
    overrides = policy.get("severity_overrides", {}) or {}
    for f in findings:
        for rule_id, sev in overrides.items():
            if f.rule == rule_id or f.rule.endswith("." + rule_id):
                f.severity = sev
                break


def validate_waivers(policy: dict, today: date, out: Outcome) -> list[dict]:
    good = []
    limit = timedelta(days=int(policy.get("max_exception_days", 90)))
    for i, w in enumerate(policy.get("exceptions") or []):
        label = f"waiver #{i + 1} ({w.get('id', '?')})"
        missing = [k for k in ("id", "reason", "owner", "expires") if not w.get(k)]
        if missing:
            out.problems.append(f"{label}: missing {', '.join(missing)}")
            continue
        exp = w["expires"] if isinstance(w["expires"], date) else date.fromisoformat(str(w["expires"]))
        if exp < today:
            out.problems.append(f"{label}: EXPIRED on {exp} (owner {w['owner']}); fix the finding or renew with a new date and reason")
            continue
        if exp - today > limit:
            out.problems.append(f"{label}: expiry {exp} is more than {limit.days} days away")
            continue
        good.append(w)
    return good


def waived(f: Finding, waivers: list[dict]) -> str | None:
    for w in waivers:
        if w["id"] != f.rule and not f.rule.endswith(w["id"]):
            continue
        if w.get("tool") and not f.tool.startswith(w["tool"]):
            continue
        if w.get("paths") and not any(fnmatch.fnmatch(f.location.split(":")[0], p) for p in w["paths"]):
            continue
        return f"{w['owner']} until {w['expires']}: {w['reason']}"
    return None


def evaluate(policy: dict, reports: Path, today: date) -> tuple[Outcome, list[Finding], list[Finding]]:
    out = Outcome()
    load_reports(reports, policy, out)
    apply_overrides(out.findings, policy)
    waivers = validate_waivers(policy, today, out)
    for f in out.findings:
        f.waived_by = waived(f, waivers)
    block = set(policy.get("block_on", ["critical", "high"]))
    blockers = [f for f in out.findings if f.severity in block and not f.waived_by]
    warns = [f for f in out.findings if f.severity in set(policy.get("warn_on", ["medium"])) and not f.waived_by]
    return out, blockers, warns


# ------------------------------------------------------------------ output
def render(out: Outcome, blockers: list[Finding], warns: list[Finding], policy: dict) -> str:
    order = {s: i for i, s in enumerate(SEVERITIES)}
    lines = ["## Security gate", ""]
    counts = {s: sum(1 for f in out.findings if f.severity == s and not f.waived_by) for s in SEVERITIES}
    lines.append("Open findings: " + ", ".join(f"{s} {n}" for s, n in counts.items() if n) if any(counts.values()) else "Open findings: none")
    lines.append(f"Waived: {sum(1 for f in out.findings if f.waived_by)}  |  Blocking severities: {', '.join(policy.get('block_on', []))}")
    for title, items in (("BLOCKING", blockers), ("Warnings (do not block)", warns)):
        if items:
            lines += ["", f"### {title}", "", "| Severity | Tool | Rule | Where | What |", "|---|---|---|---|---|"]
            for f in sorted(items, key=lambda f: (order[f.severity], f.tool, f.rule)):
                lines.append(f"| {f.severity} | {f.tool} | `{f.rule}` | {f.location} | {f.title} |")
    waived_items = [f for f in out.findings if f.waived_by]
    if waived_items:
        lines += ["", "### Waived", ""] + [f"- `{f.rule}` at {f.location}: {f.waived_by}" for f in waived_items]
    if out.problems or out.missing:
        lines += ["", "### Policy problems", ""] + [f"- {p}" for p in out.missing + out.problems]
    verdict = "FAIL (scanner output missing)" if out.missing else "FAIL" if (blockers or out.problems) else "PASS"
    if policy.get("_skipped"):
        verdict += f" [INCOMPLETE: skipped {', '.join(policy['_skipped'])}; not equivalent to a CI run]"
    lines += ["", f"**Verdict: {verdict}**"]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--policy", required=True, type=Path)
    ap.add_argument("--reports", required=True, type=Path)
    ap.add_argument("--today", help="override today's date (YYYY-MM-DD), for tests")
    ap.add_argument("--json", type=Path)
    ap.add_argument("--skip", default="", help="comma list of required reports to skip (LOCAL USE ONLY; verdict is marked incomplete)")
    a = ap.parse_args()
    policy = yaml.safe_load(a.policy.read_text()) or {}
    skipped = [k for k in a.skip.split(",") if k]
    policy["required_reports"] = [k for k in policy.get("required_reports", []) if k not in skipped]
    policy["_skipped"] = skipped
    today = date.fromisoformat(a.today) if a.today else date.today()
    out, blockers, warns = evaluate(policy, a.reports, today)
    text = render(out, blockers, warns, policy)
    print(text)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        Path(summary).write_text(text + "\n")
    if a.json:
        a.json.write_text(json.dumps({"blocking": [f.__dict__ for f in blockers], "warnings": [f.__dict__ for f in warns],
                                      "problems": out.problems, "missing": out.missing}, indent=2))
    if out.missing:
        return 2
    return 1 if (blockers or out.problems) else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Mutation check for the detection suite: break the rules in known ways and confirm the suite goes RED each time.

A test suite that cannot fail proves nothing. Each mutant below models a realistic mistake (threshold edited, regex loosened,
rule moved under the wrong parent, rule silenced). The unmutated rules must pass; every mutant must be killed (suite fails).

  python3 tools/mutation_check.py tests/detections.yml
Exit 0 if the baseline passes and all mutants are killed, 1 otherwise.
"""
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent


def mutate_150(s):
    i = s.index('<rule id="110150"')
    j = s.index("</rule>", i)
    blk = s[i:j].replace("<if_sid>110106</if_sid>", '<if_sid>110100</if_sid>\n    <field name="event" type="pcre2">^transfer$</field>')
    return s[:i] + blk + s[j:]


MUTANTS = [
    ("raise brute-force threshold 8 -> 80", lambda s: s.replace('frequency="8" timeframe="60"', 'frequency="80" timeframe="60"')),
    ("loosen SQLi regex so it matches everything", lambda s: s.replace(r"(?i)(\bunion", r"(?i)(.|\bunion", 1)),
    ("move 110150 to a sibling position (first-match-wins bug)", mutate_150),
    ("silence the SSRF-blocked rule", lambda s: s.replace("^ssrf_blocked$", "^ssrf_blocked_disabled$")),
    ("drop the duplicate-idempotency-key condition", lambda s: s.replace("<same_field>idem_key</same_field>", "<same_field>nonexistent_field</same_field>")),
    ("lower token-forgery escalation threshold to never", lambda s: re.sub(r'(id="110161" level="11" frequency=")5(")', r"\g<1>500\2", s)),
]


def run_suite(suite: Path) -> int:
    return subprocess.run([sys.executable, str(HERE / "ruletest.py"), "suite", str(suite)], capture_output=True).returncode


def main() -> int:
    suite = Path(sys.argv[1]).resolve()
    spec = yaml.safe_load(suite.read_text())
    rules = (suite.parent / spec["rules"]).resolve()
    original = rules.read_text()
    if run_suite(suite) != 0:
        print("baseline suite is already failing; fix that first")
        return 1
    survived = []
    with tempfile.TemporaryDirectory() as tmp:
        for name, fn in MUTANTS:
            mutated = fn(original)
            if mutated == original:
                print(f"  [SKIP]     {name}  (pattern not found; update the mutant)")
                survived.append(name)
                continue
            mrules = Path(tmp) / "rules.xml"
            mrules.write_text(mutated)
            msuite = Path(tmp) / "suite.yml"
            spec2 = dict(spec, rules=str(mrules))
            for c in spec2["cases"]:
                c["events"] = str((suite.parent / c["events"]).resolve())
            msuite.write_text(yaml.safe_dump(spec2))
            killed = run_suite(msuite) != 0
            print(f"  [{'KILLED' if killed else 'SURVIVED'}] {name}")
            if not killed:
                survived.append(name)
    print(f"\n{len(MUTANTS) - len(survived)}/{len(MUTANTS)} mutants killed")
    return 1 if survived else 0


if __name__ == "__main__":
    sys.exit(main())

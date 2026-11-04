PY ?= python3
.PHONY: mutate test unit rules exploits gate-demo-bad gate-demo-good diagrams
test: unit rules exploits   ## everything that can run without GitHub or Docker

unit:                 ## gate logic: pass/fail, fail-closed, waivers, expiry
	$(PY) -m unittest tests.test_gate

rules:                ## detection lint + replay suite
	$(PY) tools/ruletest.py lint detections/payloop_rules.xml
	$(PY) tools/ruletest.py suite tests/detections.yml

exploits:             ## known exploits must stay mitigated on app/
	$(PY) tests/lab.py --app app --expect mitigated
	php tests/ssrf_guard_test.php app

gate-demo-good:       ## local scanners + gate on the hardened app (expect PASS)
	./scripts/local-gate.sh app

gate-demo-bad:        ## same on the intentionally vulnerable sample (expect FAIL)
	./scripts/local-gate.sh samples/vulnerable-app; test $$? -eq 1

diagrams:
	./scripts/check_diagrams.sh

mutate:               ## prove the detection suite can fail
	$(PY) tools/mutation_check.py tests/detections.yml

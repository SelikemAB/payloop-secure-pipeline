# Pipeline design

## Stages and what each one is for
| Job | Tool | Catches | Threat model link |
|---|---|---|---|
| `secrets` | gitleaks (tree + history) | Keys, tokens and passwords committed to the repo | TM-20, TM-03 |
| `sast` | Semgrep, custom taint rules | SQL injection, path traversal, SSRF sinks, weak hashing, hard-coded secrets, error leakage | TM-07, TM-12, TM-14, TM-15, TM-13 |
| `container-and-iac` | Trivy (fs and image), checkov | Vulnerable packages and base image, root containers, unpinned tags, risky workflow settings | TM-19, TM-21 |
| `sbom` | Syft (anchore/sbom-action) | Produces an SPDX inventory kept 90 days, so the next "are we affected?" question takes minutes | TM-19 |
| `exploit-regression` | `tests/lab.py`, SSRF guard tests | Re-runs the real exploits for every known finding and fails if any works again | TM-04 to TM-12, TM-15 |
| `gate` | `tools/gate.py` | Applies one policy to every report and decides | all |
| `detection-ci` | `tools/ruletest.py` | Rule lint plus replay of attacks and benign traffic against the Wazuh rules | detection coverage in the threat model |

## Why it is built this way
- **One decision point.** Scanners only produce evidence. `gate` is the single required status check, so swapping a scanner never changes branch protection.
- **Fail closed.** `gate` runs even when a scanner job crashed (`if: always()`), refuses to pass if any upstream job did not succeed, and exits 2 if a required report is missing or unparseable. A skipped scanner must never look like a clean result.
- **Severity lives in policy.** Checkov reports no severity on the free tier; `policy/gate-policy.yml` pins the checks that matter (root container and exposed SSH block, unpinned tags warn).
- **Exploit regression beats rules alone.** A scanner can miss a logic flaw; a test that replays the exploit cannot. Every finding fixed in the vuln lab becomes a permanent test here.
- **Waivers expire.** An exception needs an owner, a reason and an expiry within 90 days. An expired waiver fails the build until someone fixes the issue or renews with a new justification.
- **The gate protects itself.** `CODEOWNERS` requires a security review for `policy/`, `tools/gate.py`, the workflows and the detections, otherwise a PR could weaken the rules it is judged by.
- **Least privilege.** Workflow `permissions: contents: read`; `persist-credentials: false` on checkout; no `pull_request_target`; untrusted values reach scripts through `env`, never interpolated into shell.
- **Samples never pollute results.** The intentionally vulnerable app and bad Dockerfile live under `samples/` and are excluded from scans, but are exercised by the unit tests to prove the gate fails when it should.

## Hardening still on the list (honest)
- Pin every action by commit SHA (tags are used here for readability; Dependabot is configured to keep pins fresh). Pin the base image by digest.
- Sign images and attach the SBOM as an attestation (cosign / GitHub artifact attestations).
- Match the SBOM against a vulnerability database on a schedule (Grype) so newly published CVEs alert without a code change.
- Add a dynamic scan (ZAP baseline) against the compose stack in a staging job.
- Secrets scanning of history runs on every push here; for large repos move full-history scans to a nightly job.

## Not verified in this authoring environment
Semgrep, checkov, the gate and the exploit regression were run locally. The GitHub Actions workflows were linted with `actionlint` and `yamllint`
but not executed on GitHub, and the Docker image was not built (no container runtime available). Run the workflow once on a fresh repo and
fix whatever the first run shows; treat pinned tool versions (gitleaks 8.21.2, trivy-action 0.28.0, checkov 3.4.0, semgrep 1.183.0) as starting points to update.

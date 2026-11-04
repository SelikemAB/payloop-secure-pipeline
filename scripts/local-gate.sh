#!/usr/bin/env bash
# Run the scanners available on your machine and the gate, for fast feedback before you push.
# Usage: scripts/local-gate.sh [app-dir]     (default: app). Use samples/vulnerable-app to watch it fail.
# gitleaks and trivy are skipped when not installed and the verdict says INCOMPLETE; CI is the authority.
set -uo pipefail
cd "$(dirname "$0")/.."
target=${1:-app}; rm -rf reports && mkdir -p reports; skip=()
semgrep --config semgrep/ --metrics=off --disable-version-check --quiet --json --output reports/semgrep.json "$target"/src "$target"/public
if command -v checkov >/dev/null; then checkov -f Dockerfile --framework dockerfile -o json --quiet > reports/checkov.json 2>/dev/null; else skip+=(checkov); fi
if command -v gitleaks >/dev/null; then gitleaks detect --no-git --source "$target" --config .gitleaks.toml --report-format json --report-path reports/gitleaks.json --exit-code 0 --no-banner >/dev/null 2>&1; else skip+=(gitleaks); fi
if command -v trivy >/dev/null; then
  trivy fs --quiet --scanners vuln,secret,misconfig --format json --output reports/trivy-fs.json "$target"; echo '{"Results":[]}' > reports/trivy-image.json; skip+=(trivy-image)
else skip+=(trivy-fs trivy-image); fi
python3 tools/gate.py --policy policy/gate-policy.yml --reports reports --skip "$(IFS=,; echo "${skip[*]}")"

#!/usr/bin/env bash
# Render every ```mermaid block in the docs with mermaid-cli to prove the diagrams parse. Needs: npm i -g @mermaid-js/mermaid-cli
set -euo pipefail
cd "$(dirname "$0")/.."
out=${1:-diagrams}; mkdir -p "$out"
cfg=$(mktemp)
# CHROME_PATH lets you point puppeteer at an existing Chromium; otherwise mermaid-cli uses its own download.
if [ -n "${CHROME_PATH:-}" ]; then printf '{"executablePath":"%s","args":["--no-sandbox"]}' "$CHROME_PATH" > "$cfg"; else echo '{"args":["--no-sandbox"]}' > "$cfg"; fi
n=0
for f in README.md docs/*.md; do
  awk -v base="$(basename "$f" .md)" -v out="$out" '
    /^```mermaid/ {k++; fn=sprintf("%s/%s-%d.mmd", out, base, k); inblock=1; next}
    /^```/ && inblock {inblock=0; close(fn); next}
    inblock {print > fn}' "$f"
done
for m in "$out"/*.mmd; do
  [ -e "$m" ] || continue
  mmdc -q -p "$cfg" -i "$m" -o "${m%.mmd}.svg" && n=$((n+1))
done
echo "rendered $n diagram(s) to $out/"

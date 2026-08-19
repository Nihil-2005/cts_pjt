#!/bin/bash
# Run OWASP ZAP baseline scan against a target URL
# Usage: ./scanners/run_zap.sh <target_url> <output_file>

set -euo pipefail

TARGET="${1:?Usage: $0 <target_url> <output_file>}"
OUTPUT="${2:?Usage: $0 <target_url> <output_file>}"

echo "[*] Running ZAP baseline scan against $TARGET"
docker run --rm --network=host \
  -v "$(dirname "$OUTPUT")":/zap/wrk \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t "$TARGET" \
  -J "/zap/wrk/$(basename "$OUTPUT")" || true

echo "[+] ZAP scan complete: $OUTPUT"

#!/bin/bash
# Run Wapiti scanner against a target URL
# Usage: ./scanners/run_bwapiti.sh <target_url> <output_file>

set -euo pipefail

TARGET="${1:?Usage: $0 <target_url> <output_file>}"
OUTPUT="${2:?Usage: $0 <target_url> <output_file>}"

echo "[*] Running Wapiti against $TARGET"
pip install wapiti3 2>/dev/null || true
wapiti -u "$TARGET" -f json -o "$OUTPUT" --flush-attacks --flush-session || true

echo "[+] Wapiti scan complete: $OUTPUT"

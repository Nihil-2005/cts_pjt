#!/bin/bash
# Run Nuclei against a target URL
# Usage: ./scanners/run_nuclei.sh <target_url> <output_file>

set -euo pipefail

TARGET="${1:?Usage: $0 <target_url> <output_file>}"
OUTPUT="${2:?Usage: $0 <target_url> <output_file>}"

echo "[*] Running Nuclei against $TARGET"
docker run --rm --network=host \
  -v "$(dirname "$OUTPUT")":/out \
  projectdiscovery/nuclei:v3.3.0 \
  -u "$TARGET" \
  -j -o "/out/$(basename "$OUTPUT")"

echo "[+] Nuclei scan complete: $OUTPUT"

#!/bin/bash
# Run Trivy against a Docker image
# Usage: ./scanners/run_trivy.sh <image_name> <output_file>

set -euo pipefail

IMAGE="${1:?Usage: $0 <image_name> <output_file>}"
OUTPUT="${2:?Usage: $0 <image_name> <output_file>}"

echo "[*] Running Trivy against $IMAGE"
docker run --rm \
  -v "$(dirname "$OUTPUT")":/out \
  aquasec/trivy:latest \
  image --format json -o "/out/$(basename "$OUTPUT")" \
  "$IMAGE" || true

echo "[+] Trivy scan complete: $OUTPUT"

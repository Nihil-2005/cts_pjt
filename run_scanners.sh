#!/usr/bin/env bash
# Background scanner runner used by E2E verification.
cd "$(dirname "$0")" || exit 1
bash scripts/03-scan.sh > scan_run.log 2>&1

#!/usr/bin/env bash
# Background pipeline runner used by E2E verification.
cd "$(dirname "$0")" || exit 1
bash scripts/04-pipeline.sh > pipeline_run.log 2>&1

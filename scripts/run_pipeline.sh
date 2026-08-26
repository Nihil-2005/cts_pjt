#!/usr/bin/env bash
cd "$(dirname "$0")" || exit 1
bash scripts/04-pipeline.sh > pipeline_run.log 2>&1

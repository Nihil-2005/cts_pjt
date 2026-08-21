#!/usr/bin/env bash
# ============================================================================
#  Stage 4: Run the 8-Stage Security Pipeline
#  1. Normalize     — parse scanner reports into unified schema
#  2. Deduplicate   — remove duplicate findings
#  3. Filter        — quarantine false positives and low-risk items
#  4. Enrich        — KEV, EPSS, NVD, Exploit-DB (optional, can skip)
#  5. Attack Paths  — map attack chains across findings
#  6. Risk Score    — 8-factor explainable scoring
#  7. AI Enrich     — FP classification + smart remediation (optional)
#  8. Remediate     — generate first-aid + full fix guidance
#
#  Usage:
#    bash scripts/04-pipeline.sh                          # full pipeline
#    bash scripts/04-pipeline.sh --skip-enrich            # skip threat intel
#    bash scripts/04-pipeline.sh --skip-enrich --skip-ai  # fully offline
#    bash scripts/04-pipeline.sh --products juice_shop    # single product
# ============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${BLUE}[*]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[X]${NC} $1"; }
header()  { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}"; echo -e "${BOLD}${CYAN}  $1${NC}"; echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}\n"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORTS_DIR="$SCRIPT_DIR/scan_reports"
OUTPUT_DIR="$SCRIPT_DIR/outputs"
CONFIG="$SCRIPT_DIR/config.json"

# Activate venv if present (fixes python: command not found on Windows)
if [ -f "$SCRIPT_DIR/venv/Scripts/activate" ]; then
    source "$SCRIPT_DIR/venv/Scripts/activate"
elif [ -f "$SCRIPT_DIR/venv/bin/activate" ]; then
    source "$SCRIPT_DIR/venv/bin/activate"
fi

# Find python executable
PYTHON=$(command -v python3 2>/dev/null || command -v python 2>/dev/null || echo python)

# Build pipeline command
CMD="$PYTHON -m pipeline.run --reports scan_reports/ --config config.json --out outputs/"

# Parse optional arguments
for arg in "$@"; do
    case "$arg" in
        --skip-enrich)  CMD="$CMD --skip-enrich" ;;
        --skip-ai)      CMD="$CMD --skip-ai" ;;
        --products)     ;; # handled below
        --help|-h)
            echo "Usage: bash scripts/04-pipeline.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --skip-enrich    Skip threat intel lookups (KEV/EPSS/NVD)"
            echo "  --skip-ai        Skip AI enrichment (FP classification)"
            echo "  --products X     Only scan specific product(s)"
            echo "  --help           Show this help"
            exit 0
            ;;
    esac
done

# Check for products argument
for i in "${!BASH_ARGV[@]}"; do
    if [ "${BASH_ARGV[$i]}" = "--products" ]; then
        NEXT=$((i - 1))
        CMD="$CMD --products ${BASH_ARGV[$NEXT]}"
    fi
done

header "Running 8-Stage Pipeline"

# Verify reports exist
if [ ! -d "$REPORTS_DIR" ] || [ -z "$(ls "$REPORTS_DIR"/*.json 2>/dev/null)" ]; then
    error "No scan reports found in $REPORTS_DIR/"
    error "Run scanner first: bash scripts/03-scan.sh"
    exit 1
fi

# Load GROQ key if available
if [ -f "$SCRIPT_DIR/.env" ]; then
    GROQ_KEY=$(grep "^GROQ_API_KEY=" "$SCRIPT_DIR/.env" 2>/dev/null | cut -d'=' -f2- || true)
    [ -n "$GROQ_KEY" ] && export GROQ_API_KEY="$GROQ_KEY"
fi

mkdir -p "$OUTPUT_DIR"

info "Running: $CMD"
echo ""

cd "$SCRIPT_DIR"
$PYTHON -m pipeline.run \
    --reports scan_reports/ \
    --config config.json \
    --out outputs/ \
    "$@" || {
    error "Pipeline failed! Check output above."
    exit 1
}

echo ""
success "Pipeline complete!"
info "Outputs in: $OUTPUT_DIR/"
ls "$OUTPUT_DIR/" 2>/dev/null | head -20

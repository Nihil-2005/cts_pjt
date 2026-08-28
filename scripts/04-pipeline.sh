#!/usr/bin/env bash
# Stage 4: Run 9-stage pipeline
set -euo pipefail
export MSYS_NO_PATHCONV=1

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

VENV_PYTHON=""
if [ -f "$SCRIPT_DIR/venv/Scripts/python.exe" ]; then
    VENV_PYTHON="$SCRIPT_DIR/venv/Scripts/python.exe"
elif [ -f "$SCRIPT_DIR/venv/Scripts/python" ]; then
    VENV_PYTHON="$SCRIPT_DIR/venv/Scripts/python"
elif [ -f "$SCRIPT_DIR/venv/bin/python" ]; then
    VENV_PYTHON="$SCRIPT_DIR/venv/bin/python"
fi

if [ -n "$VENV_PYTHON" ]; then
    source "$SCRIPT_DIR/venv/Scripts/activate" 2>/dev/null || source "$SCRIPT_DIR/venv/bin/activate" 2>/dev/null || true
fi

PYTHON="${VENV_PYTHON:-$(command -v python3 2>/dev/null || command -v python 2>/dev/null || echo python)}"

for arg in "$@"; do
    if [ "$arg" = "--help" ] || [ "$arg" = "-h" ]; then
        echo "Usage: bash scripts/04-pipeline.sh [OPTIONS]"
        echo ""
        echo "Options:"
        echo "  --skip-ai        Skip AI enrichment (FP classification)"
        echo "  --products X     Only scan specific product(s)"
        echo "  --help           Show this help"
        exit 0
    fi
done

header "Running 9-Stage Pipeline"

# Sync scan reports from Docker volume to host (scanners write to Docker volume)
if docker volume inspect devsecops-pipeline_scan-reports-vol >/dev/null 2>&1; then
    VOL_FILES=$(docker run --rm -v devsecops-pipeline_scan-reports-vol:/data alpine sh -c "ls /data/ 2>/dev/null | grep -c .")
    if [ "$VOL_FILES" -gt 0 ]; then
        info "Syncing $VOL_FILES scan reports from Docker volume..."
        docker run --rm -v devsecops-pipeline_scan-reports-vol:/data -v "$REPORTS_DIR:/host" alpine sh -c "cp -rn /data/* /host/ 2>/dev/null; cp -u /data/* /host/ 2>/dev/null"
        success "Scan reports synced"
    fi
fi

if [ ! -d "$REPORTS_DIR" ] || [ -z "$(ls "$REPORTS_DIR"/*.json "$REPORTS_DIR"/*.xml 2>/dev/null)" ]; then
    error "No scan reports found in $REPORTS_DIR/"
    error "Run scanner first: bash scripts/03-scan.sh"
    exit 1
fi

if [ -f "$SCRIPT_DIR/.env" ]; then
    set -a
    while IFS= read -r line || [ -n "$line" ]; do
        line="$(echo "$line" | tr -d '\r')"
        case "$line" in
            ''|\#*) continue ;;
        esac
        export "$line"
    done < "$SCRIPT_DIR/.env"
    set +a
fi

mkdir -p "$OUTPUT_DIR"
info "Running: pipeline $*"
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

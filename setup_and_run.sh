#!/usr/bin/env bash
# DevSecOps Risk Intelligence Pipeline — One-Command Launcher
# Order: setup → dashboard → deploy → scan → pipeline
set -euo pipefail
export MSYS_NO_PATHCONV=1

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${BLUE}[*]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[X]${NC} $1"; }
header()  { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}"; echo -e "${BOLD}${CYAN}  $1${NC}"; echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}\n"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS="$SCRIPT_DIR/scripts"

PIPELINE_TARGETS=""
PIPELINE_PRODUCTS=""
PIPELINE_SCANNERS=""
SKIP_SCAN=0
SHOW_HELP=0
ANY_FLAG=0

while [ $# -gt 0 ]; do
    ANY_FLAG=1
    case "$1" in
        --target)    PIPELINE_TARGETS="$PIPELINE_TARGETS ${2:-}"; shift 2 ;;
        --products)  PIPELINE_PRODUCTS="${2:-}"; shift 2 ;;
        --scanners)  PIPELINE_SCANNERS="${2:-}"; shift 2 ;;
        --skip-scan) SKIP_SCAN=1; shift ;;
        -h|--help)   SHOW_HELP=1; shift ;;
        *) echo "Unknown option: $1 (see --help)"; exit 1 ;;
    esac
done
export PIPELINE_TARGETS PIPELINE_PRODUCTS PIPELINE_SCANNERS SKIP_SCAN

if [ "$SHOW_HELP" = "1" ]; then
    sed -n '2,13p' "$0"
    exit 0
fi

REMOTE_MODE=0
if [ -n "${PIPELINE_TARGETS// /}" ]; then REMOTE_MODE=1; fi

header "DevSecOps Risk Intelligence Pipeline — Full Setup"
echo "  Order: setup → dashboard → deploy → scan → pipeline"
echo ""
if [ "$REMOTE_MODE" = "1" ]; then echo "  Mode: REMOTE scanning"; fi
if [ "$SKIP_SCAN" = "1" ]; then echo "  Mode: process existing reports (--skip-scan)"; fi
echo ""
if [ "$ANY_FLAG" = "1" ]; then
    info "Flags provided — starting without confirmation"
else
    echo "  Press ENTER to start, or Ctrl+C to cancel..."
    read -r
fi

header "Stage 1/5: Environment Setup"
bash "$SCRIPTS/01-setup.sh"

header "Stage 2/5: Starting Dashboard"
info "Dashboard must be online before anything else..."

if [ -z "${DASHBOARD_PASS:-}" ]; then
    _VENV_PY=""
    if [ -f "$SCRIPT_DIR/venv/Scripts/python.exe" ]; then
        _VENV_PY="$SCRIPT_DIR/venv/Scripts/python.exe"
    elif [ -f "$SCRIPT_DIR/venv/Scripts/python" ]; then
        _VENV_PY="$SCRIPT_DIR/venv/Scripts/python"
    elif [ -f "$SCRIPT_DIR/venv/bin/python" ]; then
        _VENV_PY="$SCRIPT_DIR/venv/bin/python"
    fi
    DASHBOARD_PASS=$("${_VENV_PY:-python}" -c "import secrets; print(secrets.token_urlsafe(16))" 2>/dev/null || echo "changeme")
    export DASHBOARD_PASS
fi
info "Admin password: $DASHBOARD_PASS"

bash "$SCRIPTS/05-dashboard.sh" &
DASHBOARD_PID=$!

DASHBOARD_READY=false
for i in $(seq 1 30); do
    if curl -s --max-time 3 http://localhost:8000/api/health > /dev/null 2>&1; then
        success "Dashboard is online at http://localhost:8000"
        DASHBOARD_READY=true
        break
    fi
    sleep 1
done

if ! kill -0 $DASHBOARD_PID 2>/dev/null; then
    error "Dashboard failed to start!"
    exit 1
fi

if ! $DASHBOARD_READY; then
    warn "Dashboard may still be starting (check http://localhost:8000)"
fi

cleanup() {
    info "Shutting down..."
    if kill -0 $DASHBOARD_PID 2>/dev/null; then
        kill $DASHBOARD_PID 2>/dev/null
        wait $DASHBOARD_PID 2>/dev/null || true
    fi
    if command -v docker &>/dev/null; then
        if docker compose version &>/dev/null; then
            docker compose -f "$SCRIPT_DIR/targets/docker-compose.yml" down 2>/dev/null || true
        elif command -v docker-compose &>/dev/null; then
            docker-compose -f "$SCRIPT_DIR/targets/docker-compose.yml" down 2>/dev/null || true
        fi
    fi
    exit 0
}
trap cleanup INT TERM

if [ "$SKIP_SCAN" = "1" ]; then
    header "Stage 3/5: Deploy — SKIPPED (--skip-scan)"
elif [ "$REMOTE_MODE" = "1" ]; then
    header "Stage 3/5: Deploy — SKIPPED (remote mode)"
    info "Targets run on the remote machine."
else
    header "Stage 3/5: Deploy Target Apps"
    bash "$SCRIPTS/02-deploy.sh"
fi

if [ "$SKIP_SCAN" = "1" ]; then
    header "Stage 4/5: Scanning — SKIPPED (--skip-scan)"
else
    header "Stage 4/5: Running Scanners"
    bash "$SCRIPTS/03-scan.sh"
fi

header "Stage 5/5: Running Pipeline"
bash "$SCRIPTS/04-pipeline.sh"

echo ""
success "All stages complete!"
echo ""
echo "  ACCESS:"
echo "    Dashboard: http://localhost:8000"
echo "    Login:     admin / ${DASHBOARD_PASS:-???}"
echo ""

info "Dashboard is running. Press Ctrl+C to stop."
wait $DASHBOARD_PID 2>/dev/null || true

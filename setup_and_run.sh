#!/usr/bin/env bash
# ============================================================================
#  DevSecOps Risk Intelligence Pipeline — One-Command Launcher
# ============================================================================
#  Strict initialization order:
#    1. Setup environment (venv, deps, API keys)
#    2. Start Dashboard server FIRST (central state engine)
#    3. Deploy target apps (Docker)
#    4. Run scanners (Nuclei + ZAP + Trivy + Wapiti)
#    5. Process through 8-stage pipeline
#
#  Usage:  bash setup_and_run.sh
# ============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${BLUE}[*]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[X]${NC} $1"; }
header()  { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}"; echo -e "${BOLD}${CYAN}  $1${NC}"; echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}\n"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS="$SCRIPT_DIR/scripts"

# ── Welcome ─────────────────────────────────────────────────────────────────
header "DevSecOps Risk Intelligence Pipeline — Full Setup"
echo "  Strict initialization order:"
echo ""
echo "    1. Setup environment (venv, deps, API keys)"
echo "    2. Start Dashboard server (central state engine)"
echo "    3. Deploy target apps (Docker)"
echo "    4. Run scanners (Nuclei + ZAP + Trivy + Wapiti)"
echo "    5. Process through 8-stage pipeline"
echo ""
echo "  Press ENTER to start, or Ctrl+C to cancel..."
read -r

# ── Stage 1: Setup ─────────────────────────────────────────────────────────
header "Stage 1/5: Environment Setup"
bash "$SCRIPTS/01-setup.sh"

# ── Stage 2: Dashboard FIRST (central state engine) ────────────────────────
header "Stage 2/5: Starting Dashboard (Central State Engine)"
info "Dashboard must be online before anything else..."
bash "$SCRIPTS/05-dashboard.sh" &
DASHBOARD_PID=$!
sleep 3  # Give it a moment to bind

# Verify dashboard is up
if curl -s http://localhost:8000/api/health > /dev/null 2>&1; then
    success "Dashboard is online at http://localhost:8000"
else
    warn "Dashboard may still be starting (check http://localhost:8000)"
fi

# ── Stage 3: Deploy ────────────────────────────────────────────────────────
header "Stage 3/5: Deploy Target Apps"
bash "$SCRIPTS/02-deploy.sh"

# ── Stage 4: Scan ──────────────────────────────────────────────────────────
header "Stage 4/5: Running Scanners"
bash "$SCRIPTS/03-scan.sh"

# ── Stage 5: Pipeline ──────────────────────────────────────────────────────
header "Stage 5/5: Running Pipeline"
bash "$SCRIPTS/04-pipeline.sh"

# ── Done ───────────────────────────────────────────────────────────────────
echo ""
success "All stages complete!"
echo ""
echo "  ACCESS:"
echo "    Dashboard: http://localhost:8000"
echo "    Login:     admin / admin"
echo "    API Docs:  http://localhost:8000/docs"
echo ""
echo "  INBOUND PORTS (server listens on):"
echo "    8000/tcp   HTTP  Dashboard + REST API + WebSocket"
echo ""
echo "  OUTBOUND PORTS (server connects to):"
echo "    27017/tcp  MongoDB      (NodeGoat database)"
echo "    3000/tcp   Juice Shop   (target app)"
echo "    4000/tcp   NodeGoat     (target app)"
echo "    8080/tcp   bWAPP        (target app)"
echo "    443/tcp    CDN/API      (EPSS, NVD, Exploit-DB, Groq AI)"
echo ""

# Keep dashboard running in foreground
echo ""
info "Dashboard is running. Press Ctrl+C to stop."
wait $DASHBOARD_PID 2>/dev/null || true

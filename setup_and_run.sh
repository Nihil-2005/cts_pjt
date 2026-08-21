#!/usr/bin/env bash
# ============================================================================
#  DevSecOps Risk Intelligence Pipeline — One-Command Launcher
# ============================================================================
#  Calls individual stage scripts in sequence.
#  Each script is also runnable independently.
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
echo "  This will run all 5 stages in sequence:"
echo ""
echo "    Stage 1: Setup environment (venv, deps, API keys)"
echo "    Stage 2: Deploy target apps (Docker)"
echo "    Stage 3: Run scanners (Nuclei + ZAP + Trivy + Wapiti)"
echo "    Stage 4: Process through 8-stage pipeline"
echo "    Stage 5: Open interactive dashboard"
echo ""
echo "  Press ENTER to start, or Ctrl+C to cancel..."
read -r

# ── Stage 1: Setup ─────────────────────────────────────────────────────────
header "Stage 1/5: Environment Setup"
bash "$SCRIPTS/01-setup.sh"

# ── Stage 2: Deploy ────────────────────────────────────────────────────────
header "Stage 2/5: Deploy Target Apps"
bash "$SCRIPTS/02-deploy.sh"

# ── Stage 3: Scan ──────────────────────────────────────────────────────────
header "Stage 3/5: Running Scanners"
bash "$SCRIPTS/03-scan.sh"

# ── Stage 4: Pipeline ──────────────────────────────────────────────────────
header "Stage 4/5: Running Pipeline"
bash "$SCRIPTS/04-pipeline.sh"

# ── Stage 5: Dashboard ─────────────────────────────────────────────────────
header "Stage 5/5: Starting Dashboard"
bash "$SCRIPTS/05-dashboard.sh"

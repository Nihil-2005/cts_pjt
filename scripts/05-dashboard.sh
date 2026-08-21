#!/usr/bin/env bash
# ============================================================================
#  Stage 5: Start the Interactive Dashboard
#  - Launches FastAPI server on port 8000
#  - Opens browser automatically
#  - Shows login credentials
#
#  Usage:
#    bash scripts/05-dashboard.sh              # default port 8000
#    bash scripts/05-dashboard.sh 9000         # custom port
# ============================================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${BLUE}[*]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
header()  { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}"; echo -e "${BOLD}${CYAN}  $1${NC}"; echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}\n"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${1:-8000}"
URL="http://localhost:$PORT"

header "Starting Dashboard Server"

# Check if venv exists
VENV_DIR="$SCRIPT_DIR/venv"
if [ -d "$VENV_DIR" ]; then
    # shellcheck disable=SC1091
    source "$VENV_DIR/Scripts/activate" 2>/dev/null || source "$VENV_DIR/bin/activate"
fi

# Check if server module exists
if ! python -c "from pipeline.server import app" 2>/dev/null; then
    warn "FastAPI server module not found — make sure dependencies are installed"
    warn "Run: bash scripts/01-setup.sh"
    exit 1
fi

# Check if another process is using the port
if command -v lsof &> /dev/null; then
    if lsof -i ":$PORT" -t &>/dev/null; then
        warn "Port $PORT is already in use!"
        warn "Kill it first or use a different port: bash scripts/05-dashboard.sh 9000"
        exit 1
    fi
elif command -v netstat &> /dev/null; then
    if netstat -ano 2>/dev/null | grep -q ":$PORT.*LISTENING"; then
        warn "Port $PORT is already in use!"
        warn "Kill it first or use a different port: bash scripts/05-dashboard.sh 9000"
        exit 1
    fi
fi

# Open browser after delay
(sleep 3 && case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)  cmd.exe /c start "" "$URL" 2>/dev/null ;;
    Darwin*)               open "$URL" ;;
    *)                     xdg-open "$URL" 2>/dev/null ;;
esac) &

echo ""
echo "  ${BOLD}Dashboard:${NC} $URL"
echo "  ${BOLD}Login:${NC}     admin / admin"
echo ""
echo "  ${BOLD}API Docs:${NC} $URL/docs"
echo "  ${BOLD}Health:${NC}   $URL/api/health"
echo ""
echo "  Press Ctrl+C to stop the server."
echo ""

# Start the server (sets PORT via env if needed)
export PORT="$PORT"
cd "$SCRIPT_DIR"
python -m pipeline.server

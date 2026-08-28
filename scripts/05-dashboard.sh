#!/usr/bin/env bash
# Stage 5: Start dashboard server
export MSYS_NO_PATHCONV=1

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${BLUE}[*]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[X]${NC} $1"; }
header()  { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}"; echo -e "${BOLD}${CYAN}  $1${NC}"; echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}\n"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${1:-8000}"
URL="http://localhost:$PORT"

header "Starting Dashboard Server"

VENV_DIR="$SCRIPT_DIR/venv"
VENV_PYTHON=""
if [ -f "$VENV_DIR/bin/python" ] && "$VENV_DIR/bin/python" -c "import sys" >/dev/null 2>&1; then
    VENV_PYTHON="$VENV_DIR/bin/python"
elif [ -f "$VENV_DIR/Scripts/python.exe" ] && "$VENV_DIR/Scripts/python.exe" -c "import sys" >/dev/null 2>&1; then
    VENV_PYTHON="$VENV_DIR/Scripts/python.exe"
elif [ -f "$VENV_DIR/Scripts/python" ] && "$VENV_DIR/Scripts/python" -c "import sys" >/dev/null 2>&1; then
    VENV_PYTHON="$VENV_DIR/Scripts/python"
elif command -v python3 >/dev/null 2>&1 && python3 -c "import fastapi" >/dev/null 2>&1; then
    VENV_PYTHON=$(command -v python3)
elif command -v python >/dev/null 2>&1 && python -c "import fastapi" >/dev/null 2>&1; then
    VENV_PYTHON=$(command -v python)
fi

if [ -z "$VENV_PYTHON" ]; then
    error "No working Python environment found with project dependencies installed."
    error "Please run: bash scripts/01-setup.sh"
    exit 1
fi
info "Using Python: $VENV_PYTHON"

if [ -f "$VENV_DIR/Scripts/activate" ]; then
    source "$VENV_DIR/Scripts/activate" 2>/dev/null || true
elif [ -f "$VENV_DIR/bin/activate" ]; then
    source "$VENV_DIR/bin/activate" 2>/dev/null || true
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
    info "Loaded .env"
fi

if [ -z "${DASHBOARD_PASS:-}" ]; then
    DASHBOARD_PASS=$("$VENV_PYTHON" -c "import secrets; print(secrets.token_urlsafe(16))" 2>/dev/null || echo "changeme")
    export DASHBOARD_PASS
    info "Generated admin password: $DASHBOARD_PASS"
else
    info "Using existing DASHBOARD_PASS"
fi

IMPORT_ERR=$("$VENV_PYTHON" -c "from pipeline.server import app" 2>&1)
IMPORT_RC=$?
if [ "$IMPORT_RC" -ne 0 ]; then
    error "FastAPI server module not found (exit code $IMPORT_RC)"
    error "Error: $IMPORT_ERR"
    exit 1
fi
success "Server module OK"

PORT_IN_USE=false
if command -v lsof &> /dev/null; then
    lsof -i ":$PORT" -t &>/dev/null && PORT_IN_USE=true
elif command -v ss &> /dev/null; then
    ss -tlnp 2>/dev/null | grep -q ":$PORT " && PORT_IN_USE=true
elif command -v netstat &> /dev/null; then
    netstat -ano 2>/dev/null | grep -q ":$PORT.*LISTENING" && PORT_IN_USE=true
elif command -v powershell.exe &> /dev/null; then
    powershell.exe -Command "(Get-NetTCPConnection -LocalPort $PORT -ErrorAction SilentlyContinue)" &>/dev/null && PORT_IN_USE=true
fi

if [ "$PORT_IN_USE" = true ]; then
    if curl -s --max-time 2 "http://localhost:$PORT/api/health" >/dev/null 2>&1; then
        success "Dashboard is already running and healthy on port $PORT"
        (sleep 1 && case "$(uname -s)" in
            MINGW*|MSYS*|CYGWIN*)  cmd.exe /c start "" "$URL" 2>/dev/null ;;
            Darwin*)               open "$URL" ;;
            *)                     xdg-open "$URL" 2>/dev/null ;;
        esac) &
        exit 0
    else
        warn "Port $PORT is occupied by an unresponsive process — freeing port..."
        if command -v fuser &>/dev/null; then
            fuser -k "${PORT}/tcp" 2>/dev/null || true
        elif command -v powershell.exe &>/dev/null; then
            powershell.exe -Command "Get-NetTCPConnection -LocalPort $PORT -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id \$_.OwningProcess -Force -ErrorAction SilentlyContinue }" 2>/dev/null || true
        fi
        sleep 1
    fi
fi
success "Port $PORT ready"

(sleep 3 && case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)  cmd.exe /c start "" "$URL" 2>/dev/null ;;
    Darwin*)               open "$URL" ;;
    *)                     xdg-open "$URL" 2>/dev/null ;;
esac) &

echo ""
echo "  ${BOLD}Dashboard:${NC} $URL"
echo "  ${BOLD}Login:${NC}     admin / ${DASHBOARD_PASS}"
echo ""
echo "  ${BOLD}API Docs:${NC}    $URL/docs"
echo "  ${BOLD}Health:${NC}      $URL/api/health"
echo "  ${BOLD}WebSocket:${NC}   ws://localhost:$PORT/ws/live"
echo ""

export PORT="$PORT"
export DASHBOARD_PASS
exec "$VENV_PYTHON" -m pipeline.server

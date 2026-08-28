#!/usr/bin/env bash
# Start the dashboard in Docker — runs independently of scans/pipeline.
# Usage:
#   bash start-dashboard.sh              # Start dashboard + all target apps
#   bash start-dashboard.sh --dashboard  # Start dashboard only (no targets)
#   bash start-dashboard.sh --stop       # Stop everything
#   bash start-dashboard.sh --status     # Show container status
set -euo pipefail
export MSYS_NO_PATHCONV=1

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${BLUE}[*]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[X]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# On Windows/Git Bash, convert /c/Users/... to C:/Users/... for Docker
if command -v cygpath &>/dev/null; then
    SCRIPT_DIR=$(cygpath -w "$SCRIPT_DIR")
    SCRIPT_DIR="${SCRIPT_DIR//\\//}"
fi

COMPOSE_FILE="$SCRIPT_DIR/docker-compose.dashboard.yml"
COMPOSE_TARGETS="$SCRIPT_DIR/targets/docker-compose.yml"

# ─── Parse flags ─────────────────────────────────────────────────
MODE="full"
case "${1:-}" in
    --dashboard)  MODE="dashboard-only" ;;
    --stop)       MODE="stop" ;;
    --status)     MODE="status" ;;
    --restart)    MODE="restart" ;;
    -h|--help)
        echo "Usage: bash start-dashboard.sh [--dashboard|--stop|--status|--restart]"
        echo ""
        echo "  (no flag)      Start dashboard + target apps in Docker"
        echo "  --dashboard    Start dashboard only (no target apps)"
        echo "  --stop         Stop all containers"
        echo "  --status       Show container status"
        echo "  --restart      Restart all containers"
        exit 0
        ;;
esac

# ─── Ensure .env exists ──────────────────────────────────────────
if [ ! -f "$SCRIPT_DIR/.env" ]; then
    warn ".env not found — creating with defaults"
    DASHBOARD_PASS=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))" 2>/dev/null || echo "changeme")
    cat > "$SCRIPT_DIR/.env" <<ENVEOF
DASHBOARD_PASS=$DASHBOARD_PASS
GITHUB_TOKEN=
GITHUB_REPO=
NVD_API_KEY=
GROQ_API_KEY=
JIRA_URL=
JIRA_USER=
JIRA_TOKEN=
JIRA_PROJECT=
DEFECTDOJO_URL=
DEFECTDOJO_API_KEY=
ENVEOF
    chmod 600 "$SCRIPT_DIR/.env"
    info "Created .env with password: $DASHBOARD_PASS"
fi

# ─── Ensure outputs dir exists ───────────────────────────────────
mkdir -p "$SCRIPT_DIR/outputs" "$SCRIPT_DIR/scan_reports" "$SCRIPT_DIR/intel"

# ─── Stop mode ───────────────────────────────────────────────────
if [ "$MODE" = "stop" ]; then
    info "Stopping all containers..."
    docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true
    success "All containers stopped"
    exit 0
fi

# ─── Status mode ─────────────────────────────────────────────────
if [ "$MODE" = "status" ]; then
    echo ""
    echo -e "${BOLD}Container Status:${NC}"
    echo ""
    docker compose -f "$COMPOSE_FILE" ps 2>/dev/null || true
    echo ""
    # Also check ports
    for port in 8000 3000 4000 8080 27017; do
        if curl -s --max-time 2 "http://localhost:$port/api/health" > /dev/null 2>&1; then
            success "Port $port — responding"
        elif curl -s --max-time 2 "http://localhost:$port/" > /dev/null 2>&1; then
            success "Port $port — responding (non-API)"
        else
            warn "Port $port — not responding"
        fi
    done
    exit 0
fi

# ─── Restart mode ────────────────────────────────────────────────
if [ "$MODE" = "restart" ]; then
    info "Restarting containers..."
    docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true
    sleep 2
    MODE="full"
fi

# ─── Stop conflicting containers ────────────────────────────────
info "Stopping any existing target containers..."
for cname in juiceshop nodegoat bwapp nodegoat-mongo; do
    if docker ps -a --format '{{.Names}}' | grep -q "^${cname}$"; then
        docker rm -f "$cname" 2>/dev/null || true
        info "Removed container: $cname"
    fi
done

# ─── Build dashboard image ───────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${CYAN}  DevSecOps Dashboard — Docker Mode${NC}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo ""

info "Building dashboard Docker image..."
docker compose -f "$COMPOSE_FILE" build dashboard 2>&1 | tail -5

# ─── Start containers ────────────────────────────────────────────
if [ "$MODE" = "dashboard-only" ]; then
    info "Starting dashboard only (no target apps)..."
    docker compose -f "$COMPOSE_FILE" up -d dashboard
else
    info "Starting dashboard + all target apps..."
    docker compose -f "$COMPOSE_FILE" up -d
fi

# ─── Wait for health ─────────────────────────────────────────────
echo ""
info "Waiting for dashboard to be ready..."

DASHBOARD_READY=false
for i in $(seq 1 30); do
    if curl -s --max-time 3 http://localhost:8000/api/health > /dev/null 2>&1; then
        DASHBOARD_READY=true
        break
    fi
    sleep 2
done

# ─── Get password ────────────────────────────────────────────────
DASHBOARD_PASS=""
if [ -f "$SCRIPT_DIR/.env" ]; then
    DASHBOARD_PASS=$(grep "^DASHBOARD_PASS=" "$SCRIPT_DIR/.env" | cut -d= -f2 | tr -d '\r')
fi

# ─── Print status ────────────────────────────────────────────────
echo ""
if $DASHBOARD_READY; then
    success "Dashboard is online!"
else
    warn "Dashboard may still be starting..."
fi

echo ""
echo -e "  ${BOLD}Dashboard:${NC}  http://localhost:8000"
echo -e "  ${BOLD}Login:${NC}      admin / ${DASHBOARD_PASS:-???}"
echo -e "  ${BOLD}API Docs:${NC}   http://localhost:8000/docs"
echo ""
echo -e "  ${BOLD}Target Apps:${NC}"
echo -e "    Juice Shop:  http://localhost:3000"
echo -e "    NodeGoat:    http://localhost:4000"
echo -e "    bWAPP:       http://localhost:8080"
echo ""
echo -e "  ${BOLD}Commands:${NC}"
echo -e "    Stop:        bash start-dashboard.sh --stop"
echo -e "    Status:      bash start-dashboard.sh --status"
echo -e "    Restart:     bash start-dashboard.sh --restart"
echo -e "    Logs:        docker logs -f devsecops-dashboard"
echo ""

# Auto-open browser
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)  (sleep 2 && cmd.exe /c start "" "http://localhost:8000") 2>/dev/null & ;;
    Darwin*)               (sleep 2 && open "http://localhost:8000") 2>/dev/null & ;;
    *)                     (sleep 2 && xdg-open "http://localhost:8000") 2>/dev/null & ;;
esac

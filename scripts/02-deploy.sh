#!/usr/bin/env bash
# ============================================================================
#  Stage 2: Deploy Target Apps (Docker)
#  - Checks which containers are already running
#  - Only starts missing ones (doesn't recreate running containers)
#  - Waits for apps to be ready
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
COMPOSE_FILE="$SCRIPT_DIR/targets/docker-compose.yml"

header "Deploying Target Apps"

if ! command -v docker &> /dev/null; then
    error "Docker not found! Install Docker Desktop first."
    exit 1
fi

# Check running containers
RUNNING=$(docker ps --format '{{.Names}}' 2>/dev/null || true)

JUICE_UP=false; NODE_UP=false; BWAPP_UP=false; MONGO_UP=false
echo "$RUNNING" | grep -q "^juiceshop$"  && JUICE_UP=true
echo "$RUNNING" | grep -q "^nodegoat$"   && NODE_UP=true
echo "$RUNNING" | grep -q "^bwapp$"      && BWAPP_UP=true
echo "$RUNNING" | grep -q "^nodegoat-mongo$" && MONGO_UP=true

ALL_RUNNING=true
$JUICE_UP && $NODE_UP && $BWAPP_UP && $MONGO_UP || ALL_RUNNING=false

if $ALL_RUNNING; then
    success "All target apps already running!"
    info "  juiceshop   localhost:3000"
    info "  nodegoat    localhost:4000"
    info "  bwapp       localhost:8080"
    exit 0
fi

# Show what's missing
MISSING=""
$JUICE_UP || MISSING="$MISSING Juice Shop"
$NODE_UP  || MISSING="$MISSING NodeGoat"
$BWAPP_UP || MISSING="$MISSING bWAPP"
$MONGO_UP || MISSING="$MISSING MongoDB"
info "Starting missing:$MISSING"

# Bring everything up (docker compose is idempotent — running containers stay running)
docker compose -f "$COMPOSE_FILE" up -d

# Wait for apps to be ready
info "Waiting 20 seconds for apps to start..."
sleep 20

READY=0
for port in 3000 4000 8080; do
    if curl -s -o /dev/null -w "" "http://localhost:$port" 2>/dev/null; then
        success "Port $port is up"
        READY=$((READY + 1))
    else
        warn "Port $port not responding yet"
    fi
done

if [ "$READY" -ge 2 ]; then
    success "At least 2 targets are running"
else
    warn "Some targets may not be ready — scans may partially fail"
fi

echo ""
success "Target apps deployed!"
info "  juiceshop   localhost:3000"
info "  nodegoat    localhost:4000"
info "  bwapp       localhost:8080"

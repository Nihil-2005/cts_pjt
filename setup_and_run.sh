#!/usr/bin/env bash
# ============================================================================
#  DevSecOps Risk Intelligence Pipeline — One-Command Launcher
# ============================================================================
#  This script does EVERYTHING from scratch:
#    1. Creates a Python virtual environment
#    2. Installs all dependencies
#    3. Prompts for API keys (optional — everything works offline too)
#    4. Deploys vulnerable target apps via Docker
#    5. Runs all 4 scanners (Nuclei, ZAP, Trivy, Wapiti)
#    6. Processes findings through the 8-stage pipeline
#    7. Opens the interactive dashboard in your browser
#
#  Usage:  bash setup_and_run.sh
# ============================================================================

set -euo pipefail

# ─── Colors & Helpers ───────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${BLUE}[*]${NC} $1"; }
success() { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[X]${NC} $1"; }
header()  { echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}"; echo -e "${BOLD}${CYAN}  $1${NC}"; echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════${NC}\n"; }

# Detect OS for browser open command
open_browser() {
    local file="$1"
    local abs_path
    abs_path="$(cd "$(dirname "$file")" && pwd)/$(basename "$file")"
    case "$(uname -s)" in
        MINGW*|MSYS*|CYGWIN*)  cmd.exe /c start "" "$abs_path" 2>/dev/null ;;
        Darwin*)               open "$abs_path" ;;
        *)                     xdg-open "$abs_path" 2>/dev/null || echo "  Open manually: $abs_path" ;;
    esac
}

# Detect Windows Git Bash paths (e.g. /c/Users/...)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── STEP 0: Welcome ───────────────────────────────────────────────────────
header "DevSecOps Risk Intelligence Pipeline — Full Setup"
echo "  This will set up everything and run the complete pipeline:"
echo ""
echo "    1. Create Python virtual environment"
echo "    2. Install dependencies"
echo "    3. Configure API keys (optional)"
echo "    4. Deploy vulnerable target apps (Docker)"
echo "    5. Run scanners: Nuclei + ZAP + Trivy + Wapiti"
echo "    6. Process through 8-stage pipeline"
echo "    7. Open interactive dashboard"
echo ""
echo "  Press ENTER to start, or Ctrl+C to cancel..."
read -r

# ─── STEP 1: Create Virtual Environment ────────────────────────────────────
header "STEP 1/7: Python Virtual Environment"

VENV_DIR="$SCRIPT_DIR/venv"

if [ -d "$VENV_DIR" ]; then
    warn "Virtual environment already exists at venv/ — reusing it"
else
    info "Creating virtual environment..."
    python3 -m venv "$VENV_DIR" 2>/dev/null || python -m venv "$VENV_DIR"
    success "Virtual environment created"
fi

# Activate venv
# shellcheck disable=SC1091
source "$VENV_DIR/Scripts/activate" 2>/dev/null || source "$VENV_DIR/bin/activate"
success "Activated virtual environment"
info "Python: $(python --version)"
info "pip:    $(pip --version | cut -d' ' -f1-2)"

# ─── STEP 2: Install Dependencies ──────────────────────────────────────────
header "STEP 2/7: Installing Dependencies"

pip install --upgrade pip --quiet
info "Installing project dependencies..."
pip install -r "$SCRIPT_DIR/requirements.txt" --quiet
success "All dependencies installed"

# Also install wapiti3 for Wapiti scanner (not in requirements.txt)
info "Installing Wapiti scanner..."
pip install wapiti3 --quiet 2>/dev/null || warn "Wapiti install failed — will skip Wapiti scans"
success "Dependencies ready"

# ─── STEP 3: Configure API Keys ────────────────────────────────────────────
header "STEP 3/7: API Key Configuration"

ENV_FILE="$SCRIPT_DIR/.env"

# Check if .env already has keys
EXISTING_GROQ=""
EXISTING_NVD=""
EXISTING_GITHUB_TOKEN=""
EXISTING_GITHUB_REPO=""
if [ -f "$ENV_FILE" ]; then
    EXISTING_GROQ=$(grep "^GROQ_API_KEY=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2- || true)
    EXISTING_NVD=$(grep "^NVD_API_KEY=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2- || true)
    EXISTING_GITHUB_TOKEN=$(grep "^GITHUB_TOKEN=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2- || true)
    EXISTING_GITHUB_REPO=$(grep "^GITHUB_REPOSITORY=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2- || true)
fi

echo "  All keys are OPTIONAL. Press Enter to skip any key."
echo "  The pipeline works fully offline without any keys."
echo ""

# Groq API Key (free AI enrichment — best quality)
echo -e "  ${BOLD}Groq API Key${NC} (free AI — console.groq.com)"
echo "  Sign up free, no credit card. Gets you Llama 3 70B for FP classification."
if [ -n "$EXISTING_GROQ" ]; then
    echo "  Current: ${EXISTING_GROQ:0:8}...${EXISTING_GROQ: -4}"
fi
read -rp "  Enter Groq API key (or press Enter to skip): " GROQ_KEY_INPUT
if [ -n "$GROQ_KEY_INPUT" ]; then
    GROQ_KEY="$GROQ_KEY_INPUT"
    success "Groq key configured"
else
    GROQ_KEY=""
    warn "Skipping Groq — rule-based AI will be used instead"
fi
echo ""

# NVD API Key (optional — increases rate limit from 5 to 50 req/30s)
echo -e "  ${BOLD}NVD API Key${NC} (optional — nvd.nist.gov/developers)"
echo "  Free registration. Increases NVD rate limit for CVE enrichment."
if [ -n "$EXISTING_NVD" ]; then
    echo "  Current: ${EXISTING_NVD:0:8}..."
fi
read -rp "  Enter NVD API key (or press Enter to skip): " NVD_KEY_INPUT
if [ -n "$NVD_KEY_INPUT" ]; then
    NVD_KEY="$NVD_KEY_INPUT"
    success "NVD key configured"
else
    NVD_KEY=""
    warn "Skipping NVD key — using default rate limit"
fi
echo ""

# GitHub Token (optional — for auto-creating Issues)
echo -e "  ${BOLD}GitHub Token${NC} (optional — github.com/settings/tokens)"
echo "  Free. Auto-creates GitHub Issues for P1/P2 findings."
if [ -n "$EXISTING_GITHUB_TOKEN" ]; then
    echo "  Current: ${EXISTING_GITHUB_TOKEN:0:8}..."
fi
read -rp "  Enter GitHub token (or press Enter to skip): " GH_TOKEN_INPUT
if [ -n "$GH_TOKEN_INPUT" ]; then
    GH_TOKEN="$GH_TOKEN_INPUT"
    # Also ask for repo name
    if [ -z "$EXISTING_GITHUB_REPO" ]; then
        read -rp "  Enter GitHub repo (e.g. yourname/your-repo): " GH_REPO_INPUT
        GH_REPO="${GH_REPO_INPUT:-}"
    else
        GH_REPO="$EXISTING_GITHUB_REPO"
    fi
    success "GitHub token configured"
else
    GH_TOKEN=""
    GH_REPO=""
    warn "Skipping GitHub — no auto-tickets"
fi

# Write .env file
cat > "$ENV_FILE" << ENVEOF
# DevSecOps Pipeline — API Keys
# Generated by setup_and_run.sh on $(date '+%Y-%m-%d %H:%M:%S')

# Groq: Free cloud AI (Llama 3 70B) — console.groq.com
GROQ_API_KEY=${GROQ_KEY}

# NVD: Free CVE data API — nvd.nist.gov/developers
NVD_API_KEY=${NVD_KEY}

# GitHub: Auto-create Issues for P1/P2 findings
GITHUB_TOKEN=${GH_TOKEN}
GITHUB_REPOSITORY=${GH_REPO}
ENVEOF

success ".env file written"

# ─── STEP 4: Deploy Vulnerable Target Apps ─────────────────────────────────
header "STEP 4/7: Deploying Target Apps (Docker)"

COMPOSE_FILE="$SCRIPT_DIR/targets/docker-compose.yml"

if ! command -v docker &> /dev/null; then
    error "Docker not found! Please install Docker Desktop first."
    exit 1
fi

# Stop any existing containers from this project
info "Stopping any existing target containers..."
docker compose -f "$COMPOSE_FILE" down 2>/dev/null || true

info "Pulling latest images..."
docker compose -f "$COMPOSE_FILE" pull --quiet 2>/dev/null || true

info "Starting Juice Shop (port 3000), NodeGoat (port 4000), bWAPP (port 80)..."
docker compose -f "$COMPOSE_FILE" up -d

info "Waiting for targets to be ready (30 seconds)..."
sleep 30

# Quick health check
READY=0
for port in 3000 4000 80; do
    if curl -s -o /dev/null -w "" "http://localhost:$port" 2>/dev/null; then
        success "Target on port $port is up"
        READY=$((READY + 1))
    else
        warn "Target on port $port not responding yet (may still be starting)"
    fi
done

if [ "$READY" -ge 2 ]; then
    success "At least 2 targets are running"
else
    warn "Some targets may not be ready — scans may partially fail (that's OK)"
fi

# ─── STEP 5: Run All Scanners ──────────────────────────────────────────────
header "STEP 5/7: Running Scanners"

SCAN_DIR="$SCRIPT_DIR/scan_reports"
mkdir -p "$SCAN_DIR"

# Clean old scan reports
rm -f "$SCAN_DIR"/*.json 2>/dev/null || true

TOTAL_SCANS=0
FAILED_SCANS=0

# ── Nuclei ──
echo ""
info "━━━ Nuclei Scanner ━━━"
for target_name in "nodegoat:4000" "juiceshop:3000" "bwapp:80"; do
    NAME="${target_name%%:*}"
    PORT="${target_name##*:}"
    URL="http://localhost:$PORT"
    OUTPUT="$SCAN_DIR/${NAME}_nuclei.json"

    info "Scanning $NAME ($URL)..."
    if docker run --rm --network=host \
        projectdiscovery/nuclei:latest \
        -u "$URL" -jsonl -o "/dev/stdout" 2>/dev/null > "$OUTPUT" || true; then
        success "Nuclei -> $NAME: $(wc -l < "$OUTPUT" 2>/dev/null || echo 0) findings"
        TOTAL_SCANS=$((TOTAL_SCANS + 1))
    else
        warn "Nuclei scan failed for $NAME"
        FAILED_SCANS=$((FAILED_SCANS + 1))
    fi
done

# ── ZAP ──
echo ""
info "━━━ OWASP ZAP Scanner ━━━"
for target_name in "nodegoat:4000" "juiceshop:3000" "bwapp:80"; do
    NAME="${target_name%%:*}"
    PORT="${target_name##*:}"
    URL="http://localhost:$PORT"
    OUTPUT="$SCAN_DIR/${NAME}_zap.json"

    info "Scanning $NAME ($URL)..."
    docker run --rm --network=host \
        -v "$SCAN_DIR":/zap/wrk \
        ghcr.io/zaproxy/zaproxy:stable \
        zap-baseline.py -t "$URL" -J "${NAME}_zap.json" || true

    if [ -f "$OUTPUT" ]; then
        success "ZAP -> $NAME: report generated"
        TOTAL_SCANS=$((TOTAL_SCANS + 1))
    else
        warn "ZAP scan produced no JSON for $NAME (may be normal for clean targets)"
    fi
done

# ── Trivy (container image vulnerabilities) ──
echo ""
info "━━━ Trivy Scanner (container images) ━━━"
declare -A TRIVY_TARGETS=(
    ["nodegoat"]="securecodebox/demo-target-nodegoat:latest"
    ["juiceshop"]="bkimminich/juice-shop:latest"
    ["bwapp"]="raesene/bwapp:latest"
)

for NAME in "${!TRIVY_TARGETS[@]}"; do
    IMAGE="${TRIVY_TARGETS[$NAME]}"
    OUTPUT="$SCAN_DIR/${NAME}_trivy.json"

    info "Scanning image $IMAGE..."
    docker run --rm \
        -v "$SCAN_DIR":/out \
        -v /var/run/docker.sock:/var/run/docker.sock \
        aquasec/trivy:latest \
        image --format json -o "/out/${NAME}_trivy.json" \
        "$IMAGE" || true

    if [ -f "$OUTPUT" ]; then
        success "Trivy -> $NAME: report generated"
        TOTAL_SCANS=$((TOTAL_SCANS + 1))
    else
        warn "Trivy scan failed for $NAME"
        FAILED_SCANS=$((FAILED_SCANS + 1))
    fi
done

# ── Wapiti ──
echo ""
info "━━━ Wapiti Scanner ━━━"
if command -v wapiti &> /dev/null || pip show wapiti3 &> /dev/null 2>&1; then
    for target_name in "nodegoat:4000" "juiceshop:3000"; do
        NAME="${target_name%%:*}"
        PORT="${target_name##*:}"
        URL="http://localhost:$PORT"
        OUTPUT="$SCAN_DIR/${NAME}_wapiti.json"

        info "Scanning $NAME ($URL)..."
        wapiti -u "$URL" -f json -o "$OUTPUT" --flush-attacks --flush-session 2>/dev/null || true

        if [ -f "$OUTPUT" ]; then
            success "Wapiti -> $NAME: report generated"
            TOTAL_SCANS=$((TOTAL_SCANS + 1))
        else
            warn "Wapiti scan failed for $NAME"
            FAILED_SCANS=$((FAILED_SCANS + 1))
        fi
    done
else
    warn "Wapiti not installed — skipping Wapiti scans"
fi

echo ""
success "Scanning complete: $TOTAL_SCANS reports generated"
info "Reports in: $SCAN_DIR/"
ls -la "$SCAN_DIR"/*.json 2>/dev/null || warn "No JSON reports found"

# ─── STEP 6: Run the 8-Stage Pipeline ──────────────────────────────────────
header "STEP 6/7: Running Pipeline (8 Stages)"

OUTPUT_DIR="$SCRIPT_DIR/outputs"
mkdir -p "$OUTPUT_DIR"

# Build pipeline command
PIPELINE_CMD="python -m pipeline.run --reports scan_reports/ --config config.json --out outputs/"

# Add Groq key if provided
if [ -n "$GROQ_KEY" ]; then
    export GROQ_API_KEY="$GROQ_KEY"
fi

info "Running: $PIPELINE_CMD"
echo ""

cd "$SCRIPT_DIR"
python -m pipeline.run \
    --reports scan_reports/ \
    --config config.json \
    --out outputs/ || {
    error "Pipeline failed! Check the output above for errors."
    exit 1
}

echo ""
success "Pipeline complete!"

# ─── STEP 7: Start Dashboard Server ──────────────────────────────────────
header "STEP 7/7: Starting Dashboard Server"

info "Starting FastAPI server on http://localhost:8000 ..."
info "Opening browser in 3 seconds..."

# Open browser after a short delay
(sleep 3 && case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)  cmd.exe /c start "" "http://localhost:8000" 2>/dev/null ;;
    Darwin*)               open "http://localhost:8000" ;;
    *)                     xdg-open "http://localhost:8000" 2>/dev/null ;;
) &

# Start the server (blocks until Ctrl+C)
echo ""
echo "  Dashboard: http://localhost:8000"
echo "  Login:     admin / admin"
echo ""
echo "  Press Ctrl+C to stop the server."
echo ""

python -m pipeline.server

# ─── Summary ────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${GREEN}  ALL DONE! Server is running.${NC}"
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "  Dashboard:  http://localhost:8000"
echo "  Login:      admin / admin"
echo ""
echo "  To restart later:"
echo "    source venv/Scripts/activate   # or venv/bin/activate on Mac/Linux"
echo "    python -m pipeline.server"
echo ""
echo "  To stop the target apps:"
echo "    docker compose -f targets/docker-compose.yml down"
echo ""

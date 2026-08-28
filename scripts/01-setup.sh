#!/usr/bin/env bash
# Stage 1: Setup — venv + deps + API keys
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
ENV_FILE="$SCRIPT_DIR/.env"
VENV_DIR="$SCRIPT_DIR/venv"

header "Step 1/3: Python Virtual Environment"

if [ -d "$VENV_DIR" ]; then
    warn "Virtual environment already exists — reusing"
else
    info "Creating virtual environment..."
    PYTHON_CMD=""
    if command -v python >/dev/null 2>&1 && \
       python -c 'import sys; sys.exit(0 if sys.version_info[0] >= 3 else 1)' 2>/dev/null; then
        PYTHON_CMD=$(command -v python)
    elif command -v python3 >/dev/null 2>&1 && \
         python3 -c 'import sys; sys.exit(0 if sys.version_info[0] >= 3 else 1)' 2>/dev/null; then
        PYTHON_CMD=$(command -v python3)
    fi
    if [ -z "$PYTHON_CMD" ]; then
        error "Python not found! Install Python 3.8+ first."
        exit 1
    fi
    $PYTHON_CMD --version 2>&1 | grep -q "Python 3" || {
        error "Python 3 is required (found: $($PYTHON_CMD --version))"
        exit 1
    }
    $PYTHON_CMD -m venv "$VENV_DIR"
    success "Virtual environment created"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/Scripts/activate" 2>/dev/null || source "$VENV_DIR/bin/activate"
success "Activated virtual environment"
info "Python: $(python --version)"
info "pip:    $(pip --version | cut -d' ' -f1-2)"

header "Step 2/3: Installing Dependencies"

pip install --upgrade pip --quiet 2>/dev/null

if python -c "import fastapi; import uvicorn; import pandas; import slowapi; import defusedxml" 2>/dev/null; then
    warn "Dependencies already installed — skipping"
else
    info "Installing project dependencies..."
    pip install -r "$SCRIPT_DIR/requirements.txt" --quiet
    success "All dependencies installed"
fi

if docker image inspect vulnlab/wapiti:latest &>/dev/null; then
    warn "Wapiti Docker image already present"
else
    info "Pulling Wapiti Docker image..."
    docker pull vulnlab/wapiti:latest --quiet 2>/dev/null || warn "Wapiti pull failed (will retry at scan time)"
fi
success "Dependencies ready"

header "Step 3/3: API Key Configuration"

EXISTING_GROQ=""; EXISTING_NVD=""; EXISTING_GH_TOKEN=""; EXISTING_GH_REPO=""
if [ -f "$ENV_FILE" ]; then
    EXISTING_GROQ=$(grep "^GROQ_API_KEY=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2- || true)
    EXISTING_NVD=$(grep "^NVD_API_KEY=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2- || true)
    EXISTING_GH_TOKEN=$(grep "^GITHUB_TOKEN=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2- || true)
    EXISTING_GH_REPO=$(grep "^GITHUB_REPOSITORY=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2- || true)
fi

echo "  All keys are OPTIONAL. Press Enter to skip any."
echo ""

echo -e "  ${BOLD}Groq API Key${NC} (free AI — console.groq.com)"
if [ -n "$EXISTING_GROQ" ]; then echo "  Current: ${EXISTING_GROQ:0:8}...${EXISTING_GROQ: -4}"; fi
read -rp "  Enter key (or Enter to skip): " GROQ_INPUT
GROQ_KEY="${GROQ_INPUT:-$EXISTING_GROQ}"
[ -n "$GROQ_KEY" ] && success "Groq configured" || warn "Skipping Groq"
echo ""

echo -e "  ${BOLD}NVD API Key${NC} (optional — nvd.nist.gov/developers)"
if [ -n "$EXISTING_NVD" ]; then echo "  Current: ${EXISTING_NVD:0:8}..."; fi
read -rp "  Enter key (or Enter to skip): " NVD_INPUT
NVD_KEY="${NVD_INPUT:-$EXISTING_NVD}"
[ -n "$NVD_KEY" ] && success "NVD configured" || warn "Skipping NVD"
echo ""

echo -e "  ${BOLD}GitHub Token${NC} (optional — auto-create Issues)"
if [ -n "$EXISTING_GH_TOKEN" ]; then echo "  Current: ${EXISTING_GH_TOKEN:0:8}..."; fi
read -rp "  Enter token (or Enter to skip): " GH_INPUT
if [ -n "$GH_INPUT" ]; then
    GH_TOKEN="$GH_INPUT"
    if [ -z "$EXISTING_GH_REPO" ]; then
        read -rp "  Enter GitHub repo (e.g. yourname/repo): " GH_REPO_INPUT
        GH_REPO="${GH_REPO_INPUT:-}"
    else
        GH_REPO="$EXISTING_GH_REPO"
    fi
    success "GitHub configured"
else
    GH_TOKEN="${EXISTING_GH_TOKEN:-}"
    GH_REPO="${EXISTING_GH_REPO:-}"
    [ -n "$GH_TOKEN" ] && info "Keeping existing GitHub token" || warn "Skipping GitHub"
fi

# Preserve existing integration keys from previous .env
EXISTING_JIRA_URL=""; EXISTING_JIRA_USER=""; EXISTING_JIRA_TOKEN=""; EXISTING_JIRA_PROJECT=""
EXISTING_DD_URL=""; EXISTING_DD_TOKEN=""
if [ -f "$ENV_FILE" ]; then
    EXISTING_JIRA_URL=$(grep "^JIRA_URL=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2- || true)
    EXISTING_JIRA_USER=$(grep "^JIRA_USER=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2- || true)
    EXISTING_JIRA_TOKEN=$(grep "^JIRA_TOKEN=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2- || true)
    EXISTING_JIRA_PROJECT=$(grep "^JIRA_PROJECT=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2- || true)
    EXISTING_DD_URL=$(grep "^DEFECTDOJO_URL=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2- || true)
    EXISTING_DD_TOKEN=$(grep "^DEFECTDOJO_API_KEY=" "$ENV_FILE" 2>/dev/null | cut -d'=' -f2- || true)
fi

cat > "$ENV_FILE" << ENVEOF
# DevSecOps Pipeline — API Keys
GROQ_API_KEY=${GROQ_KEY}
NVD_API_KEY=${NVD_KEY}
GITHUB_TOKEN=${GH_TOKEN}
GITHUB_REPOSITORY=${GH_REPO}
# Jira Integration (configure from dashboard Integrations tab)
JIRA_URL=${EXISTING_JIRA_URL}
JIRA_USER=${EXISTING_JIRA_USER}
JIRA_TOKEN=${EXISTING_JIRA_TOKEN}
JIRA_PROJECT=${EXISTING_JIRA_PROJECT}
# DefectDojo Integration (configure from dashboard Integrations tab)
DEFECTDOJO_URL=${EXISTING_DD_URL}
DEFECTDOJO_API_KEY=${EXISTING_DD_TOKEN}
ENVEOF

success ".env file written"
echo ""
success "Setup complete! Run: bash scripts/02-deploy.sh"

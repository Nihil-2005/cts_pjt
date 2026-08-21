#!/usr/bin/env bash
# ============================================================================
#  Stage 3: Run Scanners
#  - Nuclei (network vulnerabilities)
#  - OWASP ZAP (web app vulnerabilities)
#  - Trivy (container image vulnerabilities)
#  - Wapiti (web app vulnerabilities)
#
#  Usage:
#    bash scripts/03-scan.sh              # scan all targets
#    bash scripts/03-scan.sh juiceshop   # scan one target
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
SCAN_DIR="$SCRIPT_DIR/scan_reports"
mkdir -p "$SCAN_DIR"

# Activate venv if present
if [ -f "$SCRIPT_DIR/venv/Scripts/activate" ]; then
    source "$SCRIPT_DIR/venv/Scripts/activate"
elif [ -f "$SCRIPT_DIR/venv/bin/activate" ]; then
    source "$SCRIPT_DIR/venv/bin/activate"
fi

# Find python executable
PYTHON=$(command -v python3 2>/dev/null || command -v python 2>/dev/null || echo python)

# Clean old reports
rm -f "$SCAN_DIR"/*.json 2>/dev/null || true

# Target definitions: name:port
ALL_TARGETS=("nodegoat:4000" "juiceshop:3000" "bwapp:8080")

# Filter targets if specific one requested
if [ -n "${1:-}" ]; then
    FOUND=false
    for t in "${ALL_TARGETS[@]}"; do
        [[ "$t" == "$1"* ]] && FOUND=true
    done
    if $FOUND; then
        ALL_TARGETS=("$1")
        info "Scanning single target: $1"
    else
        error "Unknown target: $1 (available: nodegoat, juiceshop, bwapp)"
        exit 1
    fi
fi

TOTAL=0; FAILED=0

# ── Nuclei ──────────────────────────────────────────────────────────────────
header "Nuclei Scanner"
for target_name in "${ALL_TARGETS[@]}"; do
    NAME="${target_name%%:*}"
    PORT="${target_name##*:}"
    URL="http://localhost:$PORT"
    OUTPUT="$SCAN_DIR/${NAME}_nuclei.json"

    if ! curl -s -o /dev/null -w "" "$URL" 2>/dev/null; then
        warn "$NAME ($URL) not reachable — skipping"
        FAILED=$((FAILED + 1))
        continue
    fi

    info "Scanning $NAME ($URL)..."
    docker rm -f "scanner-nuclei-$NAME" 2>/dev/null || true
    if docker run --rm --name "scanner-nuclei-$NAME" --network=host \
        projectdiscovery/nuclei:latest \
        -u "$URL" -jsonl -o "/dev/stdout" 2>/dev/null > "$OUTPUT" || true; then
        COUNT=$(wc -l < "$OUTPUT" 2>/dev/null || echo 0)
        if [ "$COUNT" -gt 0 ]; then
            success "Nuclei -> $NAME: $COUNT findings"
        else
            warn "Nuclei -> $NAME: 0 findings"
        fi
        TOTAL=$((TOTAL + 1))
    else
        warn "Nuclei failed for $NAME"
        FAILED=$((FAILED + 1))
    fi
done

# ── OWASP ZAP ───────────────────────────────────────────────────────────────
header "OWASP ZAP Scanner"
for target_name in "${ALL_TARGETS[@]}"; do
    NAME="${target_name%%:*}"
    PORT="${target_name##*:}"
    URL="http://localhost:$PORT"
    OUTPUT="$SCAN_DIR/${NAME}_zap.json"

    if ! curl -s -o /dev/null -w "" "$URL" 2>/dev/null; then
        warn "$NAME ($URL) not reachable — skipping"
        FAILED=$((FAILED + 1))
        continue
    fi

    info "Scanning $NAME ($URL)..."
    docker rm -f "scanner-zap-$NAME" 2>/dev/null || true
    docker run --rm --name "scanner-zap-$NAME" --network=host \
        -v "$SCAN_DIR":/zap/wrk \
        ghcr.io/zaproxy/zaproxy:stable \
        zap-baseline.py -t "$URL" -J "${NAME}_zap.json" || true

    if [ -f "$OUTPUT" ]; then
        success "ZAP -> $NAME: report generated"
        TOTAL=$((TOTAL + 1))
    else
        warn "ZAP -> $NAME: no JSON output"
        FAILED=$((FAILED + 1))
    fi
done

# ── Trivy (container images) ────────────────────────────────────────────────
header "Trivy Scanner (container images)"
declare -A TRIVY_TARGETS=(
    ["juiceshop"]="bkimminich/juice-shop:latest"
    ["nodegoat"]="nodegoat-web:latest"
    ["bwapp"]="raesene/bwapp:latest"
)

for NAME in "juiceshop" "bwapp" "nodegoat"; do
    # Skip if target not in scan list
    if ! printf '%s\n' "${ALL_TARGETS[@]}" | grep -q "^${NAME}:"; then
        continue
    fi

    IMAGE="${TRIVY_TARGETS[$NAME]}"
    OUTPUT="$SCAN_DIR/${NAME}_trivy.json"

    info "Scanning image $IMAGE..."
    docker rm -f "scanner-trivy-$NAME" 2>/dev/null || true
    docker run --rm --name "scanner-trivy-$NAME" \
        -v "$SCAN_DIR":/out \
        -v /var/run/docker.sock:/var/run/docker.sock \
        aquasec/trivy:latest \
        image --format json \
        -o "/out/${NAME}_trivy.json" \
        "$IMAGE" || true

    if [ -f "$OUTPUT" ] && [ "$(wc -c < "$OUTPUT" 2>/dev/null || echo 0)" -gt 10 ]; then
        success "Trivy -> $NAME: report generated"
        TOTAL=$((TOTAL + 1))
    else
        warn "Trivy -> $NAME: empty or missing"
        FAILED=$((FAILED + 1))
    fi
done

# ── Wapiti ──────────────────────────────────────────────────────────────────
header "Wapiti Scanner"
if command -v wapiti &> /dev/null || $PYTHON -c "import wapiti3" 2>/dev/null; then
    for target_name in "${ALL_TARGETS[@]}"; do
        NAME="${target_name%%:*}"
        PORT="${target_name##*:}"
        URL="http://localhost:$PORT"
        OUTPUT="$SCAN_DIR/${NAME}_wapiti.json"

        # Wapiti doesn't work well with bWAPP
        if [ "$NAME" = "bwapp" ]; then
            warn "Wapiti: skipping bWAPP (compatibility issue)"
            continue
        fi

        if ! curl -s -o /dev/null -w "" "$URL" 2>/dev/null; then
            warn "$NAME ($URL) not reachable — skipping"
            FAILED=$((FAILED + 1))
            continue
        fi

        info "Scanning $NAME ($URL)..."
        wapiti -u "$URL" -f json -o "$OUTPUT" --flush-attacks --flush-session 2>/dev/null || $PYTHON -m wapiti3 -u "$URL" -f json -o "$OUTPUT" --flush-attacks --flush-session 2>/dev/null || true

        if [ -f "$OUTPUT" ] && [ "$(wc -c < "$OUTPUT" 2>/dev/null || echo 0)" -gt 10 ]; then
            success "Wapiti -> $NAME: report generated"
            TOTAL=$((TOTAL + 1))
        else
            warn "Wapiti -> $NAME: empty report"
        fi
    done
else
    warn "Wapiti not installed — skipping"
fi

# ── Summary ─────────────────────────────────────────────────────────────────
echo ""
success "Scanning complete: $TOTAL reports generated ($FAILED failed)"
info "Reports in: $SCAN_DIR/"
ls -la "$SCAN_DIR"/*.json 2>/dev/null || warn "No JSON reports found"

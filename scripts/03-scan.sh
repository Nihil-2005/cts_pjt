#!/usr/bin/env bash
# ============================================================================
#  Stage 3: Run Scanners (Comprehensive)
#  - Nuclei      — network + web vulnerabilities, CVEs, KEV, exploits
#  - OWASP ZAP   — web application vulnerabilities (full scan)
#  - Trivy       — container image CVEs + secrets + misconfig
#  - Wapiti      — web application vulnerabilities (SQLi, XSS, etc.)
#
#  Template updates run daily automatically.
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
TEMPLATE_DIR="$SCRIPT_DIR/intel/nuclei-templates"
mkdir -p "$SCAN_DIR" "$TEMPLATE_DIR"

# Activate venv if present
if [ -f "$SCRIPT_DIR/venv/Scripts/activate" ]; then
    source "$SCRIPT_DIR/venv/Scripts/activate"
elif [ -f "$SCRIPT_DIR/venv/bin/activate" ]; then
    source "$SCRIPT_DIR/venv/bin/activate"
fi

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

# Fix Git Bash / MSYS path conversion (converts /out/ to C:/Program Files/Git/out/)
export MSYS_NO_PATHCONV=1

# ============================================================================
#  NUCLEI — Comprehensive CVE + KEV + misconfig + exposure scanning
# ============================================================================
header "Nuclei Scanner (comprehensive: all severity, all template tags)"

# Update templates once per day
LAST_UPDATE_FILE="$TEMPLATE_DIR/.last_update"
NEEDS_UPDATE=true
if [ -f "$LAST_UPDATE_FILE" ]; then
    LAST_UPDATE=$(cat "$LAST_UPDATE_FILE" 2>/dev/null || echo "0")
    TODAY=$(date +%s)
    DIFF=$((TODAY - LAST_UPDATE))
    if [ "$DIFF" -lt 86400 ]; then
        NEEDS_UPDATE=false
        info "Nuclei templates updated today — skipping"
    fi
fi

if $NEEDS_UPDATE; then
    info "Updating nuclei templates..."
    docker rm -f "scanner-nuclei-update" 2>/dev/null || true
    docker run --rm --name "scanner-nuclei-update" --network=host \
        projectdiscovery/nuclei:latest \
        -update-templates 2>&1 | tail -5 || warn "Template update failed (will use cached)"
    date +%s > "$LAST_UPDATE_FILE"
    success "Nuclei templates ready"
fi

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

    # Comprehensive nuclei scan:
    #  -u URL           = target URL
    #  -severity        = all non-info severities
    #  -as              = all template tags (cves, vulnerabilities, misconfigurations,
    #                      exposures, default-logins, Takeovers, etc.)
    #  -c 25            = 25 concurrent template execution
    #  -rl 150          = rate limit 150 requests/sec
    #  -timeout 10      = 10s per request
    #  -retries 1       = retry failed once
    #  -jsonl           = JSON Lines output (one finding per line)
    docker run --rm --name "scanner-nuclei-$NAME" --network=host \
        projectdiscovery/nuclei:latest \
        -u "$URL" \
        -severity critical,high,medium,low \
        -as \
        -c 25 \
        -rl 150 \
        -timeout 10 \
        -retries 1 \
        -jsonl \
        -o "/dev/stdout" \
        2>/dev/null > "$OUTPUT" || true

    COUNT=$(wc -l < "$OUTPUT" 2>/dev/null || echo 0)
    if [ "$COUNT" -gt 0 ]; then
        CRIT=$(grep -c '"severity":"critical"' "$OUTPUT" 2>/dev/null || echo 0)
        HIGH=$(grep -c '"severity":"high"' "$OUTPUT" 2>/dev/null || echo 0)
        MED=$(grep -c '"severity":"medium"' "$OUTPUT" 2>/dev/null || echo 0)
        LOW=$(grep -c '"severity":"low"' "$OUTPUT" 2>/dev/null || echo 0)
        success "Nuclei -> $NAME: $COUNT findings (critical:$CRIT high:$HIGH medium:$MED low:$LOW)"
    else
        warn "Nuclei -> $NAME: 0 findings"
    fi
    TOTAL=$((TOTAL + 1))
done

# ============================================================================
#  OWASP ZAP — Full Spider + Active + Passive Scan
# ============================================================================
header "OWASP ZAP Scanner (full scan: spider + active + passive)"

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

    info "Spider + scanning $NAME ($URL)..."
    docker rm -f "scanner-zap-$NAME" 2>/dev/null || true

    # Full scan: spider, then passive + active scan
    docker run --rm --name "scanner-zap-$NAME" --network=host \
        -v "$SCAN_DIR":/zap/wrk \
        -t ghcr.io/zaproxy/zaproxy:stable \
        zap-full-scan.py \
        -t "$URL" \
        -J "${NAME}_zap.json" \
        -r "${NAME}_zap_report.html" \
        -d \
        -m 10 \
        -j \
        -z "-config scanner.maxScanDurationInMins=10" \
        2>/dev/null || true

    if [ -f "$OUTPUT" ]; then
        success "ZAP -> $NAME: report generated"
        TOTAL=$((TOTAL + 1))
    else
        warn "ZAP -> $NAME: no JSON output"
        FAILED=$((FAILED + 1))
    fi
done

# ============================================================================
#  TRIVY — Container image CVEs + Secrets + Misconfig
# ============================================================================
header "Trivy Scanner (container images: vuln + secrets + misconfig)"
declare -A TRIVY_TARGETS=(
    ["juiceshop"]="bkimminich/juice-shop:latest"
    ["nodegoat"]="nodegoat-web:latest"
    ["bwapp"]="raesene/bwapp:latest"
)

for NAME in "juiceshop" "bwapp" "nodegoat"; do
    if ! printf '%s\n' "${ALL_TARGETS[@]}" | grep -q "^${NAME}:"; then
        continue
    fi

    IMAGE="${TRIVY_TARGETS[$NAME]}"
    OUTPUT="$SCAN_DIR/${NAME}_trivy.json"

    info "Scanning image $IMAGE (vuln + secrets + misconfig)..."
    docker rm -f "scanner-trivy-$NAME" 2>/dev/null || true

    docker run --rm --name "scanner-trivy-$NAME" \
        -v "$SCAN_DIR":/out \
        -v /var/run/docker.sock:/var/run/docker.sock \
        aquasec/trivy:latest \
        image \
        --format json \
        --scanners vuln,secret,misconfig \
        --severity CRITICAL,HIGH,MEDIUM \
        -o "/out/${NAME}_trivy.json" \
        "$IMAGE" 2>/dev/null || true

    if [ -f "$OUTPUT" ] && [ "$(wc -c < "$OUTPUT" 2>/dev/null || echo 0)" -gt 10 ]; then
        success "Trivy -> $NAME: report generated"
        TOTAL=$((TOTAL + 1))
    else
        warn "Trivy -> $NAME: empty or missing"
        FAILED=$((FAILED + 1))
    fi
done

# ============================================================================
#  WAPITI — Web App Vulnerability Scanning (SQLi, XSS, SSRF, LFI, etc.)
# ============================================================================
header "Wapiti Scanner (SQLi, XSS, CRLF, SSRF, LFI, etc.)"

# NOTE: Docker image vulnlab/wapiti:latest has entrypoint "wapiti"
#       so we pass arguments directly (NO "wapiti" prefix in command)
#       Also requires MSYS_NO_PATHCONV=1 on Git Bash to prevent /out/ path mangling

WAPITI_OK=false
if docker image inspect "vulnlab/wapiti:latest" &>/dev/null; then
    WAPITI_OK=true
    info "Wapiti Docker image available"
else
    info "Pulling Wapiti Docker image..."
    docker pull vulnlab/wapiti:latest 2>/dev/null && WAPITI_OK=true || true
fi

if $WAPITI_OK; then
    for target_name in "${ALL_TARGETS[@]}"; do
        NAME="${target_name%%:*}"
        PORT="${target_name##*:}"
        OUTPUT="$SCAN_DIR/${NAME}_wapiti.json"

        if ! curl -s -o /dev/null -w "" "http://localhost:$PORT" 2>/dev/null; then
            warn "$NAME (localhost:$PORT) not reachable — skipping"
            FAILED=$((FAILED + 1))
            continue
        fi

        info "Scanning $NAME (http://localhost:$PORT)..."
        docker rm -f "scanner-wapiti-$NAME" 2>/dev/null || true

        # IMPORTANT: Docker entrypoint is already "wapiti", so arguments start with -u
        # -d = crawl depth (NOT --max-depth)
        # --flush-attacks/--flush-session = clean state
        # -t = timeout per request
        # -m = modules to use (all available by default)
        docker run --rm --name "scanner-wapiti-$NAME" --network=host \
            -v "$SCAN_DIR":/out \
            vulnlab/wapiti:latest \
            -u "http://localhost:$PORT" \
            -f json \
            -o "/out/${NAME}_wapiti.json" \
            -d 3 \
            --max-links-per-page 100 \
            --flush-attacks \
            --flush-session \
            -t 15 \
            2>/dev/null || true

        if [ -f "$OUTPUT" ] && [ "$(wc -c < "$OUTPUT" 2>/dev/null || echo 0)" -gt 10 ]; then
            WAPITI_VULNS=$(python -c "
import json
try:
    d=json.load(open('$OUTPUT'))
    total=sum(len(v) for v in d.get('vulnerabilities',{}).values())
    print(total)
except: print('?')
" 2>/dev/null || echo "?")
            success "Wapiti -> $NAME: $WAPITI_VULNS vulnerabilities"
            TOTAL=$((TOTAL + 1))
        else
            warn "Wapiti -> $NAME: empty report"
            FAILED=$((FAILED + 1))
        fi
    done
else
    warn "Wapiti not available — install: docker pull vulnlab/wapiti:latest"
    FAILED=$((FAILED + ${#ALL_TARGETS[@]}))
fi

# ============================================================================
#  Summary
# ============================================================================
echo ""
success "Scanning complete: $TOTAL reports generated ($FAILED failed)"
info "Reports in: $SCAN_DIR/"
ls -la "$SCAN_DIR"/*.json 2>/dev/null || warn "No JSON reports found"

# Per-scanner summary
echo ""
info "Per-scanner findings summary:"
for scanner in nuclei zap trivy wapiti; do
    COUNT=0
    for f in "$SCAN_DIR"/*_${scanner}.json; do
        [ -f "$f" ] || continue
        if [ "$scanner" = "nuclei" ]; then
            C=$(wc -l < "$f" 2>/dev/null || echo 0)
        else
            C=$($PYTHON -c "
import json
try:
    d=json.load(open('$f'))
    if 'Results' in d:
        print(sum(len(v or []) for r in d.get('Results',[]) for v in [r.get('Vulnerabilities',[])]))
    elif 'site' in d:
        print(sum(len(s.get('alerts',[])) for s in d.get('site',[])))
    elif 'vulnerabilities' in d:
        print(sum(len(v) for v in d.get('vulnerabilities',{}).values()))
    else:
        print(0)
except: print(0)
" 2>/dev/null || echo 0)
        fi
        COUNT=$((COUNT + C))
    done
    success "  $scanner: $COUNT findings"
done

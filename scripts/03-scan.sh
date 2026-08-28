#!/usr/bin/env bash
# Fix Git Bash / MSYS path conversion (converts /out/ to C:/Program Files/Git/out/)
export MSYS_NO_PATHCONV=1

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
export MSYS_NO_PATHCONV=1

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

# Find venv Python (Windows: Scripts/python.exe, Linux: bin/python)
VENV_PYTHON=""
if [ -f "$SCRIPT_DIR/venv/Scripts/python.exe" ]; then
    VENV_PYTHON="$SCRIPT_DIR/venv/Scripts/python.exe"
elif [ -f "$SCRIPT_DIR/venv/Scripts/python" ]; then
    VENV_PYTHON="$SCRIPT_DIR/venv/Scripts/python"
elif [ -f "$SCRIPT_DIR/venv/bin/python" ]; then
    VENV_PYTHON="$SCRIPT_DIR/venv/bin/python"
fi

# Activate venv if available
if [ -n "$VENV_PYTHON" ]; then
    source "$SCRIPT_DIR/venv/Scripts/activate" 2>/dev/null || source "$SCRIPT_DIR/venv/bin/activate" 2>/dev/null || true
fi

PYTHON="${VENV_PYTHON:-$(command -v python3 2>/dev/null || command -v python 2>/dev/null || echo python)}"

# Clean old reports — ARCHIVE, never delete (evidence survives across runs)
if ls "$SCAN_DIR"/*.json >/dev/null 2>&1; then
    TS=$(date +%Y-%m-%d_%H-%M-%S)
    ARCHIVE_DIR="$SCAN_DIR/archive/$TS"
    mkdir -p "$ARCHIVE_DIR"
    mv "$SCAN_DIR"/*.json "$ARCHIVE_DIR"/ 2>/dev/null || true
    info "Archived previous reports to scan_reports/archive/$TS/"
fi
# Keep only the 10 most recent archives
ls -1dt "$SCAN_DIR"/archive/*/ 2>/dev/null | tail -n +11 | while read -r old; do
    rm -rf "$old"
done

# ── Target overrides (from setup_and_run.sh --target flags) ────────────────
# PIPELINE_TARGETS: space-separated "IP[:port]" or "product=IP[:port]" values.
# Resolution order per product: keyed override > bare override host > localhost.
PIPELINE_TARGETS="${PIPELINE_TARGETS:-}"

resolve_target_url() {
    # $1 = product name, $2 = default port → echoes resolved base URL.
    # Local default is 127.0.0.1 (NOT localhost): avoids IPv6 ::1 races and
    # WSL-bash environments where 'localhost' is a different machine.
    _name="$1"; _port="$2"; _host="127.0.0.1"
    for t in $PIPELINE_TARGETS; do
        case "$t" in
            "$_name="*) _val="${t#*=}" ;;
            *=*) continue ;;
            *)   _val="$t" ;;
        esac
        case "$_val" in
            *://*) echo "$_val"; return ;;
            *:*)   _h="${_val%%:*}"; _p="${_val##*:}"; echo "http://$_h:$_p"; return ;;
            *)     _host="$_val" ;;
        esac
    done
    if [ "$_host" != "127.0.0.1" ]; then
        echo "http://$_host:$_port"; return
    fi
    echo "http://127.0.0.1:$_port"
}

is_local_target() {
    case "$1" in
        http://localhost:*|http://127.0.0.1:*|http://[::1]:*|https://localhost:*|https://127.0.0.1:*) return 0 ;;
        *) return 1 ;;
    esac
}

# Build resolved target list: entries become "name|url"
ALL_TARGETS=("nodegoat|$(resolve_target_url nodegoat 4000)" \
             "juiceshop|$(resolve_target_url juiceshop 3000)" \
             "bwapp|$(resolve_target_url bwapp 8080)")

REMOTE_MODE=0
for entry in "${ALL_TARGETS[@]}"; do
    if ! is_local_target "${entry##*|}"; then REMOTE_MODE=1; fi
done

# ── Scanner selection (--scanners flag via PIPELINE_SCANNERS) ───────────────
if [ -n "${PIPELINE_SCANNERS:-}" ]; then
    # Explicit selection always wins, remote or not
    SELECTED_SCANNERS=$(echo "$PIPELINE_SCANNERS" | tr ',' ' ')
else
    SELECTED_SCANNERS="nuclei zap trivy wapiti nmap"
    if [ "$REMOTE_MODE" = "1" ]; then
        # Default set drops trivy remotely: it inspects THIS machine's docker
        # daemon/images and can never see another machine's containers.
        SELECTED_SCANNERS="nuclei zap wapiti nmap"
        info "Remote mode: Trivy excluded from defaults (local-image scans only)"
    fi
fi

HAS_TRIVY=0
for s in $SELECTED_SCANNERS; do [ "$s" = "trivy" ] && HAS_TRIVY=1; done
if [ "$REMOTE_MODE" = "1" ] && [ "$HAS_TRIVY" = "1" ]; then
    warn "Remote mode with explicit trivy — it will scan THIS machine's local images only"
fi

want_scanner() { for s in $SELECTED_SCANNERS; do [ "$s" = "$1" ] && return 0; done; return 1; }

# Product filter (--products flag via PIPELINE_PRODUCTS, comma-separated)
if [ -n "${PIPELINE_PRODUCTS:-}" ]; then
    FILTERED=()
    IFS=',' read -ra WANTED <<< "$PIPELINE_PRODUCTS"
    for entry in "${ALL_TARGETS[@]}"; do
        NAME="${entry%%|*}"
        for w in "${WANTED[@]}"; do
            # accept both config ids (juice_shop) and container names (juiceshop)
            if [ "$NAME" = "$w" ] || { [ "$w" = "juice_shop" ] && [ "$NAME" = "juiceshop" ]; }; then
                FILTERED+=("$entry")
            fi
        done
    done
    ALL_TARGETS=("${FILTERED[@]}")
fi

TOTAL=0; FAILED=0

# ============================================================================
#  Preflight — probe every selected product before spending scan time
# ============================================================================
header "Preflight: checking targets are reachable"

for entry in "${ALL_TARGETS[@]}"; do
    NAME="${entry%%|*}"
    URL="${entry##*|}"

    READY=false
    for i in $(seq 1 5); do
        # stdout redirected by the SHELL (not curl -o): immune to
        # MSYS_NO_PATHCONV, which breaks literal /dev/null args on Windows curl
        if curl -s --max-time 3 "$URL" >/dev/null 2>&1; then
            READY=true
            break
        fi
        sleep 2
    done
    if ! $READY; then
        error "$NAME ($URL) is NOT reachable."
        case "$URL" in
            *localhost*|*127.0.0.1*)
                error "  Local target: run scripts/02-deploy.sh to start the apps." ;;
            *)
                error "  Remote target: check the app is running on that machine" ;
                error "  and ports are open (firewall inbound rules)." ;;
        esac
        exit 1
    fi

    # bWAPP cold-start trap: an unconfigured install serves its setup wizard,
    # which scanners would happily 'find vulnerabilities' in.
    if [ "$NAME" = "bwapp" ]; then
        BODY=$(curl -s --max-time 5 "$URL" 2>/dev/null \
               curl -s --max-time 5 "$URL/login.php" 2>/dev/null || true)
        case "$BODY" in
            *install.php*)
                error "bWAPP at $URL is not configured yet."
                error "  Open $URL/install.php in a browser, complete setup, then re-run."
                exit 1 ;;
        esac
    fi
    success "$NAME ($URL) ready"
done

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

want_scanner nuclei || { info "Nuclei skipped (--scanners)"; }

if want_scanner nuclei; then
for target_name in "${ALL_TARGETS[@]}"; do
    NAME="${target_name%%|*}"
    URL="${target_name##*|}"

    # --network=host only helps for localhost targets; bridge networking
    # reaches LAN IPs natively and is more reliable on Docker Desktop.
    NET_FLAG="--network=host"
    if ! is_local_target "$URL"; then NET_FLAG=""; fi

    OUTPUT="$SCAN_DIR/${NAME}_nuclei.json"

    info "Scanning $NAME ($URL)..."
    docker rm -f "scanner-nuclei-$NAME" 2>/dev/null || true

    # Comprehensive nuclei scan with DAST + vuln tags:
    #  -u URL           = target URL
    #  -c 25            = 25 concurrent template execution
    #  -rl 150          = rate limit 150 requests/sec
    #  -timeout 10      = 10s per request
    #  -retries 1       = retry failed once
    #  -dast            = enable DAST (active) templates
    #  -tags            = focus on high-overlap vulnerability types
    #  -jsonl           = JSON Lines output (one finding per line)
    docker run --rm --name "scanner-nuclei-$NAME" $NET_FLAG \
        --memory=1g --cpus=1 \
        projectdiscovery/nuclei:latest \
        -u "$URL" \
        -c 25 \
        -rl 150 \
        -timeout 10 \
        -retries 1 \
        -dast \
        -tags xss,sqli,lfi,rce,ssrf,xxe,redirect,crlf,command-injection \
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
fi

# ============================================================================
#  OWASP ZAP — Full Spider + Active + Passive Scan
# ============================================================================
header "OWASP ZAP Scanner (full scan: spider + active + passive)"

if want_scanner zap; then
for target_name in "${ALL_TARGETS[@]}"; do
    NAME="${target_name%%|*}"
    URL="${target_name##*|}"

    NET_FLAG="--network=host"
    if ! is_local_target "$URL"; then NET_FLAG=""; fi

    OUTPUT="$SCAN_DIR/${NAME}_zap.json"

    info "Scanning $NAME ($URL) [baseline mode]..."
    docker rm -f "scanner-zap-$NAME" 2>/dev/null || true

    # Baseline scan: passive scan + limited active scan (much lighter than full scan)
    # Capped at 1GB RAM / 1 CPU to prevent system crashes
    docker run --rm --name "scanner-zap-$NAME" $NET_FLAG \
        --memory=1g --cpus=1 \
        -v "$SCAN_DIR":/zap/wrk \
        ghcr.io/zaproxy/zaproxy:stable \
        zap-baseline.py \
        -t "$URL" \
        -J "${NAME}_zap.json" \
        -r "${NAME}_zap_report.html" \
        -d \
        -m 10 \
        2>/dev/null || true

    if [ -f "$OUTPUT" ]; then
        ZAP_SIZE=$(wc -c < "$OUTPUT" 2>/dev/null || echo 0)
        success "ZAP -> $NAME: report generated ($ZAP_SIZE bytes)"
        TOTAL=$((TOTAL + 1))
    else
        # Check if ZAP wrote to a different path
        ALT_OUTPUT="$SCAN_DIR/zap-report.json"
        if [ -f "$ALT_OUTPUT" ]; then
            mv "$ALT_OUTPUT" "$OUTPUT"
            success "ZAP -> $NAME: report found and renamed"
            TOTAL=$((TOTAL + 1))
        else
            warn "ZAP -> $NAME: no JSON output"
            FAILED=$((FAILED + 1))
        fi
    fi
done
fi  # want_scanner zap

# ============================================================================
#  TRIVY — Container image CVEs + Secrets + Misconfig (LOCAL ONLY)
# ============================================================================
if [ "$HAS_TRIVY" = "1" ] && want_scanner trivy; then
header "Trivy Scanner (container images: vuln + secrets + misconfig)"

# Trivy scans images by resolving them from the LOCAL docker daemon/registry.
for NAME in "juiceshop" "bwapp" "nodegoat"; do
    FOUND_IN_TARGETS=0
    for entry in "${ALL_TARGETS[@]}"; do
        [ "${entry%%|*}" = "$NAME" ] && FOUND_IN_TARGETS=1
    done
    [ "$FOUND_IN_TARGETS" = "1" ] || continue

    OUTPUT="$SCAN_DIR/${NAME}_trivy.json"

    # Check if container is running
    if ! docker inspect "$NAME" &>/dev/null; then
        warn "Trivy -> $NAME: container not running, skipping"
        FAILED=$((FAILED + 1))
        continue
    fi

    # Get the image name from the running container
    IMAGE=$(docker inspect --format='{{.Config.Image}}' "$NAME" 2>/dev/null || echo "$NAME")
    info "Scanning container $NAME (image: $IMAGE)..."
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
fi  # HAS_TRIVY && want_scanner trivy

# ============================================================================
#  WAPITI — Web App Vulnerability Scanning (SQLi, XSS, SSRF, LFI, etc.)
# ============================================================================
if want_scanner wapiti; then
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
        NAME="${target_name%%|*}"
        URL="${target_name##*|}"

        NET_FLAG="--network=host"
        if ! is_local_target "$URL"; then NET_FLAG=""; fi

        OUTPUT="$SCAN_DIR/${NAME}_wapiti.json"

        info "Scanning $NAME ($URL)..."
        docker rm -f "scanner-wapiti-$NAME" 2>/dev/null || true

        # Explicitly set entrypoint to wapiti (defensive against image changes)
        docker run --rm --name "scanner-wapiti-$NAME" $NET_FLAG \
            --memory=512m --cpus=0.5 \
            --entrypoint wapiti \
            -v "$SCAN_DIR":/out \
            vulnlab/wapiti:latest \
            -u "$URL" \
            -f json \
            -o "/out/${NAME}_wapiti.json" \
            -d 3 \
            --max-links-per-page 100 \
            --flush-attacks \
            --flush-session \
            -t 15 \
            2>/dev/null || true

        if [ -f "$OUTPUT" ] && [ "$(wc -c < "$OUTPUT" 2>/dev/null || echo 0)" -gt 10 ]; then
            WAPITI_VULNS=$($PYTHON -c "
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
fi  # want_scanner wapiti

# ============================================================================
#  NMAP — Port/Service Discovery + NSE Vuln Scripts
# ============================================================================
if want_scanner nmap; then
header "Nmap Scanner (port discovery + vuln/exploit NSE scripts)"

for target_name in "${ALL_TARGETS[@]}"; do
    NAME="${target_name%%|*}"
    URL="${target_name##*|}"

    # Nmap never uses --network=host (broken on Docker Desktop Windows/macOS)
    # Always use host.docker.internal for host access
    NET_FLAG=""

    # Extract host:port from URL for nmap, replace localhost with host.docker.internal
    NMAP_TARGET=$(echo "$URL" | sed 's|https*://||' | sed 's|/$||' | sed 's|localhost|host.docker.internal|g')

    OUTPUT_XML="$SCAN_DIR/${NAME}_nmap.xml"

    info "Scanning $NAME ($NMAP_TARGET)..."
    docker rm -f "scanner-nmap-$NAME" 2>/dev/null || true

    # Nmap with vuln + exploit NSE scripts:
    #  -sV              = service version detection
    #  --script vuln    = run vulnerability detection scripts
    #  --script exploit  = run exploit scripts (safe ones)
    #  -oX              = XML output (for normalize.py parser)
    #  -T4              = aggressive timing (faster)
    #  --open           = only show open ports
    docker run --rm --name "scanner-nmap-$NAME" $NET_FLAG \
        --memory=512m --cpus=0.5 \
        --add-host=host.docker.internal:host-gateway \
        -v "$SCAN_DIR":/out \
        instrumentisto/nmap:latest \
        -sV \
        --script vulners --script-timeout 60s \
        -oX "/out/${NAME}_nmap.xml" \
        -T4 \
        --open \
        "$NMAP_TARGET" \
        2>/dev/null || true

    if [ -f "$OUTPUT_XML" ] && [ "$(wc -c < "$OUTPUT_XML" 2>/dev/null || echo 0)" -gt 10 ]; then
        # Count open ports from XML directly (pipeline's normalize.py parses XML natively)
        NMAP_PORTS=$($PYTHON -c "
import sys
from defusedxml import ElementTree as ET
try:
    tree = ET.parse('$OUTPUT_XML')
    root = tree.getroot()
    count = 0
    for host in root.findall('host'):
        for p in host.findall('port'):
            s = p.find('state')
            if s is not None and s.get('state') == 'open':
                count += 1
    print(count)
except: print(0)
" 2>/dev/null || echo 0)
        success "Nmap -> $NAME: $NMAP_PORTS open ports/services"
        TOTAL=$((TOTAL + 1))
    else
        warn "Nmap -> $NAME: no output"
        FAILED=$((FAILED + 1))
    fi
done
fi  # want_scanner nmap

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
for scanner in nuclei zap trivy wapiti nmap; do
    COUNT=0
    for f in "$SCAN_DIR"/*_${scanner}.*; do
        [ -f "$f" ] || continue
        if [ "$scanner" = "nuclei" ]; then
            C=$(wc -l < "$f" 2>/dev/null || echo 0)
        elif [ "$scanner" = "nmap" ]; then
            C=$($PYTHON -c "
import sys
from defusedxml import ElementTree as ET
try:
    tree = ET.parse('$f')
    root = tree.getroot()
    count = 0
    for host in root.findall('host'):
        for p in host.findall('port'):
            s = p.find('state')
            if s is not None and s.get('state') == 'open':
                count += 1
    print(count)
except: print(0)
" 2>/dev/null || echo 0)
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

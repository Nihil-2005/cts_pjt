# DevSecOps Risk Intelligence Pipeline

**A 9-stage vulnerability processing pipeline that ingests raw scanner output and produces prioritized, explainable risk intelligence.**

## Architecture

```
devsecops-pipeline/
├── .github/workflows/devsecops-pipeline.yml   CI/CD: deploy -> scan -> process -> ticket
├── targets/docker-compose.yml                 3 vulnerable apps (NodeGoat, Juice Shop, bWAPP)
├── pipeline/                                  THE 9-STAGE BRAIN
│   ├── normalize.py        Stage 1: Parse raw scanner reports -> unified Finding schema
│   ├── dedup.py            Stage 2: Cross-scanner deduplication (CVE / endpoint+CWE / title)
│   ├── filter.py           Stage 3: Auditable quarantine (severity / FP / risk-accept)
│   ├── enrich.py           Stage 4: Threat intel (KEV, EPSS, NVD, Exploit-DB)
│   ├── attackpath.py       Stage 5: CAPEC-inspired CWE chain mapping
│   ├── score.py            Stage 6: 8-factor explainable risk scoring (0-100)
│   ├── remediation.py      Stage 7: First-aid + full remediation guidance
│   ├── output.py           Stage 8: Ranking, CSV/JSON/markdown, analytics
│   ├── models.py           Core data models (Finding, AttackPath, RunSummary)
│   ├── config.py           Configuration loader with sane defaults
│   ├── run.py              Unified entry point
│   ├── dashboard.py        Dark-theme HTML dashboard (Chart.js + D3)
│   ├── github_tickets.py   Auto-create GitHub Issues for P1/P2 findings
│   ├── ai_enrich.py        Hybrid AI: Groq -> Ollama -> Rule-based (all free)
│   ├── history.py          Run history persisted in SQLite
│   └── defectdojo_client.py DefectDojo integration (optional)
├── intel/                  Threat intel cache (KEV, EPSS, NVD)
├── config.json             Unified configuration
├── requirements.txt
├── setup_and_run.sh        ONE COMMAND: full setup + scan + pipeline + dashboard
├── run.bat                 Windows double-click launcher
├── Makefile                Build shortcuts
└── README.md
```

## Quick Start (One Command)

**Windows:** Double-click `run.bat`

**Mac/Linux:**
```bash
bash setup_and_run.sh
```

This does everything from scratch:
1. Creates a Python virtual environment
2. Installs all dependencies
3. Prompts for API keys (all optional -- works fully offline)
4. Deploys 3 vulnerable target apps via Docker
5. Runs Nuclei + ZAP + Trivy + Wapiti scanners
6. Processes findings through the 9-stage pipeline
7. Opens the interactive dashboard in your browser

## Manual Setup (step by step)

```bash
# 1. Create virtual environment
python -m venv venv
source venv/Scripts/activate   # Windows Git Bash
# source venv/bin/activate     # Mac/Linux

# 2. Install dependencies
pip install -r requirements.txt

# 3. Deploy target apps
docker compose -f targets/docker-compose.yml up -d
sleep 30

# 4. Run scanners
mkdir -p scan_reports
# Run Nuclei, ZAP, Trivy, Wapiti (Docker-based; see pipeline/scanner_manager.py and scripts/03-scan.sh)

# 5. Run pipeline
python -m pipeline.run --reports scan_reports/ --config config.json --out outputs/

# 6. Open dashboard
open outputs/risk_dashboard.html
```

## Run Tests

```bash
make test               # Run all tests
make test-coverage      # Run with coverage report
```

## The 9 Stages

| Stage | Module | What It Does |
|-------|--------|-------------|
| 1 | `normalize` | Parse ZAP/Nuclei/Wapiti/Trivy/Nmap/OpenVAS into unified Finding schema |
| 2 | `dedup` | Cross-scanner dedup: same CVE from 2 scanners -> 1 finding |
| 3 | `filter` | Auditable quarantine: never delete, always track why |
| 4 | `enrich` | CISA KEV + FIRST.org EPSS + NVD CVSS + Exploit-DB |
| 5 | `attackpath` | CWE->CWE chain mapping (CAPEC-inspired) |
| 6 | `score` | 8-factor explainable score (CVSS 20% + EPSS 20% + KEV 25% + ...) |
| 7 | `ai_enrich` | FP classification + smart remediation (Groq/Ollama/rule-based) |
| 8 | `remediation` | First-aid + full fix + scanner guidance |
| 9 | `output` | Ranked CSV/JSON/markdown + analytics + dashboard |

## Configuration

Edit `config.json` to customize:
- **Products**: asset criticality, business impact, exposure, data sensitivity
- **Scoring weights**: CVSS, EPSS, KEV, exploit, asset, exposure, data, patch
- **SLA bands**: P1 (24h), P2 (72h), P3 (168h), P4 (720h)
- **Filter rules**: severity floor, FP patterns, risk-accept list
- **Enrichment sources**: KEV, EPSS, NVD, Exploit-DB

## AI Enrichment (3-Tier Hybrid, All Free)

Three tiers of AI, all using open-source models, all free:

| Tier | Speed | Quality | Privacy | Setup |
|------|-------|---------|---------|-------|
| **1. Groq** | <1s | 70B params | Cloud | Free signup at console.groq.com |
| **2. Ollama** | 2-5s | 1.5B params | Local | `ollama pull qwen2:1.5b` |
| **3. Rule-based** | Instant | Heuristic | Local | Always runs |

**Cascade**: Groq -> Ollama -> Rule-based. Best available tier is used automatically.

Configure API keys in `.env` (the `setup_and_run.sh` script prompts for them):

```bash
# .env file
GROQ_API_KEY=gsk_...      # free at console.groq.com
NVD_API_KEY=              # optional, increases NVD rate limit
GITHUB_TOKEN=             # optional, auto-creates Issues for P1/P2
GITHUB_REPOSITORY=you/repo
```

## CLI Flags

```bash
# NOTE: no comments after trailing "\" — bash continuations must be clean.
python -m pipeline.run \
  --reports scan_reports/ \
  --config config.json \
  --out outputs/
```

| Flag | Effect |
|------|--------|
| `--products juice_shop,nodegoat` | Filter to specific products |
| `--skip-enrich` | Skip KEV/EPSS/NVD lookups (offline) |
| `--skip-ai` | Skip AI enrichment entirely |
| `--searchsploit` | Use Exploit-DB CSV |
| `--groq-api-key gsk_...` | Use Groq cloud AI |
| `--ollama-model qwen2:1.5b` | Use local Ollama AI |

## Remote Scanning

Scan vulnerable apps running on **another machine** in your network while
keeping the dashboard, pipeline, and history on yours.

### Machine B (targets) checklist
1. `docker compose -f targets/docker-compose.yml up -d`
2. Open firewall inbound ports `3000`, `4000`, `8080`
3. Complete bWAPP one-time setup: browse to `http://<B-ip>:8080/install.php`
   (the preflight check refuses to scan until this is done)

> MongoDB stays bound to loopback on Machine B — NodeGoat reaches it over the
> compose network. Nothing else needs exposing.

### Machine A (scanner + dashboard)

```bash
# Local mode — exactly as before (Trivy included)
bash setup_and_run.sh

# Remote mode — all products on 192.168.1.50 (ports kept from config.json).
# Deploys are skipped and Trivy is auto-dropped: it can only inspect images
# in THIS machine's Docker daemon / registries, never another PC's.
bash setup_and_run.sh --target 192.168.1.50

# Per-product overrides (repeatable, mixable with bare form)
bash setup_and_run.sh --target bwapp=192.168.1.1:8080 --products bwapp

# Restrict scanners explicitly (nuclei,zap,trivy,wapiti)
bash setup_and_run.sh --target 192.168.1.50 --scanners nuclei,zap,wapiti

# Process existing reports only (dashboard + pipeline + ticketing, no scans)
bash setup_and_run.sh --skip-scan
```

Override rules: bare host moves every selected product keeping its configured
port; `product=host[:port]` wins for that product; a port in the override
beats the configured port. Unknown product names are rejected up-front.

### History & lifecycle across runs

| Path | Behavior |
|------|----------|
| `outputs/lifecycle.db` | NEVER cleared. Tracks status transitions per finding |
| `outputs/history.db` | NEVER cleared. One row per run/product — powers risk-over-time |
| `scan_reports/archive/<timestamp>/` | Previous raw reports archived (last 10 kept) |
| `outputs/ranked_findings.*`, dashboard | Current-state snapshot, regenerated each run |

Every scan appends a **sighting** row per live finding (timestamp + score
snapshot), so the lifecycle tab shows "seen Aug 20 · Aug 22 · Aug 24" even
when scores change between runs. Recurrence never changes a score — only new
threat intel does.

### Auto-ticketing policy

Tickets fire only for findings above the threshold whose tracked lifecycle
status is `open` **and** which have no ticket yet. An open ticket is never
duplicated by rescans; if a fixed finding reappears, the existing issue gets
a "reintroduced" comment instead. Ticket URLs are remembered in
`lifecycle.db` (`issue_url`), making dedup exact rather than title-based.

## License

MIT

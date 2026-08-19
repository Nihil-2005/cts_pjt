# 🔒 DevSecOps Risk Intelligence Pipeline

**An 8-stage vulnerability processing pipeline that ingests raw scanner output and produces prioritized, explainable risk intelligence.**

> Consolidates two fragmented codebases (v1 DefectDojo + v2 custom) into a single, production-ready system.

## 🏗️ Architecture

```
devsecops-pipeline/
├── .github/workflows/devsecops-pipeline.yml   ← CI/CD: deploy → scan → process → ticket
├── targets/docker-compose.yml                 ← 3 vulnerable apps (NodeGoat, Juice Shop, bWAPP)
├── scanners/                                  ← Scanner wrapper scripts
├── pipeline/                                  ← THE 8-STAGE BRAIN
│   ├── 01_normalize.py     Stage 1: Parse raw scanner reports → unified Finding schema
│   ├── 02_dedup.py         Stage 2: Cross-scanner deduplication (CVE / endpoint+CWE / title)
│   ├── 03_filter.py        Stage 3: Auditable quarantine (severity / FP / risk-accept)
│   ├── 04_enrich.py        Stage 4: Threat intel (KEV, EPSS, NVD, Exploit-DB)
│   ├── 05_attackpath.py    Stage 5: CAPEC-inspired CWE chain mapping
│   ├── 06_score.py         Stage 6: 8-factor explainable risk scoring (0-100)
│   ├── 07_remediate.py     Stage 7: First-aid + full remediation guidance
│   ├── 08_output.py        Stage 8: Ranking, CSV/JSON/markdown, analytics
│   ├── run.py              Unified entry point
│   ├── dashboard.py        Dark-theme HTML dashboard (Chart.js + D3)
│   ├── github_tickets.py   Auto-create GitHub Issues for P1/P2 findings
│   ├── ai_enrich.py        AI-powered FP classification + remediation (Claude)
│   └── defectdojo_client.py DefectDojo integration (optional)
├── intel/                  Threat intel cache (KEV, EPSS, NVD)
├── config.json             Unified configuration
├── requirements.txt
├── Makefile                One command to rule them all
└── README.md
```

## 🚀 Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run with sample reports (offline, no Docker needed)
python -m pipeline.run \
  --reports sample_reports/ \
  --config config.json \
  --out outputs/ \
  --skip-enrich --skip-ai

# 3. Open the dashboard
open outputs/risk_dashboard.html
```

## 🐳 Full Pipeline (with live scanning)

```bash
# Deploy targets + run scanners + process pipeline + generate dashboard
make all

# Or step by step:
make deploy-targets     # Start 3 vulnerable apps
make run-scanners       # Run Nuclei + ZAP against targets
make run-pipeline       # Process through 8 stages
make dashboard          # Generate HTML dashboard
```

## 🧪 Run Tests

```bash
make test               # Run all tests
make test-coverage      # Run with coverage report
```

## 📊 The 8 Stages

| Stage | Module | What It Does |
|-------|--------|-------------|
| 1 | `normalize` | Parse ZAP/Nuclei/Wapiti/Trivy/Nmap/OpenVAS into unified Finding schema |
| 2 | `dedup` | Cross-scanner dedup: same CVE from 2 scanners → 1 finding |
| 3 | `filter` | Auditable quarantine: never delete, always track why |
| 4 | `enrich` | CISA KEV + FIRST.org EPSS + NVD CVSS + Exploit-DB |
| 5 | `attackpath` | CWE→CWE chain mapping (CAPEC-inspired) |
| 6 | `score` | 8-factor explainable score (CVSS 20% + EPSS 20% + KEV 25% + ...) |
| 7 | `remediate` | First-aid + full fix + scanner guidance |
| 8 | `output` | Ranked CSV/JSON/markdown + analytics + dashboard |

## 🎯 Why This Wins

| Question | Answer |
|----------|--------|
| "How automated?" | Full CI/CD: push → deploy → scan → process → ticket → notify |
| "How do you handle noise?" | 63%+ dedup + auditable quarantine (never delete) |
| "How do you prioritize?" | 8-factor explainable score (not raw CVSS) |
| "What about zero-days?" | EPSS probability + KEV feed + exploit availability |
| "Show me the full loop" | Commit → Scan → Enrich → Score → Ticket → Fix → Verify |
| "Can I run this myself?" | `make all` or GitHub Actions trigger |

## 📋 Configuration

Edit `config.json` to customize:
- **Products**: asset criticality, business impact, exposure, data sensitivity
- **Scoring weights**: CVSS, EPSS, KEV, exploit, asset, exposure, data, patch
- **SLA bands**: P1 (24h), P2 (72h), P3 (168h), P4 (720h)
- **Filter rules**: severity floor, FP patterns, risk-accept list
- **Enrichment sources**: KEV, EPSS, NVD, Exploit-DB

## 🤖 AI Enrichment (Optional)

Set `ANTHROPIC_API_KEY` to enable:
- **FP classification**: Claude rates false-positive likelihood per finding
- **Smart remediation**: Context-aware fix advice beyond static CWE tables
- **Executive brief**: 3-sentence CISO-ready summary

## 📜 License

MIT

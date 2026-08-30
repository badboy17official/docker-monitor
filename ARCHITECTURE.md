# Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      CLI (cli.py)                           │
│  audit | monitor | dashboard | report | status              │
└────────┬──────────┬──────────┬──────────┬───────────────────┘
         │          │          │          │
         ▼          ▼          ▼          ▼
┌────────────┐ ┌─────────┐ ┌────────┐ ┌──────────┐
│ audit.py   │ │monitor.py│ │dashboard│ │reports.py│
│ (parallel  │ │(runtime  │ │(Flask   │ │(JSON/HTML│
│  scanners) │ │ engine)  │ │ web UI) │ │ reports) │
└─────┬──────┘ └────┬─────┘ └───┬────┘ └──────────┘
      │             │            │
      ▼             ▼            ▼
┌─────────────────────────────────────────────────────────────┐
│                    Core Modules                             │
│                                                             │
│  ┌──────────┐ ┌──────────┐ ┌────────┐ ┌──────────────────┐ │
│  │ scanners/│ │ scoring/ │ │ cve.py │ │ db.py            │ │
│  │ trivy    │ │ risk     │ │ (OSV)  │ │ (SQLite, lazy    │ │
│  │ dockle   │ │ anomaly  │ │        │ │  init, pooling)  │ │
│  │ syft     │ │ ml (opt) │ │        │ │                  │ │
│  │ grype    │ │          │ │        │ │                  │ │
│  └──────────┘ └──────────┘ └────────┘ └──────────────────┘ │
│                                                             │
│  ┌──────────┐ ┌──────────────────────────────────────────┐  │
│  │alerts.py │ │ config.py (YAML + env var overrides)     │  │
│  │(webhook) │ │                                          │  │
│  └──────────┘ └──────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Data Flow

```
1. Audit Flow:
   CLI → audit.py → [trivy, dockle, syft, grype] (parallel)
                   → CVE deduplication (trivy ∪ grype)
                   → risk scoring (RuleBasedRiskScorer)
                   → cloud enrichment (cve.py → OSV.dev)
                   → alert check (alerts.py)
                   → report generation (reports.py)
                   → db persistence (db.py)

2. Monitor Flow:
   CLI → monitor.py → Docker API (poll containers)
                    → metrics collection (CPU, mem, net, PIDs)
                    → vuln scanning (Trivy, cached 15min)
                    → anomaly detection (rule + z-score + EWMA + ML)
                    → alert check
                    → export (runtime/*.json + db)

3. Dashboard Flow:
   CLI → dashboard/app.py → Flask (auth + rate limiting)
                          → reads reports/ and runtime/
                          → triggers audit/monitor on-demand
                          → container management (start/stop/restart)
```

## Scoring System

### Static Risk Score (audit)
- Sigmoid-based weighted scoring: `σ(w·features + bias) × 100`
- Features: critical, high, medium, low CVEs + Dockle fatal/warn + engine coverage

### Runtime Anomaly Score (monitor)
- **Rule-based**: Hard thresholds (CPU>90%, mem>85%, PIDs>250, net>300MB)
- **Z-score**: Statistical deviation from rolling window baseline
- **EWMA**: Exponentially weighted moving average spike detection
- **ML** (optional): IsolationForest anomaly probability
- **Ensemble**: Weighted combination of all detectors

## Security

- All dashboard endpoints require authentication (session + Basic Auth)
- Rate limiting on login (10/min) and all endpoints (200/day)
- Random secret key generated if `SECRET_KEY` not set
- Path traversal protection on report downloads
- Container name validation against regex whitelist
- No hardcoded secrets in production code

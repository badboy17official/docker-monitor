# Docker Monitor v2.8.0

Container Security Audit & Runtime Threat Monitoring Platform.

## What It Does

- **Multi-engine security audit**: Runs Trivy, Dockle, Syft, and Grype in parallel against Docker images
- **CVE deduplication**: Unifies CVE findings across scanners by ID (no double-counting)
- **Runtime threat monitoring**: Continuously monitors running containers for anomalous behavior
- **Ensemble anomaly detection**: Combines rule-based thresholds, z-score analysis, and EWMA spike detection
- **Optional ML model**: IsolationForest-based anomaly scoring (install with `pip install docker-monitor[ml]`)
- **Web dashboard**: Real-time visualization with container management controls
- **CLI interface**: Single entry point with subcommands for all operations
- **Cloud CVE enrichment**: Fetches severity data from OSV.dev API
- **Webhook alerting**: Sends alerts when threat scores exceed thresholds

## Quick Start

```bash
# Install
pip install -e .

# Check tool status
docker-monitor status

# Run a security audit
docker-monitor audit

# Start runtime monitoring (continuous)
docker-monitor monitor

# Launch the web dashboard
DASHBOARD_AUTH_USER=admin DASHBOARD_AUTH_PASSWORD=secret docker-monitor dashboard
```

## CLI Commands

```
docker-monitor audit              # Run multi-engine security audit
docker-monitor monitor [--once]   # Runtime threat monitoring
docker-monitor dashboard          # Launch web dashboard
docker-monitor report [--format]  # Generate report from latest audit
docker-monitor status             # Check tool availability
```

## Configuration

All settings in `config.yaml`. Environment variables override config values:

| Env Variable | Description |
|---|---|
| `DASHBOARD_AUTH_USER` | Dashboard login username |
| `DASHBOARD_AUTH_PASSWORD` | Dashboard login password |
| `DASHBOARD_ALLOW_INSECURE` | Set `true` to disable auth (local dev only) |
| `SECRET_KEY` | Flask session secret key |

## Architecture

```
docker_monitor/
├── cli.py          # Click CLI with subcommands
├── config.py       # Config loader with validation
├── db.py           # SQLite persistence (lazy init, connection pooling)
├── audit.py        # Parallel multi-engine scanner orchestrator
├── monitor.py      # Runtime threat monitoring engine
├── scoring/
│   ├── risk.py     # Static scan risk scorer
│   ├── anomaly.py  # Runtime anomaly detectors (rule + z-score + EWMA)
│   └── ml.py       # Optional IsolationForest ML model
├── scanners/
│   ├── trivy.py    # CVE vulnerability scanner
│   ├── dockle.py   # Container image linter
│   ├── syft.py     # SBOM generator
│   └── grype.py    # CVE vulnerability scanner
├── cve.py          # OSV.dev cloud CVE enrichment
├── alerts.py       # Webhook alert manager
├── reports.py      # JSON/HTML report generator
└── dashboard/
    ├── app.py      # Flask web application
    ├── auth.py     # Session + Basic auth
    └── templates/  # Jinja2 + Tailwind CSS templates
```

## Deployment

### Docker Compose

```bash
DASHBOARD_AUTH_USER=admin DASHBOARD_AUTH_PASSWORD=secret docker compose up
```

### Kubernetes

```bash
kubectl apply -f k8s/deployment-hardened.yaml
```

## Development

```bash
pip install -e ".[dev,ml]"
pytest tests/ -v
ruff check docker_monitor/
```

## License

MIT

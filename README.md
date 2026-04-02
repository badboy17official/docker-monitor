# DevSecOps Platform — Production-Grade Container Security

> **Architecture**: Microservices + Event-driven async pipeline  
> **Stack**: FastAPI · PostgreSQL · Elasticsearch · Redis/Kafka · Prometheus · React  
> **Status**: Phase 1 Foundation (Auth + DB + Local Env)

## Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.11+
- Node.js 18+ (for frontend)

### Setup Local Environment

1. **Clone and configure**
   ```bash
   git clone <repo>
   cd devsecops-platform
   cp .env.example .env
   # Edit .env with your secrets
   ```

2. **Start the full stack**
   ```bash
   docker-compose up -d
   ```

3. **Run migrations**
   ```bash
   ./scripts/bootstrap.sh
   ```

4. **Verify services are healthy**
   ```bash
   curl http://localhost:8000/health
   ```

## Services Overview

| Service | Port | Purpose |
|---------|------|---------|
| API Gateway | 8000 | Reverse proxy + JWT validation |
| Auth Service | 8001 | User management + Token issuing |
| Scan Orchestrator | 8002 | Scan workflow coordination |
| AI Engine | 8003 | Risk scoring + CVE enrichment |
| Report Service | 8004 | PDF/HTML report generation |
| Dashboard Backend | 8005 | Analytics & aggregation |
| Frontend | 3000 | React UI |
| PostgreSQL | 5432 | Relational data |
| Redis | 6379 | Queues + caching |
| Elasticsearch | 9200 | Full-text search |
| Prometheus | 9090 | Metrics collection |
| Grafana | 3001 | Dashboards |

## Architecture

```
┌─────────────────────────────────────────────────┐
│           React Frontend (3000)                  │
└────────────────────┬────────────────────────────┘
                     │
┌────────────────────┴────────────────────────────┐
│     API Gateway (8000)                          │
│     • JWT validation middleware                 │
│     • Rate limiting                             │
│     • Request/Response logging                  │
└────────┬──────────────────────────────┬─────────┘
         │                              │
    ┌────▼────┐    ┌──────────────┐   ┌▼────────────┐
    │  Auth   │    │ Scan         │   │ Report      │
    │ Service │    │ Orchestrator │   │ Service     │
    │ (8001)  │    │ (8002)       │   │ (8004)      │
    └────┬────┘    └──────┬───────┘   └┬────────────┘
         │                │            │
    ┌────┴────────────────┴────────────┴─────┐
    │     Message Queue (Redis/Kafka)       │
    │  queue:trivy, queue:dockle, etc       │
    └────┬────────────────────────────┬─────┘
         │                            │
    ┌────▼──────┐  ┌────────────┐ ┌──▼────────┐
    │   Trivy   │  │  Dockle    │ │   Syft/   │
    │  Worker   │  │  Worker    │ │  Grype    │
    └───────────┘  └────────────┘ └───────────┘
         │              │              │
    ┌────┴──────────────┴──────────────┴─────┐
    │    PostgreSQL + Elasticsearch          │
    │  • Vulnerability records               │
    │  • Scan history & metadata             │
    │  • Full-text search indices            │
    └────────────────────────────────────────┘
```

## Database Schema

**Relational (PostgreSQL)**
- Users + Projects + Scans metadata
- Vulnerability + Misconfig + SBOM records
- Refresh tokens (JWT blacklist)

**Search (Elasticsearch)**
- Indexed scan results for full-text search
- Time-series metrics

## API Overview

### Public Endpoints (no auth required)
- `POST /auth/register` — Create account
- `POST /auth/login` — Get JWT pair
- `GET /health` — Service health

### Protected Endpoints (Bearer token required)
- `POST /scans` — Trigger scan (202 Accepted)
- `GET /scans/:id` — Query scan status + results
- `GET /scans/:id/vulnerabilities` — Paginated vulns
- `GET /dashboard/summary` — Aggregated statistics
- `POST /reports` —Generate HTML/JSON report

See [API_REFERENCE.md](./docs/API_REFERENCE.md) for full details.

## Phases

1. ✅ **Phase 1: Foundation** — Auth + DB + Local stack
2. ⏳ **Phase 2: Scan Pipeline** — Workers + queue + result consumer
3. ⏳ **Phase 3: AI + Reports** — Risk scoring + report generation  
4. ⏳ **Phase 4: Runtime Monitor** — Container metrics + anomalies
5. ⏳ **Phase 5: Dashboard** — React frontend + analytics
6. ⏳ **Phase 6: Production** — K8s + CI/CD + hardening

## Development

### Running Tests
```bash
pytest services/auth-service/tests/ -v
```

### Linting
```bash
black . && isort . && pylint services/
```

### Building Images Locally
```bash
docker build -t devsecops/auth-service:latest services/auth-service/
```

## Security

- All inter-service traffic on isolated Docker network
- JWT tokens: 15-min expiry (short-lived)
- Bcrypt password hashing (cost ≥ 12)
- Token refresh rotation (old token invalidated)
- Input validation on all API endpoints
- SQL: parameterized queries only (SQLAlchemy ORM)

## Monitoring

- **Prometheus** scrapes metrics from all services (port 9090)
- **Grafana** dashboards (port 3001)
- **Structured JSON logging** with request_id tracing

## Support

- 📖 [Documentation](./docs)
- 🐛 [Issue Tracker](https://github.com/yourorg/devsecops/issues)
- 💬 [Discussions](https://github.com/yourorg/devsecops/discussions)

## License

MIT

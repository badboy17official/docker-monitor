# DevSecOps Platform — Implementation Guide

## Quick Start (5 minutes)

### 1. Clone and Configure
```bash
cd devsecops-platform
cp .env.example .env
# Edit .env with your secrets
```

### 2. Start Services
```bash
# Start docker-compose stack
docker-compose -f infrastructure/docker/docker-compose.yml up -d

# Wait for services to be healthy
docker-compose -f infrastructure/docker/docker-compose.yml ps

# Run migrations
bash scripts/bootstrap.sh
```

### 3. Verify Installation
```bash
# Check all services healthy
curl http://localhost:8000/health

# Access services
- API Gateway:      http://localhost:8000
- Dashboard:        http://localhost:3000
- Prometheus:       http://localhost:9090
- Grafana:          http://localhost:3001 (admin/admin)
```

---

## Phase 1 — Foundation ✅ COMPLETE

**Deliverables:**
- [x] Database schema (PostgreSQL)
- [x] Auth Service (register, login, JWT refresh, logout)
- [x] API Gateway (middleware, rate limiting, request ID)
- [x] Local docker-compose stack
- [x] Bootstrap script

**Exit Criteria:**
```bash
# Test auth flow
curl -X POST http://localhost:8001/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@devsecops.local","password":"Test1234!","name":"Test User"}'

# Should return 201 with user object
```

---

## Phase 2 — Scan Pipeline (In Progress)

### Deliverables to Implement

1. **Scan Orchestrator Service**
   - `POST /scans` — trigger scan, create jobs
   - `GET /scans/:id` — get scan status
   - Message queue integration (Redis)

2. **Scanner Workers** ✅ COMPLETE
   - [x] Base worker class
   - [x] Trivy worker
   - [x] Dockle worker
   - [ ] Syft worker (SBOM generation)
   - [ ] Grype worker (deduplication)

3. **Result Consumer**
   - Consume results queue
   - Persist to PostgreSQL
   - Index to Elasticsearch

### Implementation Checkpoint

```python
# Example: Trigger a scan
curl -X POST http://localhost:8002/scans \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "project_id": "uuid",
    "target_image": "alpine:3.18",
    "target_type": "image",
    "worker_types": ["trivy", "dockle"]
  }'

# Response 202: scan queued, jobs dispatched
# Check status: GET /scans/:id
```

---

## Phase 3 — AI + Reports

### Services to Build

1. **AI Engine** ✅ COMPLETE (Core logic)
   - [x] Risk scorer
   - [x] CVE enricher (EPSS + KEV)
   - [ ] Scoring endpoint
   - [ ] Database integration

2. **Report Service**
   - [ ] HTML report template (Jinja2)
   - [ ] JSON report generator
   - [ ] PDF export (optional)
   - [ ] Download endpoint

### Key Features

- Risk scores computed after all scan jobs complete
- EPSS + KEV data cached in Redis (24h + 6h TTL)
- Score range: 0-100 (weighted heuristic)

---

## Phase 4 — Runtime Monitor

### Services to Build

1. **Runtime Monitor** ✅ CORE (Docker stats collection)
   - [x] Docker stats collector (15s polling)
   - [x] Anomaly detector (z-score method)
   - [ ] Alert publisher (to database)
   - [ ] Alert API endpoints

### How It Works

```
Docker Container → Stats Reporter → Redis Stream
                                        ↓
                              Anomaly Detector
                                        ↓
                              Alert if z > 3σ
                                        ↓
                         Store in runtime_alerts table
```

---

## Phase 5 — Dashboard + Frontend

### React Components

- Dashboard.tsx (summary, stats, charts)
- Scans.tsx (list, filtering, trigger)
- Reports.tsx (download generated reports)
- Alerts.tsx (runtime alerts + acknowledgment)

### Backend Aggregation

```python
# GET /dashboard/summary
{
  "total_scans_30d": 47,
  "open_critical_vulns": 12,
  "mean_risk_score": 61.3,
  "top_vulnerable_images": [...],
  "recent_alerts": [...],
  "scan_trend": [...]
}
```

---

## Phase 6 — Production Hardening

### Kubernetes Deployment

```bash
# Build images with hardened base layers
docker build -t myregistry/devsecops/api-gateway:v1.0 services/api-gateway/

# Deploy to K8s
kubectl apply -f infrastructure/kubernetes/base/
kubectl apply -f infrastructure/kubernetes/overlays/prod/
```

### CI/CD Pipeline

```yaml
# GitHub Actions (pipelines/github-actions/ci.yml)
- Test (pytest, linting)
- Scan images (trivy)
- Build images
- Push to registry
- Deploy to staging
- Run integration tests
- Deploy to production
```

---

## Testing

### Unit Tests

```bash
# Auth Service
pytest services/auth-service/tests/ -v

# AI Engine (risk scoring)
pytest services/ai-engine/tests/ -v
```

### Integration Tests

```bash
# Full scan workflow
pytest tests/integration/test_scan_workflow.py -v
```

### Load Testing

```bash
# ApacheBench
ab -n 1000 -c 10 http://localhost:8000/health

# k6
k6 run tests/load/scan_trigger.js
```

---

## Monitoring & Observability

### Prometheus Metrics

- Request rate (per service)
- Error rate (by status code)
- Scan duration (p50, p95, p99)
- Queue depth (Redis)
- Database connection pool

### Grafana Dashboards

- Service health overview
- Request SLA monitoring
- Resource utilization
- Scan performance trends

### Structured Logging

All services emit JSON logs with:
- `request_id` (for tracing)
- `user_id` (for audit)
- `service` (originating microservice)
- `level` (INFO, ERROR, etc.)

```json
{
  "timestamp": "2025-01-15T10:30:00Z",
  "request_id": "req-abc123",
  "user_id": "user-xyz",
  "service": "scan-orchestrator",
  "action": "scan.triggered",
  "target_image": "nginx:1.25-alpine",
  "level": "INFO"
}
```

---

## Troubleshooting

### Service Won't Start

```bash
# Check logs
docker-compose logs <service-name>

# Verify database connectivity
docker-compose exec postgres psql -U devsecops -d devsecops -c "SELECT 1"

# Verify Redis connectivity
docker-compose exec redis redis-cli ping
```

### Scans Not Processing

```bash
# Check queue depth
redis-cli LLEN queue:trivy
redis-cli LLEN queue:results

# Check worker logs
docker logs devsecops-trivy-worker-1

# Verify image accessible
docker pull alpine:3.18
```

### High Memory Usage

- Increase trivy cache TTL or clear: `rm -rf /tmp/trivy-cache/*`
- Adjust Elasticsearch JVM heap: `ES_JAVA_OPTS=-Xms1g -Xmx1g`
- Review running scans: `GET /scans`

---

## Next Steps

1. **Implement Syft + Grype workers** for SBOM generation
2. **Build Report Service** with Jinja2 templates
3. **Create React Dashboard** with Zustand state management
4. **Deploy to EKS** with Terraform
5. **Enable OIDC authentication** (OAuth2 integration)
6. **Setup centralized logging** (ELK stack)

---

## Support & Documentation

- Architecture Diagram: [ARCHITECTURE.md](./ARCHITECTURE.md)
- Security Checklist: [SECURITY_HARDENING.md](./docs/SECURITY_HARDENING.md)
- API Reference: [API_REFERENCE.md](./docs/API_REFERENCE.md)
- Contributing: [CONTRIBUTING.md](./CONTRIBUTING.md)

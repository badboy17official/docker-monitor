# DevSecOps Platform — Architecture Overview

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      Frontend (React)                            │
│                    Port 3000 · 3 Replicas                        │
└──────────────────────────┬──────────────────────────────────────┘
                           │
┌──────────────────────────┴──────────────────────────────────────┐
│        API Gateway (FastAPI)  —  Central Entry Point             │
│  Port 8000 · 3 Replicas · JWT Auth + Rate Limiting + TLS        │
│  • Request ID injection (tracing)                               │
│  • Middleware: auth, rate limit, request logging                │
│  • Routes:  /scans, /reports, /dashboard, /alerts               │
└──────────────────────────┬──────────────────────────────────────┘
         │                 │                 │                 │
    ┌────▼────┐    ┌──────▼──┐         ┌────▼────┐         ┌─▼────┐
    │  Auth   │    │  Scan   │         │ Report  │         │ AI    │
    │Service  │    │Orchestrator       │Service  │         │Engine │
    │(8001)   │    │(8002)            │(8004)   │         │(8003) │
    │         │    │         │         │         │         │       │
    └────┬────┘    │    ┌────┴─┐      └─────────┘         └───────┘
         │         │    │      │
    ┌────▼─────────┼────▼──────▼──────────┐
    │   Message Queue (Redis/Kafka)       │
    │ ├─ queue:trivy                      │
    │ ├─ queue:dockle                     │
    │ ├─ queue:syft                       │
    │ ├─ queue:grype                      │
    │ ├─ queue:results                    │
    │ └─ stream:container_metrics        │
    └────┬──────────────────────────────┬─┘
         │                              │
    ┌────▼──────────┐          ┌────────▼──────┐
    │ Scanner Workers           │Runtime Monitor │
    │ • Trivy (2x)  │          │ • Collector    │
    │ • Dockle (2x) │          │ • Anomaly Det. │
    │ • Syft        │          │ • Alert Publisher
    │ • Grype       │          └────────┬──────┘
    └───────────────┘                   │
         │                              │
    ┌────▼──────────────────────────────▼──────────┐
    │  Data Layer                                   │
    │  ┌─────────────────────────────────────────┐ │
    │  │ PostgreSQL (Relational Metadata)      │ │
    │  │ • users, projects, scans              │ │
    │  │ • vulnerabilities, misconfigs, SBOM   │ │
    │  │ • refresh_tokens, audit_log           │ │
    │  └─────────────────────────────────────────┘ │
    │  ┌─────────────────────────────────────────┐ │
    │  │ Elasticsearch (Full-Text Search)       │ │
    │  │ • scan-results-* indices               │ │
    │  │ • runtime-events-* indices             │ │
    │  └─────────────────────────────────────────┘ │
    │  ┌─────────────────────────────────────────┐ │
    │  │ Redis (Caching)                        │ │
    │  │ • Queue storage                        │ │
    │  │ • Rate limit counters                  │ │
    │  │ • CVE enrichment cache                 │ │
    │  └─────────────────────────────────────────┘ │
    └──────────────────────────────────────────────┘
         │
    ┌────▼──────────────────────────┐
    │  Monitoring & Observability    │
    │  ┌──────────────────────────┐ │
    │  │ Prometheus (Metrics)     │ │
    │  │ • Request rate/latency   │ │
    │  │ • Error rates            │ │
    │  │ • Scan duration (p95)    │ │
    │  │ • Queue depth            │ │
    │  └──────────────────────────┘ │
    │  ┌──────────────────────────┐ │
    │  │ Grafana (Dashboards)     │ │
    │  │ • Service health         │ │
    │  │ • SLA tracking           │ │
    │  │ • Resource usage         │ │
    │  └──────────────────────────┘ │
    │  ┌──────────────────────────┐ │
    │  │ Structured JSON Logging  │ │
    │  │ • request_id tracing     │ │
    │  │ • Audit trail            │ │
    │  │ • 30-day retention       │ │
    │  └──────────────────────────┘ │
    └────────────────────────────────┘
```

---

## Data Flow — Scan Lifecycle

### 1. Scan Trigger
```
User → API Gateway (JWT validated, rate limited)
     → Scan Orchestrator POST /scans
     → Create scan record + scan_jobs (queued)
     → Publish to Redis queues (queue:trivy, queue:dockle, etc.)
     ✓ Response 202 Accepted with job list
```

### 2. Worker Processing
```
Worker (Trivy) → Pull from queue:trivy
              → subprocess trivy image scan
              → Parse JSON output
              → Normalize to internal schema
              → Publish to queue:results
              ✓ Result: { job_id, scan_id, vulnerabilities[] }
```

### 3. Result Consumption & Persistence
```
Result Consumer → Pull from queue:results
               → Validate result schema
               → Persist to PostgreSQL:
                 • vulnerabilities table
                 • misconfigurations table
                 • sbom_components table
               → Index to Elasticsearch
               → Check if scan complete
               ✓ If all jobs done → trigger AI scoring
```

### 4. AI Enrichment & Scoring
```
AI Engine → Fetch vulnerabilities for scan
         → Batch enrich CVEs:
           • EPSS scores (api.first.org)
           • KEV status (cisa.gov)
           • Cache in Redis (24h TTL)
         → Score each vulnerability:
           • severity + cvss + epss + exploit + kev
           • Result: risk_score (0-100)
         → Aggregate scan risk score
         → Update scans.risk_score in PostgreSQL
         ✓ Scan complete, ready for viewing
```

### 5. Report Generation
```
User → Report Service POST /reports
     → Query vulnerabilities from PostgreSQL
     → Render Jinja2 template (HTML/PDF)
     → Store to S3 (storage_key)
     → Return report_id + download URL
     ✓ User downloads report
```

---

## Key Design Decisions

### 1. Async Worker Pattern
- **Why**: Horizontal scaling (multiple workers per type)
- **Implementation**: Redis queue + asyncio
- **Benefit**: Handle bursting scan load without blocking

### 2. Microservices Architecture
- **Why**: Independent scaling, isolation, technology freedom
- **Implementation**: FastAPI services with shared database
- **Benefit**: Auth hotspot can scale independently of report service

### 3. Heuristic Risk Scoring (vs ML)
- **Why**: Interpretable, no training data required, deterministic
- **Implementation**: Weighted formula (base severity + CVSS + EPSS + KEV)
- **Benefit**: Transparent to users, easy to tune

### 4. PostgreSQL + Elasticsearch Hybrid
- **Why**: Strong ACID for metadata, full-text search for vulns
- **Implementation**: Write-through (Postgres → ES sync in result consumer)
- **Benefit**: Dual-model flexibility, compliance audit trail

### 5. Z-Score Anomaly Detection
- **Why**: Unsupervised, no baseline training, works for spikes
- **Implementation**: Sliding window (20 samples) + 3σ threshold
- **Benefit**: Detects unusual container behavior in real-time

---

## Deployment Topology

### Development (Local)
```
docker-compose -f infrastructure/docker/docker-compose.yml up
```
- Single PostgreSQL instance
- Single Redis instance
- Single Elasticsearch instance
- 2x scanner workers (Trivy, Dockle)
- All services on devsecops-net bridge network

### Staging (Kubernetes)
```
kubectl apply -f infrastructure/kubernetes/overlays/dev/
```
- RDS PostgreSQL with read replicas
- ElastiCache (Redis cluster)
- Elasticsearch Service (managed)
- HPA scaling for workers (1-5 replicas)
- PodDisruptionBudget (rolling updates)

### Production (Kubernetes)
```
kubectl apply -f infrastructure/kubernetes/overlays/prod/
```
- RDS Multi-AZ PostgreSQL
- ElastiCache Redis (single node to multi-node)
- Elasticsearch Service (dedicated cluster)
- HPA scaling (3-20 replicas per service)
- Ingress with WAF + TLS termination
- Pod network policies (deny by default)
- RBAC + service accounts
- Sealed Secrets for credentials

---

## Security Layers

### Layer 1: Network
- Private VPC, security groups restrict ingress
- API Gateway only public endpoint
- Workers isolated (no inbound)
- Docker socket read-only mount

### Layer 2: Identity
- JWT tokens (RS256 production, 15-min expiry)
- Refresh token rotation (old revoked immediately)
- Bcrypt password hashing (cost 12)
- Brute force lockout (5 attempts → 15-min block)

### Layer 3: Authorization
- Role-based access control (admin, engineer, viewer)
- Project-level membership (editor, admin)
- Resource ownership checks on every endpoint

### Layer 4: Data
- SQL injection prevention (SQLAlchemy ORM)
- Command injection prevention (input validation on image refs)
- SQL parameterized queries
- Sensitive data not in logs

### Layer 5: Container
- Distroless/Alpine base images
- Non-root user
- Security context (drop all capabilities)
- Read-only root filesystem

---

## Scaling Characteristics

### Bottleneck: Scanner Workers
- **Constraint**: Single scanner tool can scan one image at a time
- **Solution**: Deploy N worker replicas per tool type
- **Configuration**: K8s HPA triggered by queue depth

### Bottleneck: PostgreSQL Connections
- **Constraint**: 100 connections by default
- **Solution**: pgBouncer connection pooling + read replicas
- **Configuration**: 50 app connections + 20 reserved

### Bottleneck: Redis Memory
- **Constraint**: Queue messages accumulate during scan bursts
- **Solution**: Increase max memory + eviction policy (allkeys-lru)
- **Configuration**: Elasticsearch index TTL (7 days)

### Non-Bottleneck: API Gateway
- **Throughput**: Stateless, automatically scales
- **Limit**: 100 req/min per user (configurable)
- **Solution**: Increase rate limit if needed

---

## Failure Modes & Recovery

| Failure | Detection | Recovery |
|---------|-----------|----------|
| Scanner worker crashes | Result consumer timeout | Auto-restart + requeue job |
| Database connection lost | SQL error | Exponential backoff + reconnect |
| Redis unavailable | BLPOP timeout | Worker logs error queue, retries |
| Elasticsearch down | Index error | Fail gracefully, continue w/ Postgres |
| Scanner timeout | 300s elapsed | Kill process, mark job failed |

---

## Next Generation Roadmap

1. **Machine Learning Scoring** (v2.0)
   - Historical scanning data → risk prediction model
   - Package vulnerability lifecycle modeling

2. **Compliance Reporting** (v2.0)
   - PCI-DSS, HIPAA, SOC 2 compliance checks
   - Automated attestation & policy enforcement

3. **Supply Chain Assistant**  (v2.0)
   - SBOM comparison across builds
   - License compliance tracking

4. **Integration Hub** (v2.0)
   - Kubernetes admission controller
   - Docker registry webhooks
   - GitHub/GitLab push triggers

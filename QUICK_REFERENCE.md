# DevSecOps Platform — Quick Reference Card

## 📋 Service Ports & URLs

| Service | Port | URL | Purpose |
|---------|------|-----|---------|
| **API Gateway** | 8000 | `http://localhost:8000` | Central entry point (protected) |
| **Auth Service** | 8001 | `http://localhost:8001` | User registration + JWT tokens |
| **Scan Orchestrator** | 8002 | `http://localhost:8002` | Scan job coordination |
| **AI Engine** | 8003 | `http://localhost:8003` | Risk scoring + CVE enrichment |
| **Report Service** | 8004 | `http://localhost:8004` | Report generation |
| **Dashboard Backend** | 8005 | `http://localhost:8005` | Analytics aggregation |
| **Frontend** | 3000 | `http://localhost:3000` | React UI |
| **PostgreSQL** | 5432 | `localhost:5432` | Database |
| **Redis** | 6379 | `localhost:6379` | Queue + cache |
| **Elasticsearch** | 9200 | `http://localhost:9200` | Full-text search |
| **Prometheus** | 9090 | `http://localhost:9090` | Metrics |
| **Grafana** | 3001 | `http://localhost:3001` | Dashboards (admin/admin) |

---

## 🔑 Essential API Endpoints

### Authentication (No JWT required)

```bash
# Register
POST /auth/register
{
  "email": "user@example.com",
  "password": "StrongP@ss1",
  "name": "John Doe"
}

# Login
POST /auth/login
{
  "email": "user@example.com",
  "password": "StrongP@ss1"
}
→ { "access_token": "...", "refresh_token": "..." }

# Logout
POST /auth/logout
Header: Authorization: Bearer <token>

# Refresh Token
POST /auth/refresh
{ "refresh_token": "..." }
```

### Protected Endpoints (Require JWT)

```bash
# Get current user profile
GET /auth/me
Header: Authorization: Bearer <access_token>

# Change password
POST /auth/change-password
{ "old_password": "...", "new_password": "..." }

# Create scan (202 Accepted)
POST /scans
{
  "project_id": "uuid",
  "target_image": "alpine:3.18",
  "worker_types": ["trivy", "dockle"]
}

# Get scan status
GET /scans/:id

# List vulnerabilities
GET /scans/:id/vulnerabilities?severity=CRITICAL,HIGH&page=1

# Download report
GET /reports/:id/download

# Get alerts
GET /alerts?project_id=uuid&acknowledged=false

# Acknowledge alert
PATCH /alerts/:id/acknowledge

# Dashboard summary
GET /dashboard/summary

# Health check (no auth)
GET /health
```

---

## 🐳 Docker Compose Commands

```bash
# Start all services
docker-compose -f infrastructure/docker/docker-compose.yml up -d

# View logs
docker-compose logs -f api-gateway
docker-compose logs -f auth-service

# Check service health
docker-compose ps

# Stop all services
docker-compose down

# View database
docker-compose exec postgres psql -U devsecops -d devsecops

# Clear all data
docker-compose down -v

# Scale trivy workers
docker-compose up -d --scale trivy-worker-1=5
```

---

## 🔐 Default Credentials

| Service | Username | Password | Notes |
|---------|----------|----------|-------|
| **Admin User** | admin@devsecops.local | ChangeMe123! | Created by bootstrap.sh |
| **Grafana** | admin | admin | Change on first login |
| **PostgreSQL** | devsecops | (from .env) | Requires host access |

---

## 🧪 Common Test Commands

```bash
# Health check (all services)
curl http://localhost:8000/health

# Register test user
curl -X POST http://localhost:8001/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"Test1234!","name":"Test"}'

# Get JWT token
TOKEN=$(curl -s -X POST http://localhost:8001/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"Test1234!"}' | jq -r '.access_token')
echo $TOKEN

# Call protected endpoint with JWT
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/dashboard/summary

# Database query
docker-compose exec postgres psql -U devsecops -d devsecops -c "SELECT COUNT(*) FROM users;"

# Redis cache check
docker-compose exec redis redis-cli KEYS "enrich:*" | head -10

# View queue depth
docker-compose exec redis redis-cli LLEN "queue:trivy"
```

---

## 📊 Database Quick Reference

```sql
-- List all tables
\dt

-- Users
SELECT id, email, role, is_active FROM users;

-- Create admin user (if needed)
INSERT INTO users (email, password_hash, name, role)
VALUES ('admin@test.local', '$2b$12$...bcrypt...', 'Admin', 'admin');

-- View scans
SELECT id, target_image, status, risk_score FROM scans ORDER BY created_at DESC;

-- View vulnerabilities for scan
SELECT cve_id, severity, cvss_score, ai_risk_score 
FROM vulnerabilities 
WHERE scan_id = 'uuid'
ORDER BY ai_risk_score DESC;

-- View runtime alerts
SELECT container_id, alert_type, severity, message
FROM runtime_alerts
WHERE acknowledged = false
ORDER BY triggered_at DESC;

-- View audit log
SELECT user_id, action, resource_type, created_at
FROM audit_log
WHERE user_id = 'uuid'
ORDER BY created_at DESC LIMIT 50;
```

---

## 🛠️ Troubleshooting

### Services Won't Start

```bash
# Check logs
docker-compose logs <service-name>

# Verify database is ready
docker-compose exec postgres pg_isready

# Verify Redis
docker-compose exec redis redis-cli ping

# Check ports in use
netstat -ano | findstr :8000  # Windows
lsof -i :8000               # macOS/Linux
```

### Scans Not Processing

```bash
# Check queue depth
docker-compose exec redis redis-cli LLEN "queue:trivy"

# View worker logs
docker-compose logs trivy-worker-1

# Check results queue
docker-compose exec redis redis-cli LLEN "queue:results"

# Check job status in DB
SELECT * FROM scan_jobs WHERE scan_id = 'uuid';
```

### High Memory/CPU

```bash
# Check container resource usage
docker stats

# Clear trivy cache
docker-compose exec trivy-worker-1 rm -rf /tmp/trivy-cache/*

# Scale down workers
docker-compose down && docker-compose up -d --scale trivy-worker-1=1
```

---

## 📈 Monitoring Commands

```bash
# View Prometheus scrape targets
curl http://localhost:9090/api/v1/targets | jq .

# Query metric (request count)
curl 'http://localhost:9090/api/v1/query?query=http_requests_total'

# Export metrics from service
curl http://localhost:8000/metrics

# View Redis memory
docker-compose exec redis redis-cli INFO memory

# View Elasticsearch cluster health
curl http://localhost:9200/_cluster/health | jq .

# List indices
curl http://localhost:9200/_cat/indices
```

---

## 🚀 Deployment Checklists

### Pre-Production

- [ ] All `.env` variables configured (secrets from Vault)
- [ ] Database replication enabled (RDS Multi-AZ)
- [ ] Redis cluster mode enabled
- [ ] TLS certificates provisioned
- [ ] Network policies configured
- [ ] Pod security policies enforced
- [ ] RBAC rules defined
- [ ] Monitoring alerts configured
- [ ] Backup strategy implemented
- [ ] Disaster recovery tested

### Post-Deployment

- [ ] Health checks passing
- [ ] Logs aggregated (ELK stack)
- [ ] Metrics visible in Grafana
- [ ] Alert rules firing correctly
- [ ] Load testing completed (p95 < 500ms)
- [ ] Security audit signed off
- [ ] Runbooks reviewed
- [ ] Incident response team trained
- [ ] 24-hour stability verified

---

## 📚 Key Documentation

- `README.md` — Getting started
- `ARCHITECTURE.md` — System design
- `IMPLEMENTATION_GUIDE.md` — Build phases  
- `docs/SECURITY_HARDENING.md` — Security checklist
- `IMPLEMENTATION_COMPLETE.md` — Full summary

---

## 🆘 Support Matrix

| Issue | Solution | Docs |
|-------|----------|------|
| Auth fails | Check JWT secret, token expiry | [Auth Service](./services/auth-service/README.md) |
| Scans queue up | Check worker logs, scale workers | [Workers](./services/scanner-workers/README.md) |
| Slow queries | Add indexes, review query plans | [SQL Schema](./sql/schema.sql) |
| Memory spike | Analyze metrics, clear caches | [Monitoring](./IMPLEMENTATION_GUIDE.md) |
| Deploy issues | Check K8s events, pod logs | [K8s Setup](./infrastructure/kubernetes/README.md) |

---

**Last Updated**: 2025-01-15  
**Version**: 1.0.0  
**Maintainer**: Your Team

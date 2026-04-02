# Security Hardening Checklist

## Network Security

- [ ] All inter-service traffic on private Docker network
- [ ] Only API Gateway exposed publicly (port 8000)
- [ ] Worker containers have no inbound ports
- [ ] Docker socket mounted read-only: `/var/run/docker.sock:ro`
- [ ] Network policies restrict egress (except to required services)
- [ ] TLS termination at ingress/load balancer (production)

## Authentication & Authorization

- [ ] Passwords hashed with bcrypt (cost ≥ 12)
- [ ] JWT tokens: RS256 (production), HS256 only in dev
- [ ] Access token expiry: 15 minutes (short-lived)
- [ ] Refresh token: rotated on each use
- [ ] Refresh token hash stored in DB, not raw token
- [ ] Brute force protection: 5 failed logins → 15-min lockout
- [ ] All refresh tokens can be revoked via logout

## Input Validation

- [ ] Image reference regex validation before subprocess invocation
- [ ] All API inputs validated with Pydantic schemas
- [ ] Pagination limits capped (max `per_page: 100`)
- [ ] File download: report IDs are UUIDs (no path traversal)
- [ ] CVE IDs restricted to `[CVE-\d{4}-\d{4,}]+`

## Database Security

- [ ] All queries via SQLAlchemy ORM or parameterized raw SQL
- [ ] No string interpolation in SQL
- [ ] DB user has minimal privileges (no DROP, no pg_read_file)
- [ ] Connection pooling via pgBouncer (production)
- [ ] Connections use SSL (sslmode=require)
- [ ] Row-level security policies for multi-tenant isolation

## Secrets Management

- [ ] JWT secret ≥ 32 bytes entropy
- [ ] No secrets in source code or Docker images
- [ ] All secrets from environment variables or Vault
- [ ] Database credentials use IAM roles (AWS) or Vault
- [ ] Rotation policy: secrets rotated every 90 days
- [ ] Audit logging for all secret access

## Logging & Monitoring

- [ ] Structured JSON logging with `request_id` threading
- [ ] Log levels: INFO (default), WARNING, ERROR, CRITICAL
- [ ] Never log: passwords, tokens, API keys, PII
- [ ] Audit log for: auth events, scan triggers, alerts, report downloads
- [ ] Log retention: 30 days in Elasticsearch
- [ ] Log aggregation: ELK stack for centralized analysis

## Container Hardening

- [ ] Base layers: distroless or Alpine (minimal attack surface)
- [ ] Non-root USER in every Dockerfile
- [ ] Read-only root filesystem where possible (`fsGroup: 65534`)
- [ ] Resource limits (CPU, memory) on every container
- [ ] Security context: `runAsNonRoot: true`, `allowPrivilegeEscalation: false`
- [ ] Network policies restrict pod-to-pod communication
- [ ] Image scanning in CI/CD (trivy) — block on CRITICAL vulns

## Supply Chain Security

- [ ] Tool versions pinned (trivy, dockle, syft, grype)
- [ ] Checksum verification for binaries
- [ ] Signed commits + branch protection
- [ ] Dependency scanning (dependabot, snyk)
- [ ] SBOM generation for all builds

## API Gateway Security

- [ ] JWT validation on all protected endpoints
- [ ] Rate limiting enabled (100 req/min per user)
- [ ] CORS configured (whitelisted origins only)
- [ ] Request timeout: 30 seconds (prevent slowloris)
- [ ] Response compression disabled for sensitive data
- [ ] Security headers:
  - [ ] `Strict-Transport-Security: max-age=31536000`
  - [ ] `X-Content-Type-Options: nosniff`
  - [ ] `X-Frame-Options: DENY`
  - [ ] `Content-Security-Policy: default-src 'self'`

## Scanner Worker Security

- [ ] Docker socket mount: read-only
- [ ] No  capability grants (use default: none)
- [ ] File permissions on trivy cache: `755` (not world-writable)
- [ ] Subprocess timeouts prevent hangs (300s for trivy)
- [ ] Input validation on image references (no command injection)
- [ ] Worker processes run as non-root
- [ ] Resource limits: 2 CPU, 512MB memory per worker

## Runtime Monitoring

- [ ] Anomaly detection: z-score > 3σ triggers alert
- [ ] Metric baselines established over ≥5 samples
- [ ] Alerts stored with: container_id, alert_type, raw_payload
- [ ] Acknowledged alerts tracked with: user_id, timestamp
- [ ] Metrics exportedto Prometheus for graphing

## Incident Response

- [ ] Alert routing configured (Slack, PagerDuty, email)
- [ ] Runbook for: high CPU spike, memory exhaustion, failed scans
- [ ] Incident templates with: timeline, RCA, remediation
- [ ] Post-incident reviews: blameless, documented

## Compliance

- [ ] GDPR: delete user data on request (cascade delete)
- [ ] HIPAA: audit  trails for all data access
- [ ] SOC 2: change log & approval process
- [ ] PCI-DSS: network segmentation, secret rotation
- [ ] NIST CSF: asset inventory, baseline configs

## Testing

- [ ] Unit tests: ≥80% code coverage
- [ ] Integration tests: full scan workflow
- [ ] Security tests: SQL injection, command injection, XXE
- [ ] Load tests: 100 concurrent requests
- [ ] Failover tests: service degradation handling

## Rollout Checklist

Before production deployment:

- [ ] All security checklist items completed
- [ ] Load testing passed (p99 latency < 500ms)
- [ ] 30-day incident-free staging environment
- [ ] Security audit signed off
- [ ] Disaster recovery plan tested
- [ ] Monitoring & alerting verified
- [ ] Runbooks reviewed by ops team
- [ ] Deployment plan peer-reviewed

-- =====================================================================
-- DevSecOps Platform — PostgreSQL Schema
-- Version: 1.0.0
-- =====================================================================

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =====================================================================
-- USERS
-- =====================================================================
CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    name          TEXT,
    role          TEXT NOT NULL DEFAULT 'viewer'
                      CHECK (role IN ('admin', 'engineer', 'viewer')),
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    failed_login_attempts INT NOT NULL DEFAULT 0,
    locked_until  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_active ON users(is_active);

-- =====================================================================
-- REFRESH TOKENS (JWT blacklist + rotation)
-- =====================================================================
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked    BOOLEAN NOT NULL DEFAULT FALSE,
    issued_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_rt_user ON refresh_tokens(user_id);
CREATE INDEX idx_rt_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_rt_expires ON refresh_tokens(expires_at);

-- =====================================================================
-- PROJECTS
-- =====================================================================
CREATE TABLE IF NOT EXISTS projects (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    description TEXT,
    owner_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_projects_owner ON projects(owner_id);
CREATE INDEX idx_projects_created ON projects(created_at DESC);

CREATE TABLE IF NOT EXISTS project_members (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       TEXT NOT NULL DEFAULT 'viewer'
                   CHECK (role IN ('admin', 'engineer', 'viewer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(project_id, user_id)
);

CREATE INDEX idx_pm_project ON project_members(project_id);
CREATE INDEX idx_pm_user ON project_members(user_id);

-- =====================================================================
-- SCANS
-- =====================================================================
CREATE TABLE IF NOT EXISTS scans (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id   UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    triggered_by UUID NOT NULL REFERENCES users(id),
    target_image TEXT NOT NULL,
    target_type  TEXT NOT NULL DEFAULT 'image'
                     CHECK (target_type IN ('image', 'filesystem', 'repo')),
    status       TEXT NOT NULL DEFAULT 'queued'
                     CHECK (status IN ('queued','running','completed','failed','cancelled')),
    risk_score   NUMERIC(5,2),
    started_at   TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scans_project ON scans(project_id);
CREATE INDEX idx_scans_status ON scans(status);
CREATE INDEX idx_scans_created ON scans(created_at DESC);
CREATE INDEX idx_scans_risk ON scans(risk_score DESC NULLS LAST);

-- =====================================================================
-- SCAN JOBS (one scan → N jobs, one per worker type)
-- =====================================================================
CREATE TABLE IF NOT EXISTS scan_jobs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id      UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    worker_type  TEXT NOT NULL
                     CHECK (worker_type IN ('trivy','dockle','syft','grype')),
    status       TEXT NOT NULL DEFAULT 'queued'
                     CHECK (status IN ('queued','running','completed','failed')),
    queue_msg_id TEXT,
    error_msg    TEXT,
    started_at   TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_jobs_scan ON scan_jobs(scan_id);
CREATE INDEX idx_jobs_worker ON scan_jobs(worker_type);
CREATE INDEX idx_jobs_status ON scan_jobs(status);

-- =====================================================================
-- VULNERABILITIES (normalized CVE rows)
-- =====================================================================
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    source_worker   TEXT NOT NULL,
    cve_id          TEXT NOT NULL,
    package_name    TEXT NOT NULL,
    installed_ver   TEXT,
    fixed_ver       TEXT,
    severity        TEXT NOT NULL
                        CHECK (severity IN ('CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN')),
    cvss_score      NUMERIC(4,2),
    ai_risk_score   NUMERIC(5,2),
    epss_score      NUMERIC(6,5),
    title           TEXT,
    description     TEXT,
    references      JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vuln_scan ON vulnerabilities(scan_id);
CREATE INDEX idx_vuln_cve ON vulnerabilities(cve_id);
CREATE INDEX idx_vuln_sev ON vulnerabilities(severity);
CREATE INDEX idx_vuln_risk ON vulnerabilities(ai_risk_score DESC NULLS LAST);

-- =====================================================================
-- SBOM (Software Bill of Materials)
-- =====================================================================
CREATE TABLE IF NOT EXISTS sbom_components (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id      UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    version      TEXT,
    purl         TEXT,
    type         TEXT,
    licenses     TEXT[],
    supplier     TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sbom_scan ON sbom_components(scan_id);
CREATE INDEX idx_sbom_name ON sbom_components(name);

-- =====================================================================
-- MISCONFIGURATIONS (Dockle results)
-- =====================================================================
CREATE TABLE IF NOT EXISTS misconfigurations (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id      UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    check_id     TEXT NOT NULL,
    severity     TEXT NOT NULL,
    title        TEXT,
    description  TEXT,
    remediation  TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_misconfig_scan ON misconfigurations(scan_id);
CREATE INDEX idx_misconfig_check ON misconfigurations(check_id);

-- =====================================================================
-- REPORTS
-- =====================================================================
CREATE TABLE IF NOT EXISTS reports (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id    UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    format     TEXT NOT NULL CHECK (format IN ('json','html','pdf')),
    storage_key TEXT NOT NULL,
    file_size  BIGINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_reports_scan ON reports(scan_id);

-- =====================================================================
-- RUNTIME ALERTS
-- =====================================================================
CREATE TABLE IF NOT EXISTS runtime_alerts (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id    UUID REFERENCES projects(id) ON DELETE SET NULL,
    container_id  TEXT,
    container_name TEXT,
    alert_type    TEXT NOT NULL,
    severity      TEXT NOT NULL,
    message       TEXT NOT NULL,
    raw_payload   JSONB,
    acknowledged  BOOLEAN NOT NULL DEFAULT FALSE,
    acknowledged_by UUID REFERENCES users(id) ON DELETE SET NULL,
    acknowledged_at TIMESTAMPTZ,
    triggered_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alerts_project ON runtime_alerts(project_id);
CREATE INDEX idx_alerts_container ON runtime_alerts(container_id);
CREATE INDEX idx_alerts_time ON runtime_alerts(triggered_at DESC);
CREATE INDEX idx_alerts_ack ON runtime_alerts(acknowledged);

-- =====================================================================
-- AUDIT LOG
-- =====================================================================
CREATE TABLE IF NOT EXISTS audit_log (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID REFERENCES users(id) ON DELETE SET NULL,
    action        TEXT NOT NULL,
    resource_type TEXT,
    resource_id   UUID,
    changes       JSONB,
    ip_address    TEXT,
    user_agent    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_user ON audit_log(user_id);
CREATE INDEX idx_audit_action ON audit_log(action);
CREATE INDEX idx_audit_created ON audit_log(created_at DESC);

-- =====================================================================
-- CVE ENRICHMENT CACHE
-- =====================================================================
CREATE TABLE IF NOT EXISTS cve_enrichment_cache (
    cve_id         TEXT PRIMARY KEY,
    epss_score     NUMERIC(6,5),
    is_in_kev      BOOLEAN,
    last_updated   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_cve UNIQUE(cve_id)
);

CREATE INDEX idx_cve_updated ON cve_enrichment_cache(last_updated);

-- =====================================================================
-- FUNCTIONS & TRIGGERS
-- =====================================================================

-- Update updated_at timestamp on row modification
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply updated_at trigger to users
CREATE TRIGGER trigger_users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- Apply updated_at trigger to projects
CREATE TRIGGER trigger_projects_updated_at
BEFORE UPDATE ON projects
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- Apply updated_at trigger to scans
CREATE TRIGGER trigger_scans_updated_at
BEFORE UPDATE ON scans
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- =====================================================================
-- INITIAL DATA (Development only)
-- =====================================================================

-- Create admin user (bcrypt hash of "ChangeMe123!")
-- Hash: $2b$12$N9qo8uLOickgx2ZMRZoMyeIjZAgcg7b3XeKeUxWdeS86AGR0Kkl3G
INSERT INTO users (email, password_hash, name, role, is_active)
VALUES (
    'admin@devsecops.local',
    '$2b$12$N9qo8uLOickgx2ZMRZoMyeIjZAgcg7b3XeKeUxWdeS86AGR0Kkl3G',
    'Administrator',
    'admin',
    TRUE
)
ON CONFLICT (email) DO NOTHING;

COMMIT;

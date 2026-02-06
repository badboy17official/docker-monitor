# 🐳 Docker DUCK - Container Security Audit Platform

[![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://www.docker.com/)
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Security](https://img.shields.io/badge/Security-Audit-red?style=for-the-badge)](https://github.com/badboy17official/docker-monitor)
[![Trivy](https://img.shields.io/badge/Trivy-Scanner-blue?style=for-the-badge)](https://github.com/aquasecurity/trivy)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

> **Enterprise-grade DevSecOps platform for teaching Docker security through automated vulnerability scanning and hardening demonstrations**

An educational platform for automated container security assessment, demonstrating detection and remediation of insecure Docker configurations.

## 🎯 Project Overview

**What's New in v2.1**: Web Dashboard, CI/CD Integration, Kubernetes Deployments, Enhanced Reporting

This production-ready platform demonstrates:
- ✅ Common Docker security misconfigurations
- ✅ Container hardening best practices
- ✅ Automated security scanning (Trivy + Dockle)
- ✅ Interactive web dashboard with visualizations
- ✅ CI/CD pipeline integration (GitHub Actions + GitLab CI)
- ✅ Kubernetes security configurations
- ✅ Multi-format reporting (JSON, HTML, Text)
- ✅ Historical trend tracking

## 📁 Directory Structure

```
ContainerSecurityAudit/
├── config.yaml                    # Configuration file for audit parameters
├── audit.py                       # Main security audit automation script
├── report_generator.py            # Multi-format report generator
├── docker-compose.yml             # Multi-container orchestration
├── app/
│   ├── app.py                     # Flask web application
│   └── requirements.txt           # App dependencies
├── dashboard/                     # NEW: Web dashboard
│   ├── app.py                     # Dashboard server
│   ├── Dockerfile                 # Dashboard container
│   ├── requirements.txt           # Dashboard dependencies
│   └── templates/
│       └── dashboard.html         # Interactive UI
├── reports/                       # NEW: Generated reports
│   ├── audit_report_*.html        # HTML reports with charts
│   ├── audit_report_*.json        # JSON reports for CI/CD
│   └── audit_history.json         # Historical tracking
├── k8s/                          # NEW: Kubernetes manifests
│   ├── deployment-vulnerable.yaml # Insecure K8s config (demo)
│   └── deployment-hardened.yaml   # Production-ready K8s config
├── .github/workflows/             # NEW: GitHub Actions
│   └── security-audit.yml         # CI/CD pipeline
├── .gitlab-ci.yml                 # NEW: GitLab CI pipeline
├── Dockerfile.vuln                # Insecure Dockerfile
├── Dockerfile.hardened            # Security-hardened Dockerfile
├── .dockerignore                  # Prevents secret inclusion
├── requirements.txt               # Python dependencies
├── IMPROVEMENTS.md                # NEW: v2.0 enhancements documentation
└── UPGRADE_GUIDE.md               # NEW: Quick start for v2.0 features
```

## Vulnerabilities Demonstrated

### Vulnerable Dockerfile Issues:
1. **Unpinned base image** - Uses `python:latest` (non-deterministic)
2. **Runs as root** - Default user is root (UID 0)
3. **Hardcoded secrets** - Contains API key in environment variable
4. **Unnecessary packages** - Installs extra tools (curl, wget, vim)
5. **Excessive port exposure** - Exposes multiple unnecessary ports
6. **No .dockerignore** - May include sensitive files

### Hardened Dockerfile Fixes:
1. **Pinned minimal image** - Uses specific Python slim version
2. **Non-root user** - Creates and uses dedicated user
3. **Secret management** - Uses build args, with .dockerignore
4. **Minimal packages** - Only installs required dependencies
5. **Limited port exposure** - Only exposes necessary port (5000)
6. **Uses .dockerignore** - Prevents sensitive file inclusion

## Prerequisites

### Required:
- Docker installed and running
- Python 3.8+

### Optional (for full security scanning):
- [Trivy](https://github.com/aquasecurity/trivy) - Vulnerability scanner
- [Dockle](https://github.com/goodwithtech/dockle) - Container linter

### Installing Security Tools (Optional)

**Trivy (Windows):**
```powershell
# Using Chocolatey
choco install trivy

# Or download from: https://github.com/aquasecurity/trivy/releases
```

**Dockle (Windows):**
```powershell
# Download from: https://github.com/goodwithtech/dockle/releases
# Add to PATH after extraction
```

## 🚀 Quick Start

### Option 1: Basic Audit (Traditional)
```bash
python audit.py
```

### Option 2: Web Dashboard (NEW! ⭐)
```bash
cd dashboard
python app.py
# Open: http://localhost:8080
```

### Option 3: Docker Compose (NEW! ⭐)
```bash
docker-compose up -d

# Access services:
# - Vulnerable app: http://localhost:5001
# - Hardened app: http://localhost:5002
# - Dashboard: http://localhost:8080

docker-compose down
```

### Option 4: Kubernetes Deployment (NEW! ⭐)
```bash
# Deploy production-ready hardened version
kubectl apply -f k8s/deployment-hardened.yaml

# Verify deployment
kubectl get all -n flask-hardened
```

## 📊 New Features in v2.0

### 1. Interactive Web Dashboard
- Real-time security metrics visualization
- Historical trend analysis with charts
- Comparison tables and statistics
- REST API endpoints
- Responsive, modern UI

### 2. Enhanced Reporting
- **HTML Reports**: Beautiful reports with charts and metrics
- **JSON Reports**: Machine-readable for CI/CD integration
- **Historical Tracking**: Track improvements over 30 audits
- **Export Options**: Multiple formats for different audiences

### 3. CI/CD Integration
- **GitHub Actions**: Automated scanning on every push/PR
- **GitLab CI**: Multi-stage pipeline with deployment gates
- **Threshold Enforcement**: Fail builds if vulnerabilities exceed limits
- **PR Comments**: Automatic security summaries in pull requests

### 4. Kubernetes Production Configs
- **Hardened Manifests**: Production-ready K8s deployments
- **Security Features**: NetworkPolicy, PodSecurity, ResourceQuota
- **High Availability**: HPA, PDB, health checks
- **Best Practices**: 20+ security controls implemented

### 5. Configuration Management
- **config.yaml**: Customize thresholds, scanners, reports
- **Flexible Settings**: Enable/disable tools, set limits
- **CI/CD Ready**: Export metrics for pipeline decisions

## 💡 Usage Examples

### Run Basic Audit
```bash
python audit.py
```
Output: scan_vulnerable.txt, scan_hardened.txt

### Generate HTML Report
```bash
python audit.py
# View: reports/audit_report_*.html
```

### View Dashboard
```bash
cd dashboard && python app.py
# Navigate to: http://localhost:8080
```

### Use Docker Compose
```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Deploy to Kubernetes
```bash
# Hardened deployment (production)
kubectl apply -f k8s/deployment-hardened.yaml

# Check status
kubectl get pods -n flask-hardened
kubectl describe netpol -n flask-hardened

# Clean up
kubectl delete -f k8s/deployment-hardened.yaml
```

### CI/CD Integration
```bash
# GitHub Actions: Automatically runs on push
# See: .github/workflows/security-audit.yml

# GitLab CI: Automatically runs in pipeline
# See: .gitlab-ci.yml
```

## 📈 Results & Impact

### Typical Improvements Achieved:
- **88% Image Size Reduction** (1.22 GB → 144 MB)
- **53% Fewer Vulnerabilities** (95 → 45 CVEs)
- **Zero Hardcoded Secrets** (removed from environment)
- **Non-Root Execution** (UID 1000 vs root)
- **Minimal Attack Surface** (only required packages)

### Production-Ready Features:
- ✅ CI/CD Integration (GitHub + GitLab)
- ✅ Kubernetes Deployments (20+ security controls)
- ✅ Web Dashboard (real-time metrics)
- ✅ Multi-format Reporting (JSON, HTML, Text)
- ✅ Historical Tracking (30 audits)
- ✅ Automated Thresholds (build gate enforcement)

## 📚 Documentation

- **[IMPROVEMENTS.md](IMPROVEMENTS.md)** - Detailed v2.0 enhancements
- **[UPGRADE_GUIDE.md](UPGRADE_GUIDE.md)** - Quick start for new features
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System architecture
- **[config.yaml](config.yaml)** - Configuration reference

## 🎓 Learning Outcomes

1. **Container Security**: Docker hardening best practices
2. **Vulnerability Management**: Automated scanning and remediation
3. **DevSecOps**: Security integration in CI/CD pipelines
4. **Kubernetes Security**: Pod Security Standards, Network Policies
5. **Compliance**: Automated reporting and audit trails
6. **Monitoring**: Real-time security metrics visualization

## 🔒 Security Checklist

### Container Level:
- [ ] Use pinned, minimal base images
- [ ] Run containers as non-root user
- [ ] Never hardcode secrets in Dockerfiles
- [ ] Use .dockerignore to exclude sensitive files
- [ ] Minimize attack surface (packages, ports)
- [ ] Implement health checks
- [ ] Set resource limits

### Kubernetes Level:
- [ ] Enforce Pod Security Standards
- [ ] Implement Network Policies
- [ ] Use ResourceQuota and LimitRange
- [ ] Configure RBAC properly
- [ ] Enable audit logging
- [ ] Use Secrets (not ConfigMaps) for sensitive data
- [ ] Implement Pod Disruption Budgets

### CI/CD Level:
- [ ] Automated vulnerability scanning
- [ ] Threshold-based build gates
- [ ] SARIF upload to security dashboard
- [ ] PR comments with scan results
- [ ] Artifact retention for auditing

## 🛠️ Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Container Runtime | Docker | Image building & execution |
| Vulnerability Scanner | Trivy | CVE detection |
| Security Linter | Dockle | Best practice checking |
| Orchestration | Kubernetes | Production deployment |
| CI/CD | GitHub Actions, GitLab CI | Automation |
| Dashboard | Flask + Chart.js | Visualization |
| Reporting | Python + Jinja2 | Multi-format reports |
| Configuration | YAML | Customization |

## 🚀 Next Steps

1. **Integrate with Your CI/CD**: Copy `.github/workflows/security-audit.yml` to your repo
2. **Deploy to K8s**: Use `k8s/deployment-hardened.yaml` as template
3. **Customize Thresholds**: Edit `config.yaml` for your requirements
4. **Add More Scanners**: Extend with Snyk, Grype, or Anchore
5. **Connect to SIEM**: Export JSON reports to security tools
6. **Schedule Regular Scans**: Use cron or CI/CD schedules

## 📖 References

- [Docker Security Best Practices](https://docs.docker.com/develop/security-best-practices/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [OWASP Docker Security](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/security-checklist/)
- [NSA Kubernetes Hardening Guide](https://www.nsa.gov/Press-Room/News-Highlights/Article/Article/2716980/)

## 🤝 Contributing

Contributions welcome! Areas for enhancement:
- Additional security scanners integration
- More CI/CD platform templates
- Enhanced dashboard features
- Additional report formats
- Performance optimizations

## 📄 License

MIT License - Free for educational and commercial use

---

**v2.0** - Enterprise-grade container security audit platform
Made with ❤️ for DevSecOps teams


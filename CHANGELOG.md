# Changelog

## v2.8.0

### New Features
- **CLI with subcommands**: Single `docker-monitor` entry point with `audit`, `monitor`, `dashboard`, `report`, `status` commands
- **Parallel scanner execution**: Trivy, Dockle, Syft, and Grype run concurrently via ThreadPoolExecutor
- **Optional ML model**: IsolationForest anomaly detector is now opt-in (`pip install docker-monitor[ml]`)
- **Lazy ML model download**: ML model downloaded on first use with SHA256 verification
- **Tailwind CSS dashboard**: Modern UI with Tailwind CDN and Chart.js
- **Config validation**: All config keys are now actually read and used
- **Environment variable overrides**: `DM_*` env vars override config values

### Bug Fixes
- Fixed `is_protected` key causing TypeError crash in runtime monitor (protected containers were silently dropped)
- Fixed alert logic checking hardened image instead of vulnerable image
- Fixed 7 API endpoints exposing security data without authentication
- Fixed hardcoded fallback secret key enabling session forgery
- Fixed bare `except:` clauses replaced with `except Exception:`
- Fixed missing JSON error handling in Trivy scanner
- Fixed Trivy subprocess missing timeout (could hang indefinitely)
- Fixed dashboard template referencing 10+ non-existent `report.comparison.*` fields
- Fixed `report_generator.py` having no CLI entry point
- Fixed `pyproject.toml` missing 4 critical dependencies
- Fixed `hardened/Dockerfile` and `vulnerable/Dockerfile` with invalid COPY paths
- Fixed `db.py` creating database on import as side effect (now lazy init)
- Fixed `cloud_cve.py` sequential HTTP requests (now parallel with ThreadPoolExecutor)
- Fixed `alerting.py` unconditional `import requests` (now conditional)
- Fixed logger handler accumulation on re-import
- Fixed global random seed pollution in ML model (now uses local RandomState)
- Fixed missing `encoding="utf-8"` in multiple `open()` calls
- Fixed `.gitignore` missing `*.db`, `*.joblib`, `reports/`, `runtime/`, `logs/`
- Fixed GitLab CI `report:generate` stage running non-existent entry point
- Fixed GitLab CI missing dependencies
- Fixed GitHub Actions using unpinned `trivy-action@master`

### Improvements
- SQLite database uses connection pooling with thread-local connections and WAL journal mode
- Database path is configurable (defaults to `~/.docker-monitor/monitor.db`)
- CVE fetcher uses parallel HTTP requests (configurable concurrency)
- Dashboard subprocess calls have 300s timeout
- All endpoints in dashboard are auth-protected
- Secret key is random by default (no hardcoded fallback)
- Removed deprecated `version` key from docker-compose.yml
- Dashboard Dockerfile copies only required files
- Comprehensive test suite (30+ tests across 7 test files)

### Removed
- Removed `app/app.py` demo application (not part of the tool)
- Removed `build.sh` (replaced by `pyproject.toml` entry points)
- Removed `check_tools.sh` (integrated into `docker-monitor status`)
- Removed `setup_real_environment.sh` (user installs via pip)
- Removed `hardened/Dockerfile` and `vulnerable/Dockerfile` (redundant)
- Removed dead config keys (30+ unused keys eliminated)

## v2.0.0

- Initial multi-engine scanning with Trivy, Dockle, Syft, Grype
- Runtime threat monitoring with ensemble anomaly detection
- Web dashboard with container management
- CI/CD integration with GitHub Actions and GitLab CI

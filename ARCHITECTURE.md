# Container Security Audit - System Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                     CONTAINER SECURITY AUDIT PROJECT                          │
│                          System Architecture                                  │
└──────────────────────────────────────────────────────────────────────────────┘

                              ┌─────────────┐
                              │   User      │
                              └──────┬──────┘
                                     │
                                     ▼
                         ┌───────────────────────┐
                         │   python audit.py     │
                         │  (Main Controller)    │
                         └───────────┬───────────┘
                                     │
                    ┌────────────────┼────────────────┐
                    │                                 │
                    ▼                                 ▼
        ┌──────────────────────┐       ┌──────────────────────┐
        │  Build Vulnerable    │       │  Build Hardened      │
        │      Image           │       │      Image           │
        └──────────┬───────────┘       └──────────┬───────────┘
                   │                              │
                   ├─────────────┬────────────────┤
                   │             │                │
                   ▼             ▼                ▼
    ┌─────────────────────────────────────────────────────────┐
    │                   Docker Engine                          │
    │                                                           │
    │  ┌─────────────────────┐    ┌─────────────────────┐    │
    │  │  Dockerfile.vuln    │    │ Dockerfile.hardened │    │
    │  │                     │    │                     │    │
    │  │  FROM python:latest │    │ FROM python:3.11.6  │    │
    │  │  ENV API_KEY=secret │    │ USER appuser        │    │
    │  │  EXPOSE 5000 22 ..  │    │ EXPOSE 5000         │    │
    │  │  (runs as root)     │    │ HEALTHCHECK ...     │    │
    │  └─────────┬───────────┘    └─────────┬───────────┘    │
    │            │                           │                 │
    │            ▼                           ▼                 │
    │  ┌─────────────────┐        ┌─────────────────┐        │
    │  │  flask-app-     │        │  flask-app-     │        │
    │  │   vulnerable    │        │   hardened      │        │
    │  │   (1.12 GB)     │        │   (187 MB)      │        │
    │  └─────────┬───────┘        └─────────┬───────┘        │
    └────────────┼──────────────────────────┼─────────────────┘
                 │                           │
                 ├─────────┬─────────────────┤
                 │         │                 │
                 ▼         ▼                 ▼
        ┌────────────┐  ┌──────────┐  ┌──────────┐
        │   Trivy    │  │  Dockle  │  │   Run    │
        │  Scanning  │  │ Scanning │  │Container │
        └─────┬──────┘  └────┬─────┘  └────┬─────┘
              │              │              │
              ▼              ▼              ▼
     ┌──────────────────────────────────────────────┐
     │         Scan Results & Reports                │
     │                                               │
     │  • scan_vulnerable.txt                        │
     │  • scan_hardened.txt                          │
     │  • Comparison Table                           │
     │  • Vulnerability Summary                      │
     └──────────────────────────────────────────────┘
              │
              ▼
     ┌──────────────────┐
     │  User Reviews    │
     │   & Learns       │
     └──────────────────┘


┌──────────────────────────────────────────────────────────────────────────────┐
│                          FLASK APP ARCHITECTURE                               │
└──────────────────────────────────────────────────────────────────────────────┘

                    ┌─────────────────┐
                    │   Web Browser   │
                    │ localhost:5000  │
                    └────────┬────────┘
                             │
                             │ HTTP Request
                             ▼
                ┌────────────────────────┐
                │   Docker Container     │
                │ ┌────────────────────┐ │
                │ │    Flask App       │ │
                │ │   (app/app.py)     │ │
                │ │                    │ │
                │ │  Routes:           │ │
                │ │  • GET /           │ │
                │ │  • GET /api/info   │ │
                │ │  • GET /health     │ │
                │ └─────────┬──────────┘ │
                │           │            │
                │           ▼            │
                │ ┌────────────────────┐ │
                │ │  Container Info    │ │
                │ │  • hostname        │ │
                │ │  • user_id         │ │
                │ │  • is_root?        │ │
                │ │  • env vars        │ │
                │ └────────────────────┘ │
                └────────────┬───────────┘
                             │
                             │ HTTP Response
                             ▼
                    ┌─────────────────┐
                    │   HTML Page     │
                    │  with Security  │
                    │   Indicators    │
                    └─────────────────┘


┌──────────────────────────────────────────────────────────────────────────────┐
│                          SECURITY SCAN FLOW                                   │
└──────────────────────────────────────────────────────────────────────────────┘

    audit.py
       │
       ├─► Check Docker installed
       │
       ├─► Build Vulnerable Image
       │     │
       │     └─► docker build -f Dockerfile.vuln
       │
       ├─► Build Hardened Image
       │     │
       │     └─► docker build -f Dockerfile.hardened
       │
       ├─► Scan Vulnerable Image
       │     │
       │     ├─► trivy image flask-app-vulnerable
       │     │     └─► Find CVEs (62 HIGH/CRITICAL)
       │     │
       │     └─► dockle flask-app-vulnerable
       │           └─► Find misconfigurations (3 FATAL)
       │
       ├─► Scan Hardened Image
       │     │
       │     ├─► trivy image flask-app-hardened
       │     │     └─► Find CVEs (15 HIGH/CRITICAL)
       │     │
       │     └─► dockle flask-app-hardened
       │           └─► Find misconfigurations (0 FATAL)
       │
       ├─► Parse Results
       │     │
       │     ├─► Count vulnerabilities
       │     ├─► Count misconfigurations
       │     └─► Calculate improvements
       │
       └─► Generate Reports
             │
             ├─► scan_vulnerable.txt
             ├─► scan_hardened.txt
             └─► Console output (comparison table)


┌──────────────────────────────────────────────────────────────────────────────┐
│                     VULNERABLE vs HARDENED COMPARISON                         │
└──────────────────────────────────────────────────────────────────────────────┘

╔═══════════════════════════════╦═══════════════════════╦═══════════════════════╗
║                               ║     VULNERABLE        ║      HARDENED         ║
╠═══════════════════════════════╬═══════════════════════╬═══════════════════════╣
║ Base Image                    ║                       ║                       ║
╠═══════════════════════════════╬═══════════════════════╬═══════════════════════╣
║ FROM                          ║ python:latest ⚠️      ║ python:3.11.6-slim ✅ ║
║ Size                          ║ 1.12 GB ⚠️            ║ 187 MB ✅             ║
║ Deterministic                 ║ NO ⚠️                 ║ YES ✅                ║
╠═══════════════════════════════╬═══════════════════════╬═══════════════════════╣
║ User Configuration            ║                       ║                       ║
╠═══════════════════════════════╬═══════════════════════╬═══════════════════════╣
║ USER directive                ║ None (root) ⚠️        ║ appuser ✅            ║
║ UID                           ║ 0 (root) ⚠️           ║ 1001 ✅               ║
║ Privilege level               ║ Full ⚠️               ║ Limited ✅            ║
╠═══════════════════════════════╬═══════════════════════╬═══════════════════════╣
║ Secrets Management            ║                       ║                       ║
╠═══════════════════════════════╬═══════════════════════╬═══════════════════════╣
║ Hardcoded secrets             ║ 2 (API_KEY, TOKEN) ⚠️ ║ 0 ✅                  ║
║ Visible in inspect            ║ YES ⚠️                ║ NO ✅                 ║
╠═══════════════════════════════╬═══════════════════════╬═══════════════════════╣
║ Packages Installed            ║                       ║                       ║
╠═══════════════════════════════╬═══════════════════════╬═══════════════════════╣
║ curl, wget                    ║ YES ⚠️                ║ NO ✅                 ║
║ vim, nano                     ║ YES ⚠️                ║ NO ✅                 ║
║ openssh-server                ║ YES ⚠️                ║ NO ✅                 ║
║ sudo                          ║ YES ⚠️                ║ NO ✅                 ║
╠═══════════════════════════════╬═══════════════════════╬═══════════════════════╣
║ Network Exposure              ║                       ║                       ║
╠═══════════════════════════════╬═══════════════════════╬═══════════════════════╣
║ Ports exposed                 ║ 5 (5000,8080,3000,    ║ 1 (5000) ✅           ║
║                               ║    22,443) ⚠️         ║                       ║
╠═══════════════════════════════╬═══════════════════════╬═══════════════════════╣
║ Health & Monitoring           ║                       ║                       ║
╠═══════════════════════════════╬═══════════════════════╬═══════════════════════╣
║ HEALTHCHECK                   ║ NO ⚠️                 ║ YES ✅                ║
║ Debug mode                    ║ Enabled ⚠️            ║ Disabled ✅           ║
╠═══════════════════════════════╬═══════════════════════╬═══════════════════════╣
║ Vulnerability Scan Results    ║                       ║                       ║
╠═══════════════════════════════╬═══════════════════════╬═══════════════════════╣
║ CRITICAL CVEs                 ║ 15 ⚠️                 ║ 3 ✅                  ║
║ HIGH CVEs                     ║ 47 ⚠️                 ║ 12 ✅                 ║
║ Dockle FATAL                  ║ 3 ⚠️                  ║ 0 ✅                  ║
║ Dockle WARN                   ║ 8 ⚠️                  ║ 2 ✅                  ║
╠═══════════════════════════════╬═══════════════════════╬═══════════════════════╣
║ Security Rating               ║ ⚠️  FAIL              ║ ✅ PASS               ║
╚═══════════════════════════════╩═══════════════════════╩═══════════════════════╝


┌──────────────────────────────────────────────────────────────────────────────┐
│                            FILE DEPENDENCIES                                  │
└──────────────────────────────────────────────────────────────────────────────┘

audit.py
├── imports: subprocess, sys, os, shutil, datetime
├── calls: docker build, trivy, dockle
├── reads: Dockerfile.vuln, Dockerfile.hardened
└── writes: scan_vulnerable.txt, scan_hardened.txt

app/app.py
├── imports: Flask, os, socket
├── requires: Flask==3.0.0, Werkzeug==3.0.1
└── serves: HTTP on port 5000

Dockerfile.vuln
├── base: python:latest
├── copies: app/app.py
└── builds: flask-app-vulnerable

Dockerfile.hardened
├── base: python:3.11.6-slim-bookworm
├── copies: app/app.py
├── uses: .dockerignore
└── builds: flask-app-hardened

.dockerignore
└── excludes: secrets, .git, cache, tests, etc.


┌──────────────────────────────────────────────────────────────────────────────┐
│                         EXECUTION FLOW DIAGRAM                                │
└──────────────────────────────────────────────────────────────────────────────┘

START
  │
  ├─► Read Dockerfile.vuln
  │     │
  │     └─► Build Image (1.12 GB)
  │           │
  │           ├─► Install many packages
  │           ├─► Set API_KEY env var
  │           ├─► Expose 5 ports
  │           └─► Run as root
  │
  ├─► Read Dockerfile.hardened + .dockerignore
  │     │
  │     └─► Build Image (187 MB)
  │           │
  │           ├─► Minimal packages only
  │           ├─► Create appuser
  │           ├─► Expose 1 port
  │           └─► Run as appuser
  │
  ├─► Scan Both Images
  │     │
  │     ├─► Trivy: Find CVEs in base image & packages
  │     └─► Dockle: Check Docker best practices
  │
  ├─► Compare Results
  │     │
  │     └─► Generate comparison table
  │
  └─► Save Reports & Display
        │
        └─► User reviews and learns
              │
              └─► END


┌──────────────────────────────────────────────────────────────────────────────┐
│                    SECURITY DEFENSE LAYERS                                    │
└──────────────────────────────────────────────────────────────────────────────┘

                        Defense in Depth

    ┌────────────────────────────────────────────────┐
    │  Layer 1: Base Image                           │
    │  ✅ Pinned version (3.11.6)                    │
    │  ✅ Minimal variant (slim)                     │
    │  ✅ Official source                            │
    └────────────────────────────────────────────────┘
                        │
    ┌────────────────────────────────────────────────┐
    │  Layer 2: Build Process                        │
    │  ✅ .dockerignore prevents secret inclusion    │
    │  ✅ Minimal package installation               │
    │  ✅ No unnecessary tools                       │
    └────────────────────────────────────────────────┘
                        │
    ┌────────────────────────────────────────────────┐
    │  Layer 3: User & Permissions                   │
    │  ✅ Non-root user (appuser)                    │
    │  ✅ Limited UID (1001)                         │
    │  ✅ No sudo access                             │
    └────────────────────────────────────────────────┘
                        │
    ┌────────────────────────────────────────────────┐
    │  Layer 4: Network & Exposure                   │
    │  ✅ Single port exposed (5000)                 │
    │  ✅ No SSH access                              │
    │  ✅ No privileged ports                        │
    └────────────────────────────────────────────────┘
                        │
    ┌────────────────────────────────────────────────┐
    │  Layer 5: Monitoring & Health                  │
    │  ✅ Health check configured                    │
    │  ✅ Debug mode disabled                        │
    │  ✅ Proper logging                             │
    └────────────────────────────────────────────────┘
                        │
    ┌────────────────────────────────────────────────┐
    │  Layer 6: Secret Management                    │
    │  ✅ No hardcoded secrets                       │
    │  ✅ Runtime injection                          │
    │  ✅ Environment-based config                   │
    └────────────────────────────────────────────────┘
                        │
                  APPLICATION
              (Flask Web Server)


┌──────────────────────────────────────────────────────────────────────────────┐
│                              PROJECT SUCCESS!                                 │
└──────────────────────────────────────────────────────────────────────────────┘

You now have a complete, working Container Security Audit system that:

✅ Demonstrates real-world vulnerabilities
✅ Shows how to fix them
✅ Automates security scanning
✅ Generates detailed reports
✅ Provides hands-on learning
✅ Follows industry best practices
✅ Includes comprehensive documentation

Ready to run: python audit.py

🎉 Happy secure container building! 🐳
```

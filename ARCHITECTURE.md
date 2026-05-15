# Container Security Audit - System Architecture

```text
audit.py ──► [Trivy / Dockle / Syft / Grype] ──► reports/
│
└──► ai_security_model.py (RuleBasedRiskScorer)

realtime_threat_engine.py ──► Docker API ──► ThreatScorer ──► runtime/
│
└──► VulnerabilityScanner (Trivy)

dashboard/app.py ──► Flask ──► localhost:8080
```

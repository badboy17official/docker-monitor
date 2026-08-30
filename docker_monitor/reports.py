"""Multi-format report generator with historical tracking."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generate security audit reports in JSON and HTML formats."""

    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    def generate_json_report(self, data: Dict[str, Any], filename: str = None) -> Path:
        if filename is None:
            filename = f"audit_report_{self.timestamp}.json"
        filepath = self.output_dir / filename
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        return filepath

    def generate_html_report(self, data: Dict[str, Any], filename: str = None) -> Path:
        if filename is None:
            filename = f"audit_report_{self.timestamp}.html"
        filepath = self.output_dir / filename
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(self._build_html(data))
        return filepath

    def _build_html(self, data: Dict[str, Any]) -> str:
        vuln = data.get("vulnerable", {})
        hard = data.get("hardened", {})
        comp = data.get("comparison", {})
        ts = data.get("timestamp", datetime.now().isoformat())

        ai_drop = comp.get("ai_risk_drop", 0)
        crit_drop = comp.get("critical_drop", 0)
        high_drop = comp.get("high_drop", 0)
        engines = comp.get("engines_active", {})

        vc = vuln.get('critical', 0)
        hc = hard.get('critical', 0)
        vh = vuln.get('high', 0)
        hh = hard.get('high', 0)
        vm = vuln.get('medium', 0)
        hm = hard.get('medium', 0)
        vl = vuln.get('low', 0)
        hl = hard.get('low', 0)
        vs = vuln.get('ai_risk_score', 0)
        hs = hard.get('ai_risk_score', 0)
        vf = vuln.get('fatal', 0)
        hf = hard.get('fatal', 0)
        vw = vuln.get('warn', 0)
        hw = hard.get('warn', 0)
        vp = vuln.get('packages', 0)
        hp = hard.get('packages', 0)

        vuln_rows = ""
        for sev, badge, v, h in [
            ("CRITICAL", "bc", vc, hc),
            ("HIGH", "bh", vh, hh),
            ("MEDIUM", "bm", vm, hm),
            ("LOW", "bl", vl, hl),
        ]:
            delta = v - h
            vuln_rows += (
                f'<tr><td><span class="badge {badge}">{sev}</span></td>'
                f"<td>{v}</td><td>{h}</td>"
                f'<td class="good">-{delta}</td></tr>\n'
            )

        detail_rows = ""
        for label, v, h, cls in [
            ("AI Risk Score", vs, hs, "bad"),
            ("Fatal (Dockle)", vf, hf, ""),
            ("Warnings (Dockle)", vw, hw, ""),
            ("Packages (Syft)", vp, hp, ""),
        ]:
            vc_cls = f'class="{cls}"' if cls else ""
            gc = 'class="good"' if cls else ""
            detail_rows += (
                f"<tr><td>{label}</td>"
                f"<td {vc_cls}>{v}</td>"
                f"<td {gc}>{h}</td></tr>\n"
            )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Security Audit Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;padding:24px}}
.container{{max-width:1100px;margin:0 auto}}
.header{{background:linear-gradient(135deg,#1e3a5f,#0f172a);
  border:1px solid #334155;border-radius:16px;padding:32px;margin-bottom:24px}}
.header h1{{font-size:1.8rem;margin-bottom:8px}}
.header .ts{{color:#94a3b8;font-size:0.9rem}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
  gap:16px;margin-bottom:24px}}
.card{{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:20px}}
.card h3{{color:#94a3b8;font-size:0.85rem;margin-bottom:8px}}
.card .val{{font-size:2rem;font-weight:700}}
.good{{color:#4ade80}}.bad{{color:#f87171}}.warn{{color:#fbbf24}}
table{{width:100%;border-collapse:collapse;background:#1e293b;
  border-radius:12px;overflow:hidden;margin-bottom:24px}}
th{{background:#0f172a;color:#94a3b8;padding:12px 16px;text-align:left;
  font-size:0.8rem;text-transform:uppercase}}
td{{padding:12px 16px;border-bottom:1px solid #334155}}
.badge{{display:inline-block;padding:4px 10px;border-radius:999px;
  font-size:0.75rem;font-weight:700}}
.bc{{background:rgba(248,113,113,0.2);color:#f87171}}
.bh{{background:rgba(251,191,36,0.2);color:#fbbf24}}
.bm{{background:rgba(96,165,250,0.2);color:#60a5fa}}
.bl{{background:rgba(74,222,128,0.2);color:#4ade80}}
.section{{background:#1e293b;border:1px solid #334155;
  border-radius:12px;padding:24px;margin-bottom:24px}}
.section h2{{margin-bottom:16px;font-size:1.2rem}}
.footer{{text-align:center;color:#64748b;padding:16px;font-size:0.85rem}}
</style>
</head>
<body>
<div class="container">
<div class="header">
  <h1>Container Security Audit Report</h1>
  <p class="ts">Generated: {ts}</p>
</div>
<div class="grid">
  <div class="card"><h3>AI Risk Drop</h3>
    <div class="val good">{ai_drop}</div></div>
  <div class="card"><h3>Critical CVEs Fixed</h3>
    <div class="val good">{crit_drop}</div></div>
  <div class="card"><h3>High CVEs Fixed</h3>
    <div class="val good">{high_drop}</div></div>
  <div class="card"><h3>Engines Active</h3>
    <div class="val">{engines.get('vulnerable', 0)}</div></div>
</div>
<div class="section"><h2>Vulnerability Comparison</h2>
<table><thead><tr>
  <th>Severity</th><th>Vulnerable</th><th>Hardened</th><th>Delta</th>
</tr></thead><tbody>
{vuln_rows}</tbody></table></div>
<div class="section"><h2>Scan Details</h2>
<table><thead><tr>
  <th>Metric</th><th>Vulnerable</th><th>Hardened</th>
</tr></thead><tbody>
{detail_rows}</tbody></table></div>
<div class="footer">Docker Monitor v2.8.0 | Security Audit Report</div>
</div></body></html>"""

    def update_history(self, data: Dict[str, Any]) -> Path:
        """Track historical audit results."""
        history_file = self.output_dir / "audit_history.json"

        history = []
        if history_file.exists():
            try:
                with open(history_file, "r", encoding="utf-8") as f:
                    history = json.load(f)
            except Exception:
                history = []

        if "timestamp" not in data:
            data["timestamp"] = datetime.now().isoformat()

        history.append(data)
        history = history[-30:]

        with open(history_file, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2, default=str)

        try:
            from docker_monitor import db

            db.save_audit(data)
        except Exception as e:
            logger.error(f"Failed to save audit to DB: {e}")

        return history_file


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        report_path = Path(sys.argv[1])
        if report_path.exists():
            with open(report_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            gen = ReportGenerator()
            gen.generate_json_report(data)
            gen.generate_html_report(data)
            gen.update_history(data)
            print(f"Reports generated in {gen.output_dir}")
        else:
            print(f"File not found: {report_path}")
    else:
        print("Usage: python -m docker_monitor.reports <path_to_summary.json>")

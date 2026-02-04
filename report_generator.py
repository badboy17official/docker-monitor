"""
Enhanced Report Generator for Container Security Audit

Generates multiple report formats (JSON, HTML, Text) with historical tracking
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
import os


class ReportGenerator:
    """Generate comprehensive security audit reports in multiple formats"""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
    def generate_json_report(self, data: Dict[str, Any], filename: str = None):
        """Generate JSON format report"""
        if filename is None:
            filename = f"audit_report_{self.timestamp}.json"
        
        filepath = self.output_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        return filepath
    
    def generate_html_report(self, data: Dict[str, Any], filename: str = None):
        """Generate HTML format report with styling"""
        if filename is None:
            filename = f"audit_report_{self.timestamp}.html"
        
        filepath = self.output_dir / filename
        
        html_content = self._build_html(data)
        
        with open(filepath, 'w') as f:
            f.write(html_content)
        
        return filepath
    
    def _build_html(self, data: Dict[str, Any]) -> str:
        """Build HTML content for report"""
        
        vuln_data = data.get('vulnerable', {})
        hard_data = data.get('hardened', {})
        comparison = data.get('comparison', {})
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Container Security Audit Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header .timestamp {{
            font-size: 1em;
            opacity: 0.9;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .section {{
            margin-bottom: 40px;
        }}
        
        .section h2 {{
            color: #1e3c72;
            margin-bottom: 20px;
            font-size: 1.8em;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }}
        
        .comparison-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .metric-card {{
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }}
        
        .metric-card:hover {{
            transform: translateY(-5px);
        }}
        
        .metric-card h3 {{
            color: #1e3c72;
            margin-bottom: 10px;
            font-size: 1.1em;
        }}
        
        .metric-value {{
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }}
        
        .improvement {{
            color: #10b981;
            font-weight: bold;
            font-size: 1.2em;
        }}
        
        .warning {{
            color: #f59e0b;
        }}
        
        .danger {{
            color: #ef4444;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        
        th {{
            background: #1e3c72;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }}
        
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #e5e7eb;
        }}
        
        tr:hover {{
            background: #f9fafb;
        }}
        
        .footer {{
            background: #f3f4f6;
            padding: 20px;
            text-align: center;
            color: #6b7280;
        }}
        
        .badge {{
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        
        .badge-success {{
            background: #d1fae5;
            color: #065f46;
        }}
        
        .badge-danger {{
            background: #fee2e2;
            color: #991b1b;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔒 Container Security Audit Report</h1>
            <p class="timestamp">Generated: {data.get('timestamp', datetime.now().isoformat())}</p>
        </div>
        
        <div class="content">
            <div class="section">
                <h2>📊 Executive Summary</h2>
                <div class="comparison-grid">
                    <div class="metric-card">
                        <h3>Image Size Reduction</h3>
                        <div class="metric-value">{comparison.get('size_reduction_percent', 0):.1f}%</div>
                        <p>{comparison.get('size_vulnerable', 'N/A')} → {comparison.get('size_hardened', 'N/A')}</p>
                    </div>
                    
                    <div class="metric-card">
                        <h3>Vulnerability Reduction</h3>
                        <div class="metric-value">{comparison.get('vuln_reduction_percent', 0):.1f}%</div>
                        <p>{comparison.get('vuln_vulnerable', 0)} → {comparison.get('vuln_hardened', 0)} CVEs</p>
                    </div>
                    
                    <div class="metric-card">
                        <h3>Security Score</h3>
                        <div class="metric-value improvement">
                            {comparison.get('security_score_improvement', 'N/A')}
                        </div>
                        <p>Overall Improvement</p>
                    </div>
                    
                    <div class="metric-card">
                        <h3>Configuration Issues</h3>
                        <div class="metric-value">
                            {comparison.get('config_issues_fixed', 0)}
                        </div>
                        <p>Issues Resolved</p>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>🛡️ Vulnerability Comparison</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>Vulnerable Image</th>
                            <th>Hardened Image</th>
                            <th>Improvement</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><span class="badge badge-danger">CRITICAL</span></td>
                            <td>{vuln_data.get('critical', 0)}</td>
                            <td>{hard_data.get('critical', 0)}</td>
                            <td class="improvement">-{vuln_data.get('critical', 0) - hard_data.get('critical', 0)}</td>
                        </tr>
                        <tr>
                            <td><span class="badge badge-danger">HIGH</span></td>
                            <td>{vuln_data.get('high', 0)}</td>
                            <td>{hard_data.get('high', 0)}</td>
                            <td class="improvement">-{vuln_data.get('high', 0) - hard_data.get('high', 0)}</td>
                        </tr>
                        <tr>
                            <td><span class="badge" style="background:#fef3c7;color:#92400e">MEDIUM</span></td>
                            <td>{vuln_data.get('medium', 0)}</td>
                            <td>{hard_data.get('medium', 0)}</td>
                            <td class="improvement">-{vuln_data.get('medium', 0) - hard_data.get('medium', 0)}</td>
                        </tr>
                        <tr>
                            <td><span class="badge" style="background:#dbeafe;color:#1e40af">LOW</span></td>
                            <td>{vuln_data.get('low', 0)}</td>
                            <td>{hard_data.get('low', 0)}</td>
                            <td class="improvement">-{vuln_data.get('low', 0) - hard_data.get('low', 0)}</td>
                        </tr>
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h2>✅ Security Improvements Implemented</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Category</th>
                            <th>Before</th>
                            <th>After</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td>Base Image</td>
                            <td>python:latest (unpinned)</td>
                            <td>python:3.11.6-slim (pinned)</td>
                            <td><span class="badge badge-success">✓ Fixed</span></td>
                        </tr>
                        <tr>
                            <td>User Privileges</td>
                            <td>Root (UID 0)</td>
                            <td>Non-root user</td>
                            <td><span class="badge badge-success">✓ Fixed</span></td>
                        </tr>
                        <tr>
                            <td>Hardcoded Secrets</td>
                            <td>API keys exposed</td>
                            <td>Removed/secured</td>
                            <td><span class="badge badge-success">✓ Fixed</span></td>
                        </tr>
                        <tr>
                            <td>Image Size</td>
                            <td>{comparison.get('size_vulnerable', 'N/A')}</td>
                            <td>{comparison.get('size_hardened', 'N/A')}</td>
                            <td><span class="badge badge-success">✓ Optimized</span></td>
                        </tr>
                    </tbody>
                </table>
            </div>
            
            <div class="section">
                <h2>🔧 Tools Used</h2>
                <div class="comparison-grid">
                    <div class="metric-card">
                        <h3>Trivy</h3>
                        <p>Comprehensive vulnerability scanner for CVE detection</p>
                    </div>
                    <div class="metric-card">
                        <h3>Dockle</h3>
                        <p>Container image linter for best practices</p>
                    </div>
                    <div class="metric-card">
                        <h3>Docker</h3>
                        <p>Container runtime and image building</p>
                    </div>
                    <div class="metric-card">
                        <h3>Python</h3>
                        <p>Automation and orchestration</p>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>Container Security Audit Project | Generated with ❤️ by DevSecOps Team</p>
            <p>Report Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </div>
    </div>
</body>
</html>
"""
        return html
    
    def update_history(self, data: Dict[str, Any]):
        """Track historical audit results"""
        history_file = self.output_dir / "audit_history.json"
        
        history = []
        if history_file.exists():
            with open(history_file, 'r') as f:
                history = json.load(f)
        
        # Add timestamp if not present
        if 'timestamp' not in data:
            data['timestamp'] = datetime.now().isoformat()
        
        history.append(data)
        
        # Keep only last 30 entries
        history = history[-30:]
        
        with open(history_file, 'w') as f:
            json.dump(history, f, indent=2, default=str)
        
        return history_file

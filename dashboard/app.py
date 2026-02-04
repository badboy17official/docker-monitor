"""
Security Audit Dashboard
A Flask-based web interface to visualize container security audit results
"""

from flask import Flask, render_template, jsonify, send_file
import json
from pathlib import Path
from datetime import datetime
import os

app = Flask(__name__)

REPORTS_DIR = Path("../reports")


def load_latest_report():
    """Load the most recent audit report"""
    history_file = REPORTS_DIR / "audit_history.json"
    
    if history_file.exists():
        with open(history_file, 'r') as f:
            history = json.load(f)
            if history:
                return history[-1]
    
    return None


def load_history():
    """Load all historical audit data"""
    history_file = REPORTS_DIR / "audit_history.json"
    
    if history_file.exists():
        with open(history_file, 'r') as f:
            return json.load(f)
    
    return []


@app.route('/')
def index():
    """Main dashboard page"""
    report = load_latest_report()
    return render_template('dashboard.html', report=report)


@app.route('/api/latest')
def api_latest():
    """API endpoint for latest report"""
    report = load_latest_report()
    if report:
        return jsonify(report)
    return jsonify({"error": "No reports available"}), 404


@app.route('/api/history')
def api_history():
    """API endpoint for historical data"""
    history = load_history()
    return jsonify(history)


@app.route('/api/trends')
def api_trends():
    """API endpoint for trend analysis"""
    history = load_history()
    
    if not history:
        return jsonify({"error": "No historical data"}), 404
    
    trends = {
        "dates": [],
        "vulnerable_size": [],
        "hardened_size": [],
        "vulnerable_vulns": [],
        "hardened_vulns": []
    }
    
    for entry in history:
        timestamp = entry.get('timestamp', '')
        if timestamp:
            trends["dates"].append(timestamp[:10])  # Just date part
        
        comp = entry.get('comparison', {})
        trends["vulnerable_size"].append(float(comp.get('size_vulnerable_mb', 0)))
        trends["hardened_size"].append(float(comp.get('size_hardened_mb', 0)))
        trends["vulnerable_vulns"].append(comp.get('vuln_vulnerable', 0))
        trends["hardened_vulns"].append(comp.get('vuln_hardened', 0))
    
    return jsonify(trends)


@app.route('/reports/<filename>')
def download_report(filename):
    """Download specific report file"""
    filepath = REPORTS_DIR / filename
    if filepath.exists():
        return send_file(filepath, as_attachment=True)
    return jsonify({"error": "File not found"}), 404


@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})


if __name__ == '__main__':
    # Create reports directory if it doesn't exist
    REPORTS_DIR.mkdir(exist_ok=True)
    
    print("=" * 70)
    print("🔒 Container Security Audit Dashboard")
    print("=" * 70)
    print(f"📊 Dashboard URL: http://localhost:8080")
    print(f"📁 Reports Directory: {REPORTS_DIR.absolute()}")
    print("=" * 70)
    
    app.run(host='0.0.0.0', port=8080, debug=True)

"""Flask web dashboard for container security monitoring."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, redirect, render_template, request, send_file, session, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from docker_monitor.config import Config
from docker_monitor.dashboard.auth import configure_auth, require_auth

CONTAINER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def create_app(config: Config) -> Flask:
    """Create and configure the Flask application."""
    dashboard_dir = Path(__file__).resolve().parent
    template_dir = str(dashboard_dir / "templates")

    app = Flask(__name__, template_folder=template_dir)
    configure_auth(app)

    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://",
    )

    reports_dir = Path(config.reporting.get("output_dir", "reports"))
    runtime_dir = reports_dir.parent / "runtime"
    reports_dir.mkdir(exist_ok=True)
    runtime_dir.mkdir(exist_ok=True)

    def _run_command(
        command: List[str],
        env_overrides: Optional[Dict[str, str]] = None,
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        if env_overrides:
            env.update(env_overrides)
        return subprocess.run(command, capture_output=True, text=True, check=False, timeout=300, env=env)

    def _list_containers() -> List[Dict[str, Any]]:
        if not shutil.which("docker"):
            return []
        result = _run_command(["docker", "ps", "--format", "{{json .}}"])
        if result.returncode != 0:
            return []
        containers = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line:
                try:
                    containers.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return containers

    def _tool_status() -> Dict[str, bool]:
        tools = ["docker", "trivy", "dockle", "syft", "grype", "python"]
        return {tool: bool(shutil.which(tool)) for tool in tools}

    def _load_latest_report():
        history_file = reports_dir / "audit_history.json"
        if history_file.exists():
            try:
                with open(history_file, "r", encoding="utf-8") as f:
                    history = json.load(f)
                    if history:
                        return history[-1]
            except Exception:
                pass
        return None

    def _load_history():
        try:
            from docker_monitor import db
            db_history = db.get_audit_history()
            if db_history:
                return db_history
        except Exception:
            pass
        history_file = reports_dir / "audit_history.json"
        if history_file.exists():
            try:
                with open(history_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def _load_runtime_findings():
        runtime_file = runtime_dir / "runtime_threats_latest.json"
        if runtime_file.exists():
            try:
                with open(runtime_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "generated_at": None,
            "summary": {
                "containers_monitored": 0,
                "critical_alerts": 0,
                "high_alerts": 0,
                "medium_alerts": 0,
                "low_alerts": 0,
            },
            "findings": [],
        }

    # --- Routes ---

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("10 per minute")
    def login():
        from hmac import compare_digest
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            if (
                compare_digest(username, app.config.get("AUTH_USER", ""))
                and compare_digest(password, app.config.get("AUTH_PASSWORD", ""))
            ):
                session["authenticated"] = True
                return redirect(url_for("index"))
            return render_template("login.html", error="Invalid credentials")
        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.pop("authenticated", None)
        return redirect(url_for("login"))

    @app.route("/")
    @require_auth
    def index():
        report = _load_latest_report()
        runtime = _load_runtime_findings()
        return render_template("dashboard.html", report=report, runtime=runtime)

    @app.route("/logs")
    @require_auth
    def logs_view():
        try:
            from docker_monitor import db
            container = request.args.get("container", "")
            min_score = request.args.get("min_score", "")
            min_score_val = int(min_score) if min_score.isdigit() else None
            page = int(request.args.get("page", 1))
            limit = 50
            offset = (page - 1) * limit

            events = db.get_runtime_events(
                container_name=container,
                min_score=min_score_val,
                limit=limit,
                offset=offset,
            )
            for e in events:
                if isinstance(e.get("data"), str):
                    try:
                        e["data"] = json.loads(e["data"])
                    except Exception:
                        e["data"] = {}
            return render_template("logs.html", events=events, container=container, min_score=min_score, page=page)
        except Exception as e:
            return f"Error loading logs: {e}", 500

    # --- API Endpoints (all auth-protected) ---

    @app.route("/api/latest")
    @require_auth
    def api_latest():
        report = _load_latest_report()
        if report:
            return jsonify(report)
        return jsonify({"error": "No reports available"}), 404

    @app.route("/api/history")
    @require_auth
    def api_history():
        return jsonify(_load_history())

    @app.route("/api/runtime-history")
    @require_auth
    def api_runtime_history():
        try:
            from docker_monitor import db
            return jsonify(db.get_runtime_history())
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/trends")
    @require_auth
    def api_trends():
        history = _load_history()
        if not history:
            return jsonify({"error": "No historical data"}), 404

        trends = {"dates": [], "vulnerable_scores": [], "hardened_scores": [], "critical_drops": []}
        for entry in history:
            ts = entry.get("timestamp", "")
            if ts:
                trends["dates"].append(ts[:10])
            trends["vulnerable_scores"].append(entry.get("vulnerable", {}).get("ai_risk_score", 0))
            trends["hardened_scores"].append(entry.get("hardened", {}).get("ai_risk_score", 0))
            trends["critical_drops"].append(entry.get("comparison", {}).get("critical_drop", 0))

        return jsonify(trends)

    @app.route("/api/runtime-threats")
    @require_auth
    def api_runtime_threats():
        return jsonify(_load_runtime_findings())

    @app.route("/api/runtime-threats/alerts")
    @require_auth
    def api_runtime_alerts():
        runtime = _load_runtime_findings()
        return jsonify(runtime.get("alerts", []))

    @app.route("/api/runtime-threats/container/<name>")
    @require_auth
    def api_runtime_container_detail(name):
        data = _load_runtime_findings()
        for item in data.get("findings", []):
            if item.get("name") == name:
                return jsonify(item)
        return jsonify({"error": "container not found"}), 404

    @app.route("/api/control-panel/status")
    @require_auth
    @limiter.limit("10 per minute")
    def api_control_panel_status():
        runtime_file = runtime_dir / "runtime_threats_latest.json"
        runtime_exists = runtime_file.exists()
        return jsonify({
            "timestamp": datetime.now().isoformat(),
            "tools": _tool_status(),
            "runtime_output_exists": runtime_exists,
            "runtime_generated_at": _load_runtime_findings().get("generated_at") if runtime_exists else None,
            "containers_running": len(_list_containers()),
            "control_auth_enabled": app.config.get("AUTH_ENABLED", False),
        })

    @app.route("/api/control-panel/containers")
    @require_auth
    @limiter.limit("10 per minute")
    def api_control_panel_containers():
        containers = _list_containers()
        try:
            from docker_monitor import db
            protected = db.get_protected_containers()
            for c in containers:
                if c.get("ID") and c["ID"][:12] in protected:
                    c["is_protected"] = True
        except Exception:
            pass
        return jsonify({"containers": containers})

    @app.route("/api/control-panel/runtime/snapshot", methods=["POST"])
    @require_auth
    @limiter.limit("10 per minute")
    def api_control_panel_runtime_snapshot():
        command = [sys.executable, "-m", "docker_monitor.monitor"]
        result = _run_command(command, env_overrides={"RUNTIME_MONITOR_MODE": "once"})
        return jsonify({
            "success": result.returncode == 0,
            "stdout": result.stdout[-2000:],
            "stderr": result.stderr[-2000:],
            "exit_code": result.returncode,
        }), (200 if result.returncode == 0 else 500)

    @app.route("/api/control-panel/audit/run", methods=["POST"])
    @require_auth
    @limiter.limit("10 per minute")
    def api_control_panel_run_audit():
        command = [sys.executable, "-m", "docker_monitor.cli", "audit"]
        result = _run_command(command)
        return jsonify({
            "success": result.returncode == 0,
            "stdout": result.stdout[-3000:],
            "stderr": result.stderr[-3000:],
            "exit_code": result.returncode,
        }), (200 if result.returncode == 0 else 500)

    @app.route("/api/control-panel/container-action", methods=["POST"])
    @require_auth
    @limiter.limit("10 per minute")
    def api_control_panel_container_action():
        data = request.get_json(silent=True) or {}
        container = (data.get("container") or "").strip()
        action = data.get("action")

        if action not in ("start", "stop", "restart"):
            return jsonify({"success": False, "error": "Invalid action"}), 400
        if not container:
            return jsonify({"success": False, "error": "Container is required"}), 400
        if not CONTAINER_NAME_RE.fullmatch(container):
            return jsonify({"success": False, "error": "Invalid container name"}), 400

        result = _run_command(["docker", action, container])
        return jsonify({
            "success": result.returncode == 0,
            "container": container,
            "action": action,
            "exit_code": result.returncode,
        }), (200 if result.returncode == 0 else 500)

    @app.route("/api/control-panel/protect/<container_id>", methods=["POST"])
    @require_auth
    def api_control_panel_protect(container_id):
        try:
            from docker_monitor import db
            container_name = (request.json or {}).get("container_name", container_id)
            db.protect_container(container_id, container_name)
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/control-panel/unprotect/<container_id>", methods=["POST"])
    @require_auth
    def api_control_panel_unprotect(container_id):
        try:
            from docker_monitor import db
            db.unprotect_container(container_id)
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500

    @app.route("/api/control-panel/report/runtime", methods=["POST"])
    @require_auth
    @limiter.limit("10 per minute")
    def api_control_panel_runtime_report():
        payload = request.get_json(silent=True) or {}
        fmt = payload.get("format", "json")
        if fmt not in ("json", "txt"):
            return jsonify({"success": False, "error": "format must be json or txt"}), 400

        runtime = _load_runtime_findings()
        if not runtime.get("generated_at"):
            return jsonify({"success": False, "error": "no runtime findings available"}), 404

        try:
            from docker_monitor.monitor import RuntimeThreatEngine
            engine = RuntimeThreatEngine(config)
            path = engine.generate_report(runtime, fmt=fmt)
            return jsonify({"success": True, "format": fmt, "path": str(path)})
        except Exception as exc:
            return jsonify({"success": False, "error": str(exc)}), 500

    @app.route("/reports/<path:filename>")
    @require_auth
    @limiter.limit("10 per minute")
    def download_report(filename):
        reports_root = reports_dir.resolve()
        requested = (reports_root / filename).resolve()
        if reports_root not in requested.parents or not requested.is_file():
            return jsonify({"error": "File not found"}), 404
        return send_file(requested, as_attachment=True)

    @app.route("/health")
    def health():
        return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

    return app

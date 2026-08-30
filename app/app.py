"""Demo Flask application for security audit testing."""

import os
from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/")
def index():
    return jsonify({
        "service": "flask-demo",
        "environment": os.getenv("APP_ENV", "development"),
        "user": os.getenv("USER", "unknown"),
    })


@app.route("/health")
def health():
    return jsonify({"status": "healthy"})


@app.route("/info")
def info():
    return jsonify({
        "hostname": os.uname().nodename,
        "uid": os.getuid(),
        "env": dict(os.environ),
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=os.getenv("FLASK_DEBUG", "0") == "1")

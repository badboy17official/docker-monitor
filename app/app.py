"""
Simple Flask Web Application for Container Security Demo
"""
from flask import Flask, jsonify, render_template_string
import os
import socket

app = Flask(__name__)

# HTML template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Container Security Demo</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
        }
        .info-box {
            background-color: #e3f2fd;
            padding: 15px;
            border-radius: 4px;
            margin: 10px 0;
            border-left: 4px solid #2196F3;
        }
        .warning-box {
            background-color: #fff3e0;
            padding: 15px;
            border-radius: 4px;
            margin: 10px 0;
            border-left: 4px solid #ff9800;
        }
        .success-box {
            background-color: #e8f5e9;
            padding: 15px;
            border-radius: 4px;
            margin: 10px 0;
            border-left: 4px solid #4caf50;
        }
        code {
            background-color: #f5f5f5;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🐳 Container Security Demo</h1>
        <p>This is a simple Flask application running inside a Docker container.</p>
        
        <div class="info-box">
            <strong>Container Information:</strong><br>
            Hostname: <code>{{ hostname }}</code><br>
            User ID: <code>{{ user_id }}</code><br>
            User Name: <code>{{ user_name }}</code>
        </div>
        
        {% if is_root %}
        <div class="warning-box">
            <strong>⚠️ Security Warning:</strong><br>
            This container is running as ROOT user (UID 0)!<br>
            This is a security risk in production environments.
        </div>
        {% else %}
        <div class="success-box">
            <strong>✅ Security Good Practice:</strong><br>
            This container is running as a non-root user.<br>
            Running as: <code>{{ user_name }}</code> (UID: {{ user_id }})
        </div>
        {% endif %}
        
        <div class="info-box">
            <strong>Environment Variables:</strong><br>
            {% for key, value in env_vars.items() %}
                {{ key }}: <code>{{ value }}</code><br>
            {% endfor %}
        </div>
        
        <p><a href="/api/info">View JSON API</a></p>
    </div>
</body>
</html>
"""

@app.route('/')
def home():
    """Main page with container information"""
    hostname = socket.gethostname()
    user_id = os.getuid()
    
    # Get username
    try:
        import pwd
        user_name = pwd.getpwuid(user_id).pw_name
    except:
        user_name = "unknown"
    
    is_root = (user_id == 0)
    
    # Get relevant environment variables (filter sensitive ones for display)
    env_vars = {
        'PYTHON_VERSION': os.getenv('PYTHON_VERSION', 'Not set'),
        'APP_ENV': os.getenv('APP_ENV', 'Not set'),
        'PORT': os.getenv('PORT', '5000'),
    }
    
    # Show API_KEY if it exists (this is intentionally vulnerable for demo)
    api_key = os.getenv('API_KEY')
    if api_key:
        env_vars['API_KEY'] = api_key + ' ⚠️ (Hardcoded secret detected!)'
    
    return render_template_string(
        HTML_TEMPLATE,
        hostname=hostname,
        user_id=user_id,
        user_name=user_name,
        is_root=is_root,
        env_vars=env_vars
    )

@app.route('/api/info')
def info():
    """JSON API endpoint with container information"""
    hostname = socket.gethostname()
    user_id = os.getuid()
    
    try:
        import pwd
        user_name = pwd.getpwuid(user_id).pw_name
    except:
        user_name = "unknown"
    
    return jsonify({
        'hostname': hostname,
        'user_id': user_id,
        'user_name': user_name,
        'is_root': (user_id == 0),
        'python_version': os.getenv('PYTHON_VERSION', 'Not set'),
        'app_env': os.getenv('APP_ENV', 'production'),
        'has_api_key': bool(os.getenv('API_KEY')),
    })

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'flask-app'}), 200

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

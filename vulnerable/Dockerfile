# ⚠️ VULNERABLE DOCKERFILE - FOR EDUCATIONAL PURPOSES ONLY ⚠️
# This Dockerfile contains intentional security misconfigurations

# VULNERABILITY 1: Unpinned base image (uses 'latest' tag)
# This is non-deterministic and can lead to unexpected behavior
FROM python:latest

# VULNERABILITY 2: Hardcoded secret in environment variable
# Never store secrets directly in Dockerfiles!
ENV API_KEY=super_secret_key_12345
ENV APP_ENV=production

# VULNERABILITY 3: Installing unnecessary packages
# Increases attack surface and image size
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    vim \
    net-tools \
    netcat-traditional \
    telnet \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy application files
COPY ../app/requirements.txt .
COPY ../app/app.py .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# VULNERABILITY 4: Exposing unnecessary ports
# Only port 5000 is needed for Flask
EXPOSE 5000
EXPOSE 8080
EXPOSE 3000
EXPOSE 22

# VULNERABILITY 5: Running as root user (default)
# No USER directive means the container runs as root (UID 0)

# Set environment variable for Flask
ENV FLASK_APP=app.py

# Run the application
CMD ["python", "app.py"]

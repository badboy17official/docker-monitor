# ✅ HARDENED DOCKERFILE - Security Best Practices Applied

# SECURITY FIX 1: Use pinned, minimal base image
# Using slim variant reduces attack surface and image size
FROM python:3.11.6-slim

# SECURITY FIX 2: No hardcoded secrets
# Secrets should be passed at runtime via environment variables or secrets management
ENV APP_ENV=production

# Set working directory
WORKDIR /app

# SECURITY FIX 3: Only install required packages
# Minimal package installation reduces attack surface
# Copy requirements first for better layer caching
COPY ../app/requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# SECURITY FIX 4: Create non-root user
# Running as non-root limits potential damage from container breakout
RUN groupadd -r appuser && \
    useradd -r -g appuser -u 1001 -m -s /sbin/nologin appuser && \
    chown -R appuser:appuser /app

# Copy application files
COPY ../app/app.py .

# SECURITY FIX 5: Only expose necessary ports
# Only expose the port that Flask uses
EXPOSE 5000

# SECURITY FIX 6: Switch to non-root user
# All subsequent commands and the container runtime use this user
USER appuser

# Set environment variable for Flask
ENV FLASK_APP=app.py

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/health')" || exit 1

# Run the application
CMD ["python", "app.py"]

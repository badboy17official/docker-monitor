FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir flask

# Create non-root user
RUN useradd -m -u 1000 dashboard && \
    chown -R dashboard:dashboard /app

# Copy application
COPY app.py .
COPY templates/ templates/

# Switch to non-root user
USER dashboard

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

# Run application
CMD ["python", "app.py"]

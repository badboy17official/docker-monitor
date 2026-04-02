FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y \
    gcc \
    trivy \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ ./app/
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser
CMD ["python", "-m", "app.main"]

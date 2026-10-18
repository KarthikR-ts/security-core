# Dockerfile — Security-Core Application
FROM python:3.12-slim

WORKDIR /app

# Install system dependencies (kubectl for remediation execution)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && curl -LO "https://dl.k8s.io/release/v1.30.0/bin/linux/amd64/kubectl" \
    && chmod +x kubectl \
    && mv kubectl /usr/local/bin/

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose ports: 8000 (orchestrator), 8080 (dashboard API), 8081 (forwarder)
EXPOSE 8000 8080 8081

# Default command (overridden per service in docker-compose)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

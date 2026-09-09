FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app

# System dependencies: Sleuth Kit for forensic toolchain, e2fsprogs for ext4
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    sleuthkit \
    e2fsprogs \
    file \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements first (layer-cache friendly)
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Copy application source only — NOT data/ or keys/
# Keys are generated at runtime into the mounted persistent volume.
COPY app/ ./app/

# Ensure the data directory tree exists inside the image as a mount point.
# Actual data and keys are never baked in — they come from the named volume.
RUN mkdir -p /app/data/evidence /app/data/cases /app/data/audit \
             /app/data/uploads /app/data/keys

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

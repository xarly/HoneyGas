# HoneyGas container image.
# Runs as a non-root user; the Python runtime needs no build tooling.
FROM python:3.12-slim

# Create an unprivileged user to run the honeypot.
RUN useradd --create-home --uid 10001 honey

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY honeygas/ ./honeygas/
COPY config/ ./config/

# Writable data (audit + quarantine) lives on a mounted volume.
RUN mkdir -p /data/audit /data/quarantine && chown -R honey:honey /data /app

USER honey

# Audit/quarantine paths are overridden to the volume via config or env-mounted
# config. See docker-compose.yml.
ENTRYPOINT ["python", "-m", "honeygas", "--config", "config/honeygas.yaml"]

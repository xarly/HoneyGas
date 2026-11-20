#!/usr/bin/env bash
# ============================================================================
# Reset a HoneyGas instance to a clean state (container-level rebuild).
# ----------------------------------------------------------------------------
# When: on a schedule (hygiene, e.g. daily via cron/systemd timer) and on
# demand after an analyst has finished with a session or a host-breakout signal
# fires in Wazuh (see docs/deployment-wazuh.md -> "Resetting after compromise").
#
# Why it is lossless: the audit trail and quarantine inventory are shipped to
# Wazuh in near-real-time by the host agent, so the evidence is already off-box
# in the management subnet (which the attacker cannot reach). This still
# snapshots the data dir to cold storage first, as a belt-and-suspenders, then
# recreates the instance with an EMPTY data dir so no attacker state (session
# overlays, quarantined samples) persists into the next life of the honeypot.
#
# This resets the CONTAINER + its data. For a suspected HOST compromise, prefer
# the stronger VM-level immutable rebuild (terminate + recreate from the golden
# image) documented in the deployment guide.
#
# Usage: sudo docker/rebuild.sh docker/compose.transport.yml
# ============================================================================
set -euo pipefail

COMPOSE="${1:?usage: rebuild.sh <compose-file>}"
DATA_DIR="${HONEYGAS_DATA_DIR:-/opt/honeygas/data}"
COLD_DIR="${HONEYGAS_SNAPSHOT_DIR:-/opt/honeygas/snapshots}"
UID_GID="10001:10001"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"

echo "[*] Rebuilding HoneyGas from ${COMPOSE} at ${STAMP}"

# 1. Snapshot current evidence to cold storage (best-effort).
if [ -d "${DATA_DIR}" ]; then
  mkdir -p "${COLD_DIR}"
  tar czf "${COLD_DIR}/honeygas-${STAMP}.tar.gz" -C "${DATA_DIR}" . 2>/dev/null \
    && echo "[*] Snapshot: ${COLD_DIR}/honeygas-${STAMP}.tar.gz" \
    || echo "[!] Snapshot skipped (nothing to archive)"
fi

# 2. Tear the instance down.
docker compose -f "${COMPOSE}" down --remove-orphans

# 3. Wipe and recreate a clean data dir owned by the container user.
rm -rf "${DATA_DIR:?}/"* "${DATA_DIR:?}/".[!.]* 2>/dev/null || true
install -d -o "${UID_GID%:*}" -g "${UID_GID#*:}" \
  "${DATA_DIR}/audit" "${DATA_DIR}/quarantine"

# 4. Bring a fresh instance up.
docker compose -f "${COMPOSE}" up -d --force-recreate --build

echo "[*] Done. Clean instance running from ${COMPOSE}."

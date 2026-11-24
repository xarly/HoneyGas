#!/usr/bin/env bash
# ============================================================================
# HoneyGas - all-in-one provisioner for a minimal Debian server
# ----------------------------------------------------------------------------
# Asks what MISSION the machine has and leaves every service running:
#
#   gaseoducto  -> gas-transport honeypot (transport profile)   + Wazuh agent
#   biometano   -> biomethane-plant honeypot (biomethane profile)+ Wazuh agent
#   wazuh       -> Wazuh SIEM (indexer + manager + dashboard)
#
# Run as root from a checkout of this repository:
#   sudo deploy/provision.sh
#
# Non-interactive (cloud-init / automation) via environment variables:
#   sudo MISSION=gaseoducto WAZUH_MANAGER_IP=10.20.0.10 deploy/provision.sh
#   sudo MISSION=wazuh HONEYPOT_CIDR=10.10.0.0/24 ADMIN_CIDR=10.0.0.0/24 deploy/provision.sh
#
# Optional env:
#   ADMIN_SSH_CIDR   restrict inbound SSH to this CIDR (default: open, with a warning)
#   HONEYPOT_CIDR    (wazuh) source range allowed to send agent traffic (1514/1515)
#   ADMIN_CIDR       (wazuh) source range allowed to reach the dashboard (443)
#
# DEPLOY ONLY on infrastructure and network segments you own or are authorized
# to operate. See the repository README ("Legal & ethical use").
# ============================================================================
set -euo pipefail

log()  { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

[[ "${EUID:-$(id -u)}" -eq 0 ]] || die "Ejecuta como root (sudo)."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
APP_DIR="/opt/honeygas/app"
DATA_DIR="/opt/honeygas/data"
SNAP_DIR="/opt/honeygas/snapshots"
export DEBIAN_FRONTEND=noninteractive

# --------------------------------------------------------------- mission pick
MISSION="${MISSION:-}"
if [[ -z "$MISSION" ]]; then
  if [[ -t 0 ]]; then
    echo "¿Qué misión tiene esta máquina?"
    select _m in "gaseoducto  (honeypot transporte de gas)" \
                 "biometano   (honeypot planta de biometano)" \
                 "wazuh       (SIEM / gestión)" \
                 "tpot        (sensor T-Pot: honeypots IT, feeds Wazuh)"; do
      case "${REPLY:-}" in
        1) MISSION=gaseoducto; break ;;
        2) MISSION=biometano;  break ;;
        3) MISSION=wazuh;      break ;;
        4) MISSION=tpot;       break ;;
        *) echo "Elige 1, 2, 3 o 4." ;;
      esac
    done
  else
    die "Define MISSION=gaseoducto|biometano|wazuh|tpot (no hay TTY para el menú)."
  fi
fi
case "$MISSION" in
  gaseoducto|biometano|wazuh|tpot) ;;
  *) die "MISSION inválida: '$MISSION' (usa gaseoducto|biometano|wazuh|tpot)." ;;
esac
log "Misión seleccionada: $MISSION"

# For honeypot missions we need the Wazuh manager IP for the agent.
if [[ "$MISSION" != wazuh ]]; then
  if [[ -z "${WAZUH_MANAGER_IP:-}" ]]; then
    if [[ -t 0 ]]; then
      read -rp "IP del manager Wazuh (subred de gestión): " WAZUH_MANAGER_IP
    fi
    [[ -n "${WAZUH_MANAGER_IP:-}" ]] || die "Falta WAZUH_MANAGER_IP."
  fi
fi

# ------------------------------------------------------------------ base step
base_setup() {
  log "Base: actualizando índices e instalando paquetes"
  apt-get update -y
  apt-get install -y ca-certificates curl gnupg gawk ufw
  log "Hora en UTC + NTP (systemd-timesyncd) para correlación en el SIEM"
  timedatectl set-timezone UTC || true
  timedatectl set-ntp true || true
}

install_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    log "Instalando Docker CE (script oficial)"
    curl -fsSL https://get.docker.com | sh
  fi
  systemctl enable --now docker
}

stage_repo() {
  log "Copiando el repositorio a ${APP_DIR}"
  mkdir -p "$APP_DIR"
  if [[ "$REPO_ROOT" != "$APP_DIR" ]]; then
    cp -a "${REPO_ROOT}/." "${APP_DIR}/"
  fi
  chmod +x "${APP_DIR}/docker/rebuild.sh" "${APP_DIR}/deploy/provision.sh" 2>/dev/null || true
}

# ----------------------------------------------------------- honeypot missions
append_agent_localfiles() {
  # Add the two JSON localfiles to the agent config, before </ossec_config>.
  local conf="/var/ossec/etc/ossec.conf"
  grep -q "honeygas-audit.jsonl" "$conf" 2>/dev/null && return 0
  local blocks; blocks="$(mktemp)"
  cat > "$blocks" <<'XML'
  <localfile>
    <log_format>json</log_format>
    <location>/opt/honeygas/data/audit/honeygas-audit.jsonl</location>
  </localfile>
  <localfile>
    <log_format>json</log_format>
    <location>/opt/honeygas/data/quarantine/inventory.jsonl</location>
  </localfile>
XML
  awk -v insfile="$blocks" '
    /<\/ossec_config>/ && !done { while ((getline l < insfile) > 0) print l; done=1 }
    { print }
  ' "$conf" > "${conf}.new" && mv "${conf}.new" "$conf"
  rm -f "$blocks"
}

install_wazuh_agent() {
  local group="$1" name
  name="$(hostname)-${group}"
  if [[ ! -x /var/ossec/bin/wazuh-control ]]; then
    log "Instalando Wazuh agent (manager ${WAZUH_MANAGER_IP}, grupo ${group})"
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
      | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list
    apt-get update -y
    WAZUH_MANAGER="$WAZUH_MANAGER_IP" WAZUH_AGENT_GROUP="$group" WAZUH_AGENT_NAME="$name" \
      apt-get install -y wazuh-agent
  fi
}

start_agent() {
  systemctl daemon-reload
  systemctl enable --now wazuh-agent
}

append_tpot_localfiles() {
  # Point the agent at T-Pot's on-disk honeypot logs. Paths follow T-Pot's
  # ~/tpotce/data convention; confirm the exact filenames on the box.
  local home="$1" conf="/var/ossec/etc/ossec.conf"
  grep -q "tpotce/data" "$conf" 2>/dev/null && return 0
  local blocks; blocks="$(mktemp)"
  cat > "$blocks" <<XML
  <localfile>
    <log_format>json</log_format>
    <location>${home}/tpotce/data/cowrie/log/cowrie.json</location>
  </localfile>
  <localfile>
    <log_format>json</log_format>
    <location>${home}/tpotce/data/suricata/log/eve.json</location>
  </localfile>
  <localfile>
    <log_format>json</log_format>
    <location>${home}/tpotce/data/dionaea/log/dionaea.json</location>
  </localfile>
XML
  awk -v insfile="$blocks" '
    /<\/ossec_config>/ && !done { while ((getline l < insfile) > 0) print l; done=1 }
    { print }
  ' "$conf" > "${conf}.new" && mv "${conf}.new" "$conf"
  rm -f "$blocks"
}

install_rebuild_timer() {
  local profile="$1"
  local compose="${APP_DIR}/docker/compose.${profile}.yml"
  log "Timer systemd: reconstrucción limpia diaria (higiene)"
  cat > /etc/systemd/system/honeygas-rebuild.service <<EOF
[Unit]
Description=HoneyGas scheduled clean rebuild (${profile})
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=${APP_DIR}/docker/rebuild.sh ${compose}
EOF
  cat > /etc/systemd/system/honeygas-rebuild.timer <<'EOF'
[Unit]
Description=Daily HoneyGas clean rebuild

[Timer]
OnCalendar=*-*-* 04:17:00
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now honeygas-rebuild.timer
}

deploy_honeypot() {
  local profile="$1" group="$2"
  log "Preparando volumen de datos en ${DATA_DIR}"
  install -d -o 10001 -g 10001 "${DATA_DIR}/audit" "${DATA_DIR}/quarantine" "$SNAP_DIR"
  log "Levantando el honeypot (${profile})"
  docker compose -f "${APP_DIR}/docker/compose.${profile}.yml" up --build -d
  install_wazuh_agent "$group"
  append_agent_localfiles
  start_agent
  install_rebuild_timer "$profile"
}

# -------------------------------------------------------------- wazuh mission
deploy_wazuh() {
  if [[ ! -x /var/ossec/bin/wazuh-control ]]; then
    log "Instalando Wazuh all-in-one (indexer + manager + dashboard)"
    warn "Requiere ~4 GB de RAM. La contraseña del dashboard se imprime al final"
    warn "y queda en wazuh-install-files.tar (usuario 'admin')."
    curl -fsSL https://packages.wazuh.com/4.x/wazuh-install.sh -o /root/wazuh-install.sh
    bash /root/wazuh-install.sh -a
  fi
  log "Creando grupos de agentes: gaseoducto, biometano, tpot"
  for g in gaseoducto biometano tpot; do
    mkdir -p "/var/ossec/etc/shared/${g}"
  done
  chown -R wazuh:wazuh /var/ossec/etc/shared 2>/dev/null || true
  log "Instalando reglas de detección (HoneyGas + T-Pot)"
  cat "${APP_DIR}/wazuh/local_rules.xml" > /var/ossec/etc/rules/local_rules.xml
  [[ -f "${APP_DIR}/wazuh/local_rules_tpot.xml" ]] && \
    cat "${APP_DIR}/wazuh/local_rules_tpot.xml" >> /var/ossec/etc/rules/local_rules.xml
  chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml 2>/dev/null || true
  systemctl restart wazuh-manager
}

# --------------------------------------------------------------- tpot mission
disable_tpot_service() {
  local f="$1" svc="$2"
  [[ -f "$f" ]] || { warn "No existe ${f}; desactiva '${svc}' a mano."; return 1; }
  apt-get install -y python3 python3-yaml >/dev/null 2>&1 || true
  if command -v python3 >/dev/null 2>&1 && python3 -c 'import yaml' >/dev/null 2>&1; then
    python3 - "$f" "$svc" <<'PY'
import sys, yaml
path, svc = sys.argv[1], sys.argv[2]
with open(path) as fh:
    doc = yaml.safe_load(fh) or {}
services = doc.get("services", {})
if svc in services:
    del services[svc]
    with open(path, "w") as fh:
        yaml.safe_dump(doc, fh, default_flow_style=False, sort_keys=False)
    print("removed:", svc)
else:
    print("not present:", svc)
PY
  else
    warn "python3/pyyaml no disponible: elimina el bloque '${svc}:' de ${f} a mano."
    return 1
  fi
}

deploy_tpot() {
  local tpot_user="${TPOT_USER:-tpot}" tpot_home
  if ! id "$tpot_user" >/dev/null 2>&1; then
    log "Creando usuario ${tpot_user} para T-Pot"
    adduser --disabled-password --gecos "" "$tpot_user" >/dev/null
  fi
  tpot_home="$(getent passwd "$tpot_user" | cut -d: -f6)"
  echo "${tpot_user} ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/${tpot_user}"
  chmod 440 "/etc/sudoers.d/${tpot_user}"

  log "Instalando el agente Wazuh (grupo tpot) apuntando a los logs de T-Pot"
  install_wazuh_agent tpot
  append_tpot_localfiles "$tpot_home"
  start_agent

  if [[ ! -d "${tpot_home}/tpotce" ]]; then
    log "Instalando T-Pot (edición sensor) como ${tpot_user} — NECESITA salida a internet"
    warn "T-Pot cambiará el SSH a 64295 y la UI a 64297, y requiere reinicio."
    su - "$tpot_user" -c 'git clone https://github.com/telekom-security/tpotce && cd tpotce && ./install.sh -s -t s'
  else
    warn "Ya existe ${tpot_home}/tpotce; omito la instalación de T-Pot."
  fi

  if [[ -z "${TPOT_KEEP_CONPOT:-}" ]]; then
    log "Desactivando Conpot (HoneyGas es el ICS de alta fidelidad)"
    disable_tpot_service "${tpot_home}/tpotce/docker-compose.yml" conpot || true
  fi
}

# ----------------------------------------------------------------- firewall
apply_firewall() {
  if [[ "$MISSION" == tpot ]]; then
    warn "T-Pot gestiona su propio firewall (firewalld) y necesita egress abierto + inbound amplio."
    warn "No aplico ufw. En la SG de nube: inbound de señuelo permitido, 64295/64297 solo al admin, egress abierto."
    return 0
  fi
  log "Aplicando firewall (ufw)"
  ufw --force reset >/dev/null
  ufw default deny incoming >/dev/null

  if [[ -n "${ADMIN_SSH_CIDR:-}" ]]; then
    ufw allow from "$ADMIN_SSH_CIDR" to any port 22 proto tcp >/dev/null
  else
    warn "SSH abierto a cualquier origen. Define ADMIN_SSH_CIDR para restringirlo a un bastión."
    ufw allow 22/tcp >/dev/null
  fi

  case "$MISSION" in
    gaseoducto|biometano)
      # Egress locked: only the SIEM, DNS and NTP leave the box.
      ufw default deny outgoing >/dev/null
      local ports=(502 102 2404 20000 8080)
      [[ "$MISSION" == gaseoducto ]] && ports+=(10001)
      # (Container-published ports are already reachable via Docker; opened here
      #  for clarity and for hosts without docker-proxy.)
      for p in "${ports[@]}"; do ufw allow "${p}/tcp" >/dev/null; done
      ufw allow out to "$WAZUH_MANAGER_IP" port 1514 proto tcp >/dev/null
      ufw allow out to "$WAZUH_MANAGER_IP" port 1515 proto tcp >/dev/null
      ufw allow out 53 >/dev/null
      ufw allow out 123/udp >/dev/null
      ;;
    wazuh)
      ufw default allow outgoing >/dev/null
      local dmz="${HONEYPOT_CIDR:-any}"
      ufw allow from "$dmz" to any port 1514 proto tcp >/dev/null
      ufw allow from "$dmz" to any port 1515 proto tcp >/dev/null
      if [[ -n "${ADMIN_CIDR:-}" ]]; then
        ufw allow from "$ADMIN_CIDR" to any port 443 proto tcp >/dev/null
      else
        warn "Dashboard (443) no abierto: define ADMIN_CIDR para permitir el acceso del administrador."
      fi
      ;;
  esac
  ufw --force enable >/dev/null
}

# -------------------------------------------------------------------- summary
summary() {
  echo
  log "===================== HoneyGas listo (${MISSION}) ====================="
  local profile
  [[ "$MISSION" == gaseoducto ]] && profile=transport || profile=biomethane
  case "$MISSION" in
    gaseoducto|biometano)
      docker compose -f "${APP_DIR}/docker/compose.${profile}.yml" ps 2>/dev/null || true
      echo "Agente Wazuh : $(systemctl is-active wazuh-agent 2>/dev/null || echo desconocido)"
      echo "Timer reinicio: $(systemctl is-active honeygas-rebuild.timer 2>/dev/null || echo desconocido)"
      echo "Datos         : ${DATA_DIR}  (auditoría + cuarentena)"
      echo "Reinicio manual: sudo ${APP_DIR}/docker/rebuild.sh ${APP_DIR}/docker/compose.<perfil>.yml"
      ;;
    wazuh)
      echo "Manager Wazuh : $(systemctl is-active wazuh-manager 2>/dev/null || echo desconocido)"
      echo "Dashboard     : https://<esta-IP>  (usuario admin; contraseña en wazuh-install-files.tar)"
      echo "Reglas        : /var/ossec/etc/rules/local_rules.xml"
      ;;
    tpot)
      echo "T-Pot         : instalado (edición sensor); se reinicia para activarse"
      echo "Admin SSH     : puerto 64295    |    UI T-Pot: https://<esta-IP>:64297"
      echo "Agente Wazuh  : $(systemctl is-active wazuh-agent 2>/dev/null || echo desconocido) (grupo tpot)"
      echo "Logs T-Pot    : ${TPOT_USER:-tpot} -> ~/tpotce/data (ingeridos por el agente)"
      ;;
  esac
  echo "Firewall      : $(ufw status | head -n1)"
  log "======================================================================"
}

# ------------------------------------------------------------------- run it
base_setup
case "$MISSION" in
  gaseoducto) install_docker; stage_repo; deploy_honeypot transport  gaseoducto ;;
  biometano)  install_docker; stage_repo; deploy_honeypot biomethane biometano ;;
  wazuh)      stage_repo; deploy_wazuh ;;
  tpot)       stage_repo; deploy_tpot ;;
esac
apply_firewall
summary

if [[ "$MISSION" == tpot && -z "${TPOT_SKIP_REBOOT:-}" ]]; then
  warn "T-Pot requiere reinicio para activarse. Reiniciando en 10 s (TPOT_SKIP_REBOOT=1 para omitir)."
  sleep 10 || true
  reboot
fi

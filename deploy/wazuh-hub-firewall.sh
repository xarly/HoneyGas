#!/usr/bin/env bash
# ============================================================================
# Host firewall for the Wazuh hub (multi-provider topology, Ubuntu/Debian with
# iptables). See docs/deployment-wazuh.md section 4.
# ----------------------------------------------------------------------------
# Self-contained: it does not rely on whatever firewall the provider's image
# ships. It adds its own chains at the TOP of INPUT/FORWARD/OUTPUT and leaves
# any existing rules in place (some cloud images ship rules the VM needs to
# reach its metadata, DNS and NTP services: never flush them).
#
#   INPUT   public side: loopback, replies to the hub's own connections, DHCP
#           and udp/WG_PORT (WireGuard: silent to unauthenticated packets, so
#           the hub shows no open port to scanners). Everything else DROPPED,
#           including public SSH: run this only once SSH over the overlay works.
#   INPUT   from wg0: honeypots -> 1514/1515 (agent) + 123/udp (NTP) only;
#           admin -> 22 (SSH) + 443 (dashboard)
#   FORWARD wg0 -> wg0: admin -> honeypots:22 only. Honeypots can never reach
#           each other or the admin. Nothing else is routed.
#   OUTPUT  to honeypots: no NEW connections (the SIEM never initiates to the
#           sacrificial boxes; replies to their connections still flow).
#
# Keep the provider's cloud firewall as the outer wall: ingress udp/WG_PORT
# only (plus tcp/22 until the overlay works).
#
# Idempotent: safe to re-run after editing the variables.
# Usage: sudo deploy/wazuh-hub-firewall.sh
#        sudo HONEYPOTS="10.99.0.11 10.99.0.12" ADMIN=10.99.0.100 deploy/wazuh-hub-firewall.sh
# ============================================================================
set -euo pipefail

WG_IF="${WG_IF:-wg0}"
WG_PORT="${WG_PORT:-51820}"
HONEYPOTS="${HONEYPOTS:-10.99.0.11 10.99.0.12}"
ADMIN="${ADMIN:-10.99.0.100}"

[ "$(id -u)" -eq 0 ] || { echo "[!] run as root" >&2; exit 1; }

# Our chains, flushed on every run.
for c in HG-PUBLIC-IN HG-WG-IN HG-WG-FWD HG-WG-OUT; do
  iptables -N "$c" 2>/dev/null || iptables -F "$c"
done

# (Re)insert a rule at the top of a built-in chain, removing old copies first.
rehook() {
  local chain="$1"; shift
  while iptables -D "$chain" "$@" 2>/dev/null; do :; done
  iptables -I "$chain" 1 "$@"
}

# Inserted in reverse: the overlay jump ends up first, the public jump second.
rehook INPUT   ! -i "$WG_IF" -j HG-PUBLIC-IN
rehook INPUT   -i "$WG_IF" -j HG-WG-IN
rehook FORWARD -j HG-WG-FWD
rehook OUTPUT  -o "$WG_IF" -j HG-WG-OUT

# --- public interface(s) -----------------------------------------------------
iptables -A HG-PUBLIC-IN -i lo -j ACCEPT
iptables -A HG-PUBLIC-IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A HG-PUBLIC-IN -p udp --sport 67 --dport 68 -j ACCEPT
iptables -A HG-PUBLIC-IN -p udp --dport "$WG_PORT" -j ACCEPT
iptables -A HG-PUBLIC-IN -j DROP

# --- traffic arriving through the overlay -----------------------------------
iptables -A HG-WG-IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
for hp in $HONEYPOTS; do
  iptables -A HG-WG-IN -s "$hp" -p tcp -m multiport --dports 1514,1515 -j ACCEPT
  iptables -A HG-WG-IN -s "$hp" -p udp --dport 123 -j ACCEPT
done
iptables -A HG-WG-IN -s "$ADMIN" -p tcp -m multiport --dports 22,443 -j ACCEPT
iptables -A HG-WG-IN -s "$ADMIN" -p icmp -j ACCEPT
iptables -A HG-WG-IN -m limit --limit 6/min -j LOG --log-prefix "HONEYGAS-HUB-DENY "
iptables -A HG-WG-IN -j DROP

# --- routing (admin -> honeypot SSH through the overlay, nothing else) -------
iptables -A HG-WG-FWD -i "$WG_IF" -o "$WG_IF" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
for hp in $HONEYPOTS; do
  iptables -A HG-WG-FWD -i "$WG_IF" -o "$WG_IF" -s "$ADMIN" -d "$hp" -p tcp --dport 22 -j ACCEPT
done
iptables -A HG-WG-FWD -m limit --limit 6/min -j LOG --log-prefix "HONEYGAS-HUB-FWD-DENY "
iptables -A HG-WG-FWD -j DROP

# --- the hub itself never opens connections to the honeypots -----------------
for hp in $HONEYPOTS; do
  iptables -A HG-WG-OUT -d "$hp" -m conntrack --ctstate NEW -j DROP
done

# IPv6 is not used by the overlay or the agents: close it on the public side.
if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -N HG-PUBLIC-IN6 2>/dev/null || ip6tables -F HG-PUBLIC-IN6
  while ip6tables -D INPUT -j HG-PUBLIC-IN6 2>/dev/null; do :; done
  ip6tables -I INPUT 1 -j HG-PUBLIC-IN6
  ip6tables -A HG-PUBLIC-IN6 -i lo -j ACCEPT
  ip6tables -A HG-PUBLIC-IN6 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ip6tables -A HG-PUBLIC-IN6 -p ipv6-icmp -j ACCEPT    # neighbour discovery
  ip6tables -A HG-PUBLIC-IN6 -j DROP
fi

# Routing is needed only for the admin -> honeypot SSH path.
echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-honeygas-wg.conf
sysctl -q -p /etc/sysctl.d/99-honeygas-wg.conf

if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save >/dev/null
  echo "[*] Rules applied and persisted (netfilter-persistent)."
else
  echo "[!] Rules applied but NOT persisted: install iptables-persistent and re-run." >&2
fi

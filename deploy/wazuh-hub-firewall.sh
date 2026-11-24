#!/usr/bin/env bash
# ============================================================================
# Host firewall for the Wazuh hub (multi-provider topology, Ubuntu/Debian with
# iptables). See docs/deployment-wazuh.md sections 4 and 8.
# ----------------------------------------------------------------------------
# Self-contained: it does not rely on whatever firewall the provider's image
# ships. It adds its own chains at the TOP of INPUT/FORWARD/OUTPUT and leaves
# any existing rules in place (some cloud images ship rules the VM needs to
# reach its metadata, DNS and NTP services: never flush them).
#
#   INPUT   public side: loopback, replies to the hub's own connections, DHCP,
#           and (WireGuard only) udp/WG_PORT, silent to unauthenticated
#           packets. Everything else DROPPED, including public SSH: run this
#           only once SSH over the overlay works.
#   INPUT   from the overlay: honeypots -> 1514/1515 (agent) + 123/udp (NTP)
#           only; admin device(s) -> 22 (SSH) + 443 (dashboard)
#   FORWARD WireGuard: admin -> honeypots:22 only, routed by the hub.
#           Tailscale: nothing (admins reach the honeypots directly).
#           Honeypots can never reach each other or the admin.
#   OUTPUT  to honeypots: no NEW connections (the SIEM never initiates to the
#           sacrificial boxes; replies to their connections still flow).
#
# Keep the provider's cloud firewall as the outer wall: ingress udp/WG_PORT
# only with WireGuard, nothing at all with Tailscale (plus tcp/22 until the
# overlay works).
#
# Idempotent: safe to re-run after editing the variables.
# Usage (WireGuard, default addresses):
#   sudo deploy/wazuh-hub-firewall.sh
# Usage (Tailscale; addresses from `tailscale ip -4` on each node):
#   sudo OVERLAY=tailscale HONEYPOTS="100.x.y.1 100.x.y.2" ADMIN="100.x.y.9" \
#        deploy/wazuh-hub-firewall.sh
# ============================================================================
set -euo pipefail

OVERLAY="${OVERLAY:-wireguard}"
WG_PORT="${WG_PORT:-51820}"
case "$OVERLAY" in
  wireguard)
    OVERLAY_IF="${OVERLAY_IF:-wg0}"
    HONEYPOTS="${HONEYPOTS:-10.99.0.11 10.99.0.12}"
    ADMIN="${ADMIN:-10.99.0.100}"
    ;;
  tailscale)
    OVERLAY_IF="${OVERLAY_IF:-tailscale0}"
    : "${HONEYPOTS:?set HONEYPOTS to the Tailscale IPs of the honeypots}"
    : "${ADMIN:?set ADMIN to the Tailscale IPs of your admin devices}"
    ;;
  *)
    echo "[!] OVERLAY must be 'wireguard' or 'tailscale'" >&2; exit 1
    ;;
esac

[ "$(id -u)" -eq 0 ] || { echo "[!] run as root" >&2; exit 1; }

# Our chains, flushed on every run.
for c in HG-PUBLIC-IN HG-OVERLAY-IN HG-OVERLAY-FWD HG-OVERLAY-OUT; do
  iptables -N "$c" 2>/dev/null || iptables -F "$c"
done

# (Re)insert a rule at the top of a built-in chain, removing old copies first.
rehook() {
  local chain="$1"; shift
  while iptables -D "$chain" "$@" 2>/dev/null; do :; done
  iptables -I "$chain" 1 "$@"
}

# Inserted in reverse: the overlay jump ends up first, the public jump second.
rehook INPUT   ! -i "$OVERLAY_IF" -j HG-PUBLIC-IN
rehook INPUT   -i "$OVERLAY_IF" -j HG-OVERLAY-IN
rehook FORWARD -j HG-OVERLAY-FWD
rehook OUTPUT  -o "$OVERLAY_IF" -j HG-OVERLAY-OUT

# --- public interface(s) -----------------------------------------------------
iptables -A HG-PUBLIC-IN -i lo -j ACCEPT
iptables -A HG-PUBLIC-IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A HG-PUBLIC-IN -p udp --sport 67 --dport 68 -j ACCEPT
if [ "$OVERLAY" = wireguard ]; then
  iptables -A HG-PUBLIC-IN -p udp --dport "$WG_PORT" -j ACCEPT
fi
iptables -A HG-PUBLIC-IN -j DROP

# --- traffic arriving through the overlay -----------------------------------
iptables -A HG-OVERLAY-IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
for hp in $HONEYPOTS; do
  iptables -A HG-OVERLAY-IN -s "$hp" -p tcp -m multiport --dports 1514,1515 -j ACCEPT
  iptables -A HG-OVERLAY-IN -s "$hp" -p udp --dport 123 -j ACCEPT
done
for adm in $ADMIN; do
  iptables -A HG-OVERLAY-IN -s "$adm" -p tcp -m multiport --dports 22,443 -j ACCEPT
  iptables -A HG-OVERLAY-IN -s "$adm" -p icmp -j ACCEPT
done
iptables -A HG-OVERLAY-IN -m limit --limit 6/min -j LOG --log-prefix "HONEYGAS-HUB-DENY "
iptables -A HG-OVERLAY-IN -j DROP

# --- routing: WireGuard admin -> honeypot SSH only; Tailscale none -----------
if [ "$OVERLAY" = wireguard ]; then
  iptables -A HG-OVERLAY-FWD -i "$OVERLAY_IF" -o "$OVERLAY_IF" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  for adm in $ADMIN; do
    for hp in $HONEYPOTS; do
      iptables -A HG-OVERLAY-FWD -i "$OVERLAY_IF" -o "$OVERLAY_IF" -s "$adm" -d "$hp" -p tcp --dport 22 -j ACCEPT
    done
  done
fi
iptables -A HG-OVERLAY-FWD -m limit --limit 6/min -j LOG --log-prefix "HONEYGAS-HUB-FWD-DENY "
iptables -A HG-OVERLAY-FWD -j DROP

# --- the hub itself never opens connections to the honeypots -----------------
for hp in $HONEYPOTS; do
  iptables -A HG-OVERLAY-OUT -d "$hp" -m conntrack --ctstate NEW -j DROP
done

# IPv6 is not used by the overlay or the agents: close it on every interface.
if command -v ip6tables >/dev/null 2>&1; then
  ip6tables -N HG-PUBLIC-IN6 2>/dev/null || ip6tables -F HG-PUBLIC-IN6
  while ip6tables -D INPUT -j HG-PUBLIC-IN6 2>/dev/null; do :; done
  ip6tables -I INPUT 1 -j HG-PUBLIC-IN6
  ip6tables -A HG-PUBLIC-IN6 -i lo -j ACCEPT
  ip6tables -A HG-PUBLIC-IN6 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ip6tables -A HG-PUBLIC-IN6 -p ipv6-icmp -j ACCEPT    # neighbour discovery
  ip6tables -A HG-PUBLIC-IN6 -j DROP
fi

# Routing is needed only for the WireGuard admin -> honeypot SSH path.
if [ "$OVERLAY" = wireguard ]; then
  echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-honeygas-wg.conf
  sysctl -q -p /etc/sysctl.d/99-honeygas-wg.conf
fi

if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save >/dev/null
  echo "[*] Rules applied (${OVERLAY}) and persisted (netfilter-persistent)."
else
  echo "[!] Rules applied (${OVERLAY}) but NOT persisted: install iptables-persistent and re-run." >&2
fi

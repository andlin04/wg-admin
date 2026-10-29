#!/bin/bash
# wg-admin install (map wg-admin-package): WireGuard server + nftables + wg-admin web UI on one Debian 12/13 host.
# Idempotent; run as root from this directory (it holds every file it installs):
#   bash install.sh [--endpoint HOST:PORT] [--hostname FQDN]
#   --endpoint  what client configs connect to (kept in /etc/wireguard/vpn.env; omitted = kept, or set it later in
#               the Server view). --hostname: TLS certificate name (default `hostname -f`).
# Host settings go to /etc/wireguard/vpn.env once, detected from this host; set any of them in the environment to
# override (also on later runs): LAN_IF, GATEWAY, GATEWAY_NAME, DNS_CHECK ("SERVER NAME"), CLIENT_DNS, SPLIT_ROUTES,
# NAT4 (on|off), TRANSIT_IF + TRANSIT_GW (NAT4=off: peers' IPv4 policy-routed out TRANSIT_IF to TRANSIT_GW).
# Server > Network in the UI changes NAT4, LAN_IF, TRANSIT_IF, TRANSIT_GW later (vpn-peer network-set).
# Tunnel 10.66.0.0/24 + fd66:66::/64 (server .1 / ::1), UDP 51820. Clients get their profile's routes (enforced here
# by nftables, written by vpn-peer); with NAT4=on (default) this host masquerades their traffic, so the router needs
# only the UDP port forward; NAT4=off routes their IPv4 (the router needs a route for 10.66.0.0/24 to this host). Web UI: nginx TLS on :8443 -> wg-admin on 127.0.0.1:8080. Undo: uninstall.sh. Homelab: setup-vpn1.sh.
set -euo pipefail
cd "$(dirname "$0")"

endpoint="" fqdn=""
while [ $# -gt 0 ]; do
  case $1 in
    --endpoint) endpoint=${2:?--endpoint HOST:PORT}; shift 2 ;;
    --hostname) fqdn=${2:?--hostname FQDN}; shift 2 ;;
    *) echo "usage: install.sh [--endpoint HOST:PORT] [--hostname FQDN]" >&2; exit 2 ;;
  esac
done
fqdn=${fqdn:-$(hostname -f 2>/dev/null || hostname)}
[ "$(id -u)" = 0 ] || { echo "install.sh: run as root" >&2; exit 1; }

DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard-tools nftables qrencode dnsutils iputils-ping age \
  python3-fastapi python3-uvicorn sudo openssl nginx >/dev/null

# ---------------------------------------------------------------- WireGuard
# Only for new directories (rule:shared-dir-perms); wireguard-tools may already have made /etc/wireguard (700).
for d in /etc/wireguard /etc/wireguard/clients; do [ -d "$d" ] || install -d -m 700 "$d"; done
ENV=/etc/wireguard/vpn.env
[ -f "$ENV" ] || (umask 077; : > "$ENV")
has() { grep -q "^$1=" "$ENV"; }
setenv() {  # KEY VALUE: replace or add one line; other keys (KEEPALIVE from the Server view) stay
  (umask 077; { grep -v "^$1=" "$ENV" || true; echo "$1=$2"; } > "$ENV.new")
  mv "$ENV.new" "$ENV"
}
route=$(ip -4 route show default | head -n1)
lan_if=$(awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}' <<<"$route")
gw=$(awk '{print $3; exit}' <<<"$route")
dns=$(awk '$1 == "nameserver" && $2 !~ /^127\./ {print $2; exit}' /etc/resolv.conf 2>/dev/null || true)
dns=${dns:-$gw}
net=$(ip -4 route show dev "${LAN_IF:-$lan_if}" scope link proto kernel 2>/dev/null | awk '{print $1; exit}')
declare -A default=([LAN_IF]=$lan_if [GATEWAY]=$gw [GATEWAY_NAME]=Gateway [DNS_CHECK]="$dns deb.debian.org"
                    [CLIENT_DNS]=$dns [SPLIT_ROUTES]=$net [NAT4]=on [TRANSIT_IF]= [TRANSIT_GW]=)
for k in LAN_IF GATEWAY GATEWAY_NAME DNS_CHECK CLIENT_DNS SPLIT_ROUTES NAT4 TRANSIT_IF TRANSIT_GW; do
  if [ -n "${!k:-}" ]; then setenv "$k" "${!k}"; elif ! has "$k"; then setenv "$k" "${default[$k]}"; fi
done
[ -n "$endpoint" ] && setenv ENDPOINT "$endpoint"
has ENDPOINT || setenv ENDPOINT ""
LAN=$(sed -n 's/^LAN_IF=//p' "$ENV" | head -n1)
[ -n "$LAN" ] && ip link show "$LAN" >/dev/null 2>&1 || { echo "install.sh: LAN_IF '$LAN' not found" >&2; exit 1; }

if [ ! -f /etc/wireguard/server.key ]; then
  (umask 077; wg genkey > /etc/wireguard/server.key)
  wg pubkey < /etc/wireguard/server.key > /etc/wireguard/server.pub
fi
# PrivateKey belongs in wg0.conf: vpn-peer's `wg syncconf` clears a key that only a PostUp line had set (2026-10-26).
if [ ! -f /etc/wireguard/wg0.conf ]; then
  (umask 077; cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
Address = 10.66.0.1/24, fd66:66::1/64
ListenPort = 51820
PrivateKey = $(cat /etc/wireguard/server.key)
EOF
)
fi
# accept_ra=2 keeps the LAN interface taking router advertisements while forwarding (IPv6 profiles).
printf '%s\n' 'net.ipv4.ip_forward = 1' 'net.ipv6.conf.all.forwarding = 1' "net.ipv6.conf.$LAN.accept_ra = 2" \
  > /etc/sysctl.d/90-wireguard.conf.new
# Applied only when the file changes or forwarding is off: each sysctl run raised a Defend "Suspicious Kernel Feature
# Activity" alert (2026-10-28/29); boot applies the file through systemd-sysctl.
if ! cmp -s /etc/sysctl.d/90-wireguard.conf.new /etc/sysctl.d/90-wireguard.conf ||
   [ "$(cat /proc/sys/net/ipv4/ip_forward)" != 1 ]; then
  mv /etc/sysctl.d/90-wireguard.conf.new /etc/sysctl.d/90-wireguard.conf
  sysctl -q -p /etc/sysctl.d/90-wireguard.conf
else
  rm /etc/sysctl.d/90-wireguard.conf.new
fi

# ---------------------------------------------------------------- firewall + CLI
install -m 755 vpn-peer.sh /usr/local/sbin/vpn-peer
install -m 755 vpn-gate.sh /usr/local/sbin/vpn-gate
# vpn-peer keeps one table (inet wgadmin) in /etc/nftables.d/wgadmin.nft; nftables.conf loads it at boot through
# the include line, appended once (marked, so uninstall.sh can take it out).
mkdir -p /etc/nftables.d
if [ ! -f /etc/nftables.conf ]; then
  printf '%s\n' '#!/usr/sbin/nft -f' 'flush ruleset' > /etc/nftables.conf
fi
if ! grep -q 'nftables.d' /etc/nftables.conf; then
  printf '%s\n' 'include "/etc/nftables.d/*.nft"  # wg-admin' >> /etc/nftables.conf
fi
# vpn-peer owns the transit policy routing (two ip rules, table 66). systemd-networkd removes rules and routes it
# did not make on every restart (netplan apply), so it is told to leave them.
if systemctl is-active -q systemd-networkd; then
  mkdir -p /etc/systemd/networkd.conf.d
  printf '%s\n' '# wg-admin (vpn-peer routing): keep the transit policy rules and table 66 on networkd restarts.' \
    '[Network]' 'ManageForeignRoutingPolicyRules=no' 'ManageForeignRoutes=no' > /etc/systemd/networkd.conf.d/wg-admin.conf.new
  if ! cmp -s /etc/systemd/networkd.conf.d/wg-admin.conf.new /etc/systemd/networkd.conf.d/wg-admin.conf; then
    mv /etc/systemd/networkd.conf.d/wg-admin.conf.new /etc/systemd/networkd.conf.d/wg-admin.conf
    systemctl restart systemd-networkd
  else
    rm /etc/systemd/networkd.conf.d/wg-admin.conf.new
  fi
fi
/usr/local/sbin/vpn-peer firewall
# Disabled peers: wg-quick loads all of wg0.conf at boot; vpn-peer sync drops them right after. The firewall already
# leaves them out of every peer set, so the gap only allows a handshake, no traffic.
mkdir -p /etc/systemd/system/wg-quick@wg0.service.d
printf '%s\n' '[Service]' 'ExecStartPost=/usr/local/sbin/vpn-peer sync' \
  > /etc/systemd/system/wg-quick@wg0.service.d/vpn-peer.conf

# ---------------------------------------------------------------- wg-admin (user wgadmin, root only via vpn-gate)
id wgadmin >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin wgadmin
echo 'wgadmin ALL=(root) NOPASSWD: /usr/local/sbin/vpn-gate' > /etc/sudoers.d/wg-admin
chmod 440 /etc/sudoers.d/wg-admin; visudo -cq -f /etc/sudoers.d/wg-admin
[ -d /etc/wg-admin ] || install -d -m 750 -o root -g wgadmin /etc/wg-admin
chgrp wgadmin /etc/wg-admin  # a reinstall after uninstall.sh (data kept) gets a new wgadmin group id
rm -rf /opt/wg-admin.new; mkdir -p /opt/wg-admin.new
cp -r wgadmin /opt/wg-admin.new/; find /opt/wg-admin.new -name __pycache__ -prune -exec rm -rf {} +
rm -rf /opt/wg-admin; mv /opt/wg-admin.new /opt/wg-admin
# App settings (config.py): empty = standalone (local logins only, audit to the journal). setup-vpn1.sh writes the
# homelab portal's values.
if [ ! -f /etc/wg-admin/wg-admin.env ]; then
  printf '%s\n' '# wg-admin settings (deploy/vpn/wgadmin/config.py). Portal SSO: proxy IPs + /etc/wg-admin/portal.secret.' \
    'WGADMIN_TRUSTED_PROXIES=' 'WGADMIN_EVENT_URL=' 'WGADMIN_CA_FILE=' > /etc/wg-admin/wg-admin.env
fi
# Local logins and API tokens (`sudo -u wgadmin python3 -m wgadmin set-password|token NAME` in /opt/wg-admin),
# mail settings and the SMTP relay password (Server > Mail writes them in place), authenticators (Account) and
# access schedules (Schedules). wgadmin cannot create files here: each is created once, then written in place.
for f in users.json tokens.json mail.json totp.json schedules.json; do
  [ -f /etc/wg-admin/$f ] || (umask 077; echo '{}' > /etc/wg-admin/$f)
  chown wgadmin:wgadmin /etc/wg-admin/$f
done
[ -f /etc/wg-admin/smtp.secret ] || (umask 077; : > /etc/wg-admin/smtp.secret)
chown wgadmin:wgadmin /etc/wg-admin/smtp.secret; chmod 600 /etc/wg-admin/smtp.secret

# TLS for nginx: the key never leaves this host. Without a cert: a self-signed one (825 days) so the UI works at
# once. A CSR (tls.csr) is left while the cert is self-signed or has under 30 days left; sign it with your CA and
# write the result to /etc/wg-admin/tls.crt, then `systemctl reload nginx`.
if [ ! -f /etc/wg-admin/tls.key ]; then
  (umask 077; openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /etc/wg-admin/tls.key 2>/dev/null)
fi
chown root:wgadmin /etc/wg-admin/tls.key; chmod 640 /etc/wg-admin/tls.key
selfsigned() { [ "$(openssl x509 -noout -issuer -nameopt compat -in "$1" | sed 's/^issuer=//')" = \
                 "$(openssl x509 -noout -subject -nameopt compat -in "$1" | sed 's/^subject=//')" ]; }
if [ ! -f /etc/wg-admin/tls.crt ] || { selfsigned /etc/wg-admin/tls.crt \
     && ! openssl x509 -checkend $((30 * 86400)) -noout -in /etc/wg-admin/tls.crt >/dev/null 2>&1; }; then
  openssl req -x509 -key /etc/wg-admin/tls.key -subj "/CN=$fqdn" -days 825 -addext "subjectAltName=DNS:$fqdn" \
    -out /etc/wg-admin/tls.crt 2>/dev/null
fi
if selfsigned /etc/wg-admin/tls.crt || ! openssl x509 -checkend $((30 * 86400)) -noout -in /etc/wg-admin/tls.crt >/dev/null 2>&1
then
  openssl req -new -key /etc/wg-admin/tls.key -subj "/CN=$fqdn" -addext "subjectAltName=DNS:$fqdn" \
    -out /etc/wg-admin/tls.csr 2>/dev/null
fi

install -m 644 wg-admin.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable -q nftables wg-quick@wg0 wg-admin
systemctl restart nftables
systemctl is-active -q wg-quick@wg0 || systemctl start wg-quick@wg0
systemctl restart wg-admin
# Prometheus metrics only where node_exporter's textfile collector runs (found missing on a clean test guest).
if [ -d /var/lib/prometheus/node-exporter ]; then
  install -m 755 wg-metrics.sh /usr/local/sbin/wg-metrics
  install -m 644 wg-metrics.service wg-metrics.timer /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable -q --now wg-metrics.timer
  systemctl start wg-metrics.service
fi
# nginx terminates TLS on :8443; started after wg-admin left :8443 for 127.0.0.1:8080 (older installs). Only this
# site is enabled (Debian's default site on :80 is switched off; its file stays in sites-available).
install -m 644 wg-admin.nginx.conf /etc/nginx/sites-available/wg-admin
ln -sf ../sites-available/wg-admin /etc/nginx/sites-enabled/wg-admin
rm -f /etc/nginx/sites-enabled/default
nginx -tq
systemctl enable -q nginx
systemctl reload-or-restart nginx

echo "wg-admin: wg0 $(ip -4 -o addr show wg0 | awk '{print $4}'), peers $(wg show wg0 peers | wc -l)," \
  "port $(wg show wg0 listen-port), UI https://$fqdn:8443/"

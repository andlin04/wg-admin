#!/bin/bash
# wg-admin uninstall: removes what install.sh put on this host. Run as root:
#   bash uninstall.sh            keep the data (/etc/wireguard: keys, peers, profiles; /etc/wg-admin: logins, TLS)
#   bash uninstall.sh --purge    also delete that data (every key and client config; export it first:
#                                `vpn-peer export FILE`)
# wg0 is always stopped and disabled: without wg-admin's firewall table its peers would reach everything.
# Debian packages (wireguard-tools, nftables, nginx, python3-fastapi, ...) stay; remove them with apt if unused.
set -euo pipefail

purge=0
case ${1:-} in
  "") ;;
  --purge) purge=1 ;;
  *) echo "usage: uninstall.sh [--purge]" >&2; exit 2 ;;
esac
[ "$(id -u)" = 0 ] || { echo "uninstall.sh: run as root" >&2; exit 1; }

systemctl disable -q --now wg-admin wg-metrics.timer wg-quick@wg0 2>/dev/null || true
systemctl stop wg-metrics.service 2>/dev/null || true
rm -f /etc/systemd/system/wg-admin.service /etc/systemd/system/wg-metrics.service /etc/systemd/system/wg-metrics.timer
rm -rf /etc/systemd/system/wg-quick@wg0.service.d
systemctl daemon-reload

rm -f /etc/nginx/sites-enabled/wg-admin /etc/nginx/sites-available/wg-admin
if systemctl is-active -q nginx; then
  if [ -z "$(ls -A /etc/nginx/sites-enabled 2>/dev/null)" ]; then systemctl disable -q --now nginx  # nothing else served
  else nginx -tq && systemctl reload nginx; fi
fi

nft delete table inet wgadmin 2>/dev/null || true
rm -f /etc/nftables.d/wgadmin.nft
[ ! -f /etc/nftables.conf ] || sed -i '/^include "\/etc\/nftables.d\/\*.nft"  # wg-admin$/d' /etc/nftables.conf
rm -f /etc/sysctl.d/90-wireguard.conf  # forwarding stays on until the next reboot (or sysctl net.ipv4.ip_forward=0)

rm -rf /opt/wg-admin /opt/wg-admin.new
rm -f /usr/local/sbin/vpn-peer /usr/local/sbin/vpn-gate /usr/local/sbin/wg-metrics /etc/sudoers.d/wg-admin
rm -f /var/lib/prometheus/node-exporter/wireguard.prom
id wgadmin >/dev/null 2>&1 && userdel wgadmin

if [ "$purge" = 1 ]; then
  rm -rf /etc/wireguard /etc/wg-admin
  echo "wg-admin removed, data deleted"
else
  echo "wg-admin removed; data kept in /etc/wireguard and /etc/wg-admin (reinstall: install.sh)"
fi

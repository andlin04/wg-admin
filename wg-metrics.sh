#!/bin/bash
# WireGuard metrics for Prometheus (node_exporter textfile collector on vpn1), every minute from wg-metrics.timer.
set -euo pipefail

OUT=/var/lib/prometheus/node-exporter/wireguard.prom
tmp=$(mktemp "$OUT.XXXX")
{
  echo '# HELP wireguard_up 1 when wg0 exists'
  echo '# TYPE wireguard_up gauge'
  if wg show wg0 >/dev/null 2>&1; then
    echo 'wireguard_up 1'
    echo '# HELP wireguard_peer_last_handshake_seconds Unix time of the latest handshake (0 = never)'
    echo '# TYPE wireguard_peer_last_handshake_seconds gauge'
    awk '/^# name:/ {n=$3} /^PublicKey/ && n {print $3, n; n=""}' /etc/wireguard/wg0.conf > "$tmp.names"
    while read -r pub t; do
      name=$(awk -v k="$pub" '$1 == k {print $2}' "$tmp.names")
      echo "wireguard_peer_last_handshake_seconds{peer=\"${name:-unknown}\"} $t"
    done < <(wg show wg0 latest-handshakes)
    rm -f "$tmp.names"
  else
    echo 'wireguard_up 0'
  fi
} > "$tmp"
chmod 644 "$tmp"
mv "$tmp" "$OUT"

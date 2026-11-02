#!/bin/bash
# VPN connection log (map wg-admin-log, owner 2026-11-01): every 30 s from wg-connlog.timer (installed as
# /usr/local/sbin/wg-connlog). Compares `wg show wg0 dump` with the last run and writes journal lines, tag wg-conn:
#   event=connect    first handshake after none or an ended session
#   event=handshake  new handshake in a running session (WireGuard re-keys every 2 min while traffic flows)
#   event=roam       the device's public endpoint changed (Wi-Fi <-> mobile)
#   event=end        no handshake for 180 s: the session keys expired (idle, or the device lost the connection)
#   event=removed    the device left wg0 during a session (disabled, schedule, revoked)
# Also keeps the kernel's WireGuard debug messages on (handshake attempts, invalid handshakes = wrong key, retries,
# unallowed source IPs); keepalives, keypairs and send-path noise stay off. rsyslog forwards both to log1;
# wg-admin's Log tab reads them through `vpn-peer log`. Tests override the paths and the clock with WG_* variables.
set -euo pipefail

CONF=${WG_CONF:-/etc/wireguard/wg0.conf}
STATE=${WG_STATE:-/var/lib/wg-connlog/state}
CTL=${WG_DYNDBG:-/sys/kernel/debug/dynamic_debug/control}
now=${WG_NOW:-$(date +%s)}

if [ -w "$CTL" ] && grep -q '\[wireguard\]' "$CTL" && ! grep '\[wireguard\]' "$CTL" | grep -q ' =p '; then
  for q in 'module wireguard +p' 'module wireguard format keepalive -p' 'module wireguard func wg_xmit -p' \
           'module wireguard func wg_noise_handshake_begin_session -p' 'module wireguard func keypair_free_kref -p' \
           'module wireguard func wg_packet_rx_poll -p'; do
    echo "$q" > "$CTL"
  done
  logger -t wg-conn "event=debug kernel WireGuard handshake messages on"
fi

if [ -n "${WG_DUMP_FILE:-}" ]; then dump=$(cat "$WG_DUMP_FILE"); else dump=$(wg show wg0 dump); fi
mkdir -p "$(dirname "$STATE")"
first=0; [ -f "$STATE" ] || first=1
[ -f "$CONF" ] || CONF=/dev/null
out=$(printf '%s\n' "$dump" | awk -v now="$now" -v first="$first" -v newstate="$STATE.new" '
  function h(b) { return b >= 1e9 ? sprintf("%.1fGB", b / 1e9) : b >= 1e6 ? sprintf("%.1fMB", b / 1e6) : sprintf("%.0fkB", b / 1e3) }
  # device id ("# id:" in the peer block, vpn-peer ids): the Log tab shows a group admin the lines of its devices
  f == 1 { if ($0 ~ /^\[Peer\]/) u = ""; else if ($0 ~ /^# name:/) n = $3; else if ($0 ~ /^# id:/) u = $3
           else if ($1 == "PublicKey" && n) { name[$3] = n; uid[$3] = u; n = "" } next }
  f == 2 { known[$1] = 1; phs[$1] = $2; pep[$1] = $3; pact[$1] = $4; pid[$1] = $5; next }
  f == 3 && NF == 8 {
    nm = ($1 in name) ? name[$1] : "unknown-" substr($1, 1, 8)
    id = ($1 in uid) ? uid[$1] : ""
    ep = $3; ip = $4; sub(/,.*/, "", ip); sub(/\/32$/, "", ip); hs = $5 + 0
    act = (hs > 0 && now - hs < 180) ? 1 : 0
    seen[nm] = 1; peers++
    ev = ""
    if (first) ev = ""
    else if (!(nm in known)) { if (act) ev = "connect" }
    else if (hs > phs[nm]) ev = pact[nm] ? (ep != pep[nm] ? "roam" : "handshake") : "connect"
    else if (pact[nm] && !act) ev = "end"
    else if (act && ep != pep[nm]) ev = "roam"
    if (ev != "") {
      line = "event=" ev " peer=" nm (id != "" ? " id=" id : "") " tunnel=" ip " endpoint=" ep
      if (ev == "roam" && nm in known) line = line " from=" pep[nm]
      line = line " last_handshake=" (hs ? (now - hs) "s_ago" : "never") " rx=" h($6) " tx=" h($7)
      print line
    }
    print nm, hs, ep, act, id > newstate
  }
  END {
    if (first) print "event=start peers=" peers + 0 " (log begins)"
    for (nm in known) if (!(nm in seen) && pact[nm]) print "event=removed peer=" nm (pid[nm] != "" ? " id=" pid[nm] : "") " endpoint=" pep[nm] " (left wg0 during a session: disabled, schedule or revoked)"
    printf "" > newstate
  }' f=1 "$CONF" f=2 "$([ "$first" = 1 ] && echo /dev/null || echo "$STATE")" f=3 -)
mv "$STATE.new" "$STATE"
[ -z "$out" ] && exit 0
while IFS= read -r line; do
  if [ -n "${WG_LOG:-}" ]; then echo "$line" >> "$WG_LOG"; else logger -t wg-conn "$line"; fi
done <<< "$out"

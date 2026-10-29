#!/bin/bash
# WireGuard peers on vpn1 (installed as /usr/local/sbin/vpn-peer by setup-vpn1.sh; the portal reaches it through
# vpn-gate.sh):
#   vpn-peer add NAME [PROFILE] [ALLOWED]   new key pair + next free 10.66.0.x; client config
#                                 /etc/wireguard/clients/NAME.conf. PROFILE from /etc/wireguard/profiles (default
#                                 split). ALLOWED overrides the client routes (LAN tests only).
#   vpn-peer profile NAME PROFILE  switch a peer's profile (the client must import the new config)
#   vpn-peer conf NAME            the client config (holds the client's private key)
#   vpn-peer qr NAME [svg]        QR code of the client config (terminal, or SVG)
#   vpn-peer remove NAME
#   vpn-peer list                 name, profile, address, latest handshake
#   vpn-peer dump                 tab-separated: name profile address handshake rx tx created tags reimport(0|1) email
#                                 disabled(0|1)
#   vpn-peer disable|enable NAME  VPN access off/on, setup kept (owner 2026-10-27): a "# disabled: 1" line in the
#                                 block keeps the peer out of the live wg0 and out of the firewall's peer sets
#   vpn-peer sync                 load wg0.conf minus disabled peers into wg0 (wg-quick@wg0 ExecStartPost at boot)
#   vpn-peer email NAME ADDR      set the device owner's email ("-" = none; map vpn-mail)
#   vpn-peer tags NAME TAGS       set a peer's tags (comma-separated, "-" = none; portal filter, owner 2026-10-26)
#   vpn-peer profiles             tab-separated: name routes dns peers ipv6 allow description
#   vpn-peer profile-set NAME ROUTES DNS IPV6 ALLOW [DESCRIPTION...]   add or change a profile; ROUTES/DNS
#                                 comma-separated, DNS "none" = no DNS line, IPV6 on|off, ALLOW "-" or allowed
#                                 destinations CIDR[/tcp|udp/PORT[-PORT]],... Rewrites its peers' client configs.
#   vpn-peer profile-del NAME     refused while a peer uses it or it is the last profile
#   vpn-peer health               key=value lines for the portal's health map (read-only; never prints a key)
#   vpn-peer server               key=value server settings for wg-admin's Server view (read-only; public key only)
#   vpn-peer server-set ENDPOINT PORT KEEPALIVE   endpoint host:port (client configs, vpn.env), wg0 listen port,
#                                 client keepalive s (0 = off, vpn.env). Endpoint/keepalive rewrite every client config.
#   vpn-peer network              key=value: mode nat|route, incoming/transit interface, gateway, interfaces
#   vpn-peer network-set nat|route IN_IF OUT_IF GW   NAT or routed IPv4; IN_IF = WireGuard UDP + own traffic;
#                                 route with OUT_IF != IN_IF: peers' IPv4 policy-routed to GW on OUT_IF ("-" = none)
#   vpn-peer ruleset              the generated $NFT (read-only)
#   vpn-peer firewall             rewrite + load $NFT (setup-vpn1.sh; the verbs above call it too)
#   vpn-peer check                dry run: generate the ruleset, `nft -c` it, print it; nothing is loaded
#   vpn-peer export FILE          root on the console only (not in vpn-gate): age-encrypted tar of /etc/wireguard and
#                                 /etc/wg-admin; age asks for the passphrase (owner 2026-10-26). README.md: restore.
#   vpn-peer import FILE          restore an export; the current state moves to /etc/<dir>.before-import-TIME
# Each peer block in wg0.conf carries "# name:", "# profile:" and "# created:" lines; the client private key lives
# only in the client config (owner 2026-10-26: kept, so the portal can hand out the package again).
# Profiles (owner 2026-10-26: editable from the portal): one line each in $PROFILES, name TAB routes TAB dns TAB
# ipv6 (on|off) TAB allow ("-" or allowed destinations) TAB description. IPv6 on: the client gets fd66:66::N next to 10.66.0.N and vpn1 forwards (NAT66) to
# the profile's IPv6 routes; off: IPv6 from the peer is dropped (an IPv6 route like ::/0 then blocks leaks). Every
# server-side peer owns both addresses. Re-import list $REIMPORT: peers whose client config changed (profile,
# profile-set, server-set) until their config or QR is fetched again; dump's last field. Enforced on vpn1 (owner 2026-10-26; client configs are editable): add, remove, profile, profile-set
# and profile-del regenerate the whole ruleset $NFT (per profile: peer set, route set, DNS servers), check it with
# `nft -c` and load it in one transaction; a failed check keeps the old ruleset and exits 1. The ruleset is one
# table, inet wgadmin (map vpn-standalone step 5): loading it replaces only that table, so it can share a host.
# /etc/nftables.conf includes it, so reboot and `systemctl restart nftables` load it too.
set -euo pipefail

CONF=/etc/wireguard/wg0.conf
DIR=/etc/wireguard/clients
PROFILES=/etc/wireguard/profiles
NFT=/etc/nftables.d/wgadmin.nft
ENV=/etc/wireguard/vpn.env
REIMPORT=/etc/wireguard/reimport
DESC_RE="^[A-Za-z0-9 ,.:;()/+'-]{0,160}$"
TAGS_RE='^(-|[a-z0-9][a-z0-9-]{0,19}(,[a-z0-9][a-z0-9-]{0,19}){0,7})$'
EMAIL_RE='^(-|[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+)$'
# awk (RS="" paragraph mode): true for the peer block whose "# name:" line is exactly n. A plain index() also hit
# "# name: anna-phone" for anna, so remove/profile touched both blocks (fixed 2026-10-26).
MINE='function mine() { return index("\n" $0 "\n", "\n" n "\n") } '
cmd=${1:-list} name=${2:-}

need_name() {
  [[ "$name" =~ ^[a-z0-9][a-z0-9-]{0,30}$ ]] || { echo "name: lowercase letters, digits, dashes"; exit 2; }
}
need_peer() { need_name; grep -qx "# name: $name" "$CONF" || { echo "$name not found"; exit 1; }; }
envval() { sed -n "s/^$1=//p" "$ENV" 2>/dev/null | head -n1 || true; }
# Host settings in vpn.env, written once by install.sh from this host's network (setup-vpn1.sh: the home values).
LAN=$(envval LAN_IF); LAN=${LAN:-eth0}
# NAT4=off: peers' IPv4 is routed, not masqueraded (the router has a route for 10.66.0.0/24 to this host and NATs it
# to the internet; logs then show each peer's 10.66.0.N). IPv6 (fd66:66::/64) is always NAT66.
NAT4=$(envval NAT4); NAT4=${NAT4:-on}
# TRANSIT_IF (map vpn-transit, NAT4=off only): peers' IPv4 leaves through this interface, never through $LAN, by
# policy routing to TRANSIT_GW (routing()). Unset = $LAN. IPv6 always uses $LAN.
OUT4=$(envval TRANSIT_IF); OUT4=${OUT4:-$LAN}
[ "$NAT4" = off ] || OUT4=$LAN
TUN4=10.66.0.0/24 RT_TABLE=66
listen_port() { sed -n '1,/^\[Peer\]/{s/^ListenPort *= *//p}' "$CONF" | head -n1; }
mark() { (umask 077; printf '%s\n' "$@" >> "$REIMPORT"); }
unmark() {
  [ -f "$REIMPORT" ] || return 0
  grep -Fvx "$1" "$REIMPORT" > "$REIMPORT.new" || true
  chmod 600 "$REIMPORT.new"; mv "$REIMPORT.new" "$REIMPORT"
}
seed_profiles() {
  if [ -f "$PROFILES" ]; then
    # Lines from before the ipv6 field (2026-10-26) get "off" as field 4, from before allow (2026-10-27) "-" as 5.
    awk -F'\t' 'NF && ($4 != "on" && $4 != "off" || NF == 5) {old=1} END {exit !old}' "$PROFILES" || return 0
    awk -F'\t' -v OFS='\t' 'NF && $4 != "on" && $4 != "off" {$0 = $1 OFS $2 OFS $3 OFS "off" OFS $4}
      NF == 5 {$0 = $1 OFS $2 OFS $3 OFS $4 OFS "-" OFS $5} {print}' "$PROFILES" > "$PROFILES.new"
    chmod 600 "$PROFILES.new"; mv "$PROFILES.new" "$PROFILES"
    return
  fi
  local routes dns
  routes=$(envval SPLIT_ROUTES); dns=$(envval CLIENT_DNS)
  (umask 077
   printf '%s\t%s\t%s\t%s\t-\t%s\n' \
     split "${routes:-10.0.0.0/8,172.16.0.0/12,192.168.0.0/16}" "${dns:-none}" off \
     "Split tunnel: only the home subnets go through the VPN; the rest of the device's traffic stays local." \
     full 0.0.0.0/0,::/0 "${dns:-none}" off \
     "Full tunnel: all traffic goes through the VPN (LAN and internet via home)." > "$PROFILES")
}
# Field 2 (routes), 3 (dns) or 4 (ipv6) of profile $1; unknown profile -> exit 2.
field() {
  seed_profiles
  local v
  v=$(awk -F'\t' -v n="$1" -v f="$2" '$1 == n {print $f; found=1} END {exit !found}' "$PROFILES") \
    || { echo "profile $1 not found" >&2; exit 2; }
  echo "$v"
}
peers_of() {  # names of the peers with profile $1 (no profile line = split)
  awk -v p="$1" '/^\[Peer\]/ {n=""; q="split"} /^# name:/ {n=$3} /^# profile:/ {q=$3}
                 /^AllowedIPs/ && n && q == p {print n; n=""}' "$CONF"
}
# Client config of peer $1 gets profile $2's routes, DNS and (ipv6 on) its fd66:66::N address.
apply() {
  local f="$DIR/$1.conf" routes dns v6
  routes=$(field "$2" 2)
  dns=$(field "$2" 3)
  v6=$(field "$2" 4)
  awk -v r="$routes" -v d="$dns" -v v6="$v6" '/^DNS = / {next} /^AllowedIPs = / {$0 = "AllowedIPs = " r}
    /^Address = / {split($3, a, ","); $0 = "Address = " a[1]
                   if (v6 == "on") {split(a[1], o, "[./]"); $0 = $0 ", fd66:66::" o[4] "/128"}}
    {print} /^Address = / && d != "none" {print "DNS = " d}' "$f" > "$f.new"
  chmod 600 "$f.new"; mv "$f.new" "$f"
}
peers6() {  # server side, once per peer: AllowedIPs 10.66.0.N/32 -> 10.66.0.N/32,fd66:66::N/128 (peers before IPv6)
  local re='^AllowedIPs = 10[.]66[.]0[.][0-9]+/32$'
  grep -Eq "$re" "$CONF" || return 0
  awk -v re="$re" '$0 ~ re {split($3, o, "[./]"); $0 = $0 ",fd66:66::" o[4] "/128"} {print}' "$CONF" > "$CONF.new"
  chmod 600 "$CONF.new"; mv "$CONF.new" "$CONF"
  reload
}
# Live wg0 = wg0.conf without the disabled peer blocks (filtered copy; wg-quick strip takes a path named wg0.conf).
reload() {
  local d
  d=$(mktemp -d)
  (umask 077; awk 'BEGIN{RS=""; ORS="\n\n"} !/\n# disabled: 1(\n|$)/' "$CONF" > "$d/wg0.conf")
  wg syncconf wg0 <(wg-quick strip "$d/wg0.conf")
  rm -rf "$d"
}
csv() {  # items of comma list $1 matching regex $2, joined with ", " (nft set elements)
  local x out="" xs
  IFS=, read -ra xs <<<"$1"
  for x in "${xs[@]}"; do [[ $x =~ $2 ]] && out+="${out:+, }$x"; done
  echo "$out"
}
addrs_of() {  # tunnel addresses (IPv$2: 4 or 6) of the enabled peers with profile $1, comma-separated
  awk -v p="$1" -v f="$2" '/^\[Peer\]/ {n=""; q="split"; x=0} /^# name:/ {n=$3} /^# profile:/ {q=$3}
                 /^# disabled: 1$/ {x=1}
                 /^AllowedIPs/ && n && q == p && !x {split($3, a, "[,/]"); split(a[1], o, ".")
                   print (f == 6 ? "fd66:66::" o[4] : a[1]); n=""}' "$CONF" | paste -sd, -
}
elements() { [ -z "$1" ] || echo " elements = { $1 };"; }
# The whole vpn1 ruleset. Peers only reach their profile's routes through eth0 (masqueraded unless NAT4=off); vpn1 itself only
# answers ping; no peer-to-peer. A profile with DNS server addresses: DNS (53, 853) from its peers only to those.
# IPv6 only for profiles with ipv6 on (their peers' fd66:66::N to the profile's IPv6 routes, NAT66, same DNS limit);
# other peers' IPv6 is dropped, so their IPv6 routes (::/0) only keep IPv6 from leaking outside the tunnel.
# Allowed destinations (field 5, "-" = none; map vpn-profile-rules): the peers reach only those (plus their DNS
# servers), not the whole routes.
# One accept rule per allowed destination $2 (CIDR[/tcp|udp/PORT[-PORT]]) of profile id $1 and family $3 (4|6).
allow_rule() {
  local a p proto ports fam=ip peers=@$1_peers match
  IFS=/ read -r a p proto ports <<<"$2"
  [ "$3" = 6 ] && fam=ip6 peers=@$1_peers6
  match="$fam daddr $a/$p"
  [ -z "$proto" ] || match+=" $proto dport $ports"
  local out=$OUT4
  [ "$3" = 6 ] && out=$LAN
  echo "    iifname \"wg0\" oifname \"$out\" $fam saddr $peers $match accept"
}
ruleset() {
  local n r d v6 allow _ id peers r4 dns dns6 x sets="" rules="" nat=""
  [ "$NAT4" = off ] && nat="meta nfproto ipv6 "
  local V6='^[0-9a-f]*:[0-9a-f:]*$'
  seed_profiles
  while IFS=$'\t' read -r n r d v6 allow _; do
    id=p_${n//-/_}
    peers=$(csv "$(addrs_of "$n" 4)" '^[0-9.]+$')
    r4=$(csv "$r" '^[0-9./]+$')
    dns=$(csv "$d" '^[0-9.]+$')
    dns6=$(csv "$d" "$V6")
    sets+="  # profile $n"$'\n'
    sets+="  set ${id}_peers { type ipv4_addr;$(elements "$peers") }"$'\n'
    sets+="  set ${id}_routes { type ipv4_addr; flags interval; auto-merge;$(elements "$r4") }"$'\n'
    if [ -n "$dns" ]; then
      sets+="  set ${id}_dns { type ipv4_addr;$(elements "$dns") }"$'\n'
      rules+="    iifname \"wg0\" ip saddr @${id}_peers meta l4proto { tcp, udp } th dport { 53, 853 } ip daddr != @${id}_dns drop"$'\n'
      [ "$allow" = - ] || rules+="    iifname \"wg0\" ip saddr @${id}_peers meta l4proto { tcp, udp } th dport { 53, 853 } ip daddr @${id}_dns accept"$'\n'
    fi
    if [ "$allow" = - ]; then
      rules+="    iifname \"wg0\" oifname \"$OUT4\" ip saddr @${id}_peers ip daddr @${id}_routes accept"$'\n'
    else
      for x in ${allow//,/ }; do [[ $x == *:* ]] || rules+="$(allow_rule "$id" "$x" 4)"$'\n'; done
    fi
    [ "$v6" = on ] || continue
    sets+="  set ${id}_peers6 { type ipv6_addr;$(elements "$(csv "$(addrs_of "$n" 6)" "$V6")") }"$'\n'
    sets+="  set ${id}_routes6 { type ipv6_addr; flags interval; auto-merge;$(elements "$(csv "$r" '^[0-9a-f]*:[0-9a-f:/]*$')") }"$'\n'
    if [ -n "$dns6" ]; then
      sets+="  set ${id}_dns6 { type ipv6_addr;$(elements "$dns6") }"$'\n'
      rules+="    iifname \"wg0\" ip6 saddr @${id}_peers6 meta l4proto { tcp, udp } th dport { 53, 853 } ip6 daddr != @${id}_dns6 drop"$'\n'
      [ "$allow" = - ] || rules+="    iifname \"wg0\" ip6 saddr @${id}_peers6 meta l4proto { tcp, udp } th dport { 53, 853 } ip6 daddr @${id}_dns6 accept"$'\n'
    elif [ -n "$dns" ]; then
      rules+="    iifname \"wg0\" ip6 saddr @${id}_peers6 meta l4proto { tcp, udp } th dport { 53, 853 } drop"$'\n'
    fi
    if [ "$allow" = - ]; then
      rules+="    iifname \"wg0\" oifname \"$LAN\" ip6 saddr @${id}_peers6 ip6 daddr @${id}_routes6 accept"$'\n'
    else
      for x in ${allow//,/ }; do [[ $x != *:* ]] || rules+="$(allow_rule "$id" "$x" 6)"$'\n'; done
    fi
  done < "$PROFILES"
  cat <<EOF
#!/usr/sbin/nft -f
# WireGuard firewall, written by vpn-peer (deploy/vpn/vpn-peer.sh) from $PROFILES and wg0.conf: edit those, not this.
# Peers reach only their profile's routes. NAT4=$NAT4 (vpn.env): on = masqueraded as this host (the router needs no
# route for 10.66.0.0/24); off = IPv4 routed (the router routes 10.66.0.0/24 here), IPv6 still NAT66.
# Only table inet wgadmin is replaced (create, delete, define: one transaction); forward policy accept leaves
# traffic that is not to or from wg0 to the host's other tables.
table inet wgadmin
delete table inet wgadmin

table inet wgadmin {
${sets}
  chain input {
    type filter hook input priority 0; policy accept;
    iifname "wg0" ct state established,related accept
    iifname "wg0" icmp type echo-request accept
    iifname "wg0" icmpv6 type echo-request accept
    iifname "wg0" drop
  }
  chain forward {
    type filter hook forward priority 0; policy accept;
    ct state established,related accept
    oifname "wg0" drop
${rules}    iifname "wg0" drop
  }
  chain postrouting {
    type nat hook postrouting priority 100;
    iifname "wg0" oifname "$LAN" ${nat}masquerade
  }
}
EOF
}
firewall() {  # write + check + load $NFT in one transaction; a failed check keeps the old file and ruleset
  mkdir -p "$(dirname "$NFT")"
  ruleset > "$NFT.new"
  if ! nft -c -f "$NFT.new"; then
    rm -f "$NFT.new"
    echo "nftables check failed; old ruleset kept" >&2
    exit 1
  fi
  chmod 644 "$NFT.new"; mv "$NFT.new" "$NFT"
  nft -f "$NFT"
  routing
}
# Policy routing (map vpn-routing-mode): with a transit interface, peers' IPv4 (from $TUN4) goes to table $RT_TABLE,
# default via TRANSIT_GW; traffic to the peers stays in main (wg0). Otherwise the rules and table are removed.
# Idempotent; firewall (every verb, install.sh) and sync (boot) call it. Only these two rules are touched.
routing() {
  local gw
  gw=$(envval TRANSIT_GW)
  while ip -4 rule del to "$TUN4" lookup main pref 100 2>/dev/null; do :; done
  while ip -4 rule del from "$TUN4" lookup "$RT_TABLE" pref 101 2>/dev/null; do :; done
  ip -4 route flush table "$RT_TABLE" 2>/dev/null || true
  [ "$OUT4" != "$LAN" ] && [ -n "$gw" ] || return 0
  ip -4 rule add to "$TUN4" lookup main pref 100
  ip -4 rule add from "$TUN4" lookup "$RT_TABLE" pref 101
  ip -4 route replace default via "$gw" dev "$OUT4" table "$RT_TABLE" ||
    echo "routing: no route to $gw on $OUT4; device traffic is dropped until it is reachable" >&2
}
addr4() { ip -4 -o addr show dev "$1" scope global 2>/dev/null | awk '{print $4; exit}'; }

case "$cmd" in
  add)
    need_name
    profile=${3:-split}
    field "$profile" 2 >/dev/null
    allowed=${4:-$(field "$profile" 2)}
    grep -qx "# name: $name" "$CONF" && { echo "$name exists"; exit 1; }
    ENDPOINT=$(envval ENDPOINT) KEEPALIVE=$(envval KEEPALIVE)
    [ -n "$ENDPOINT" ] || { echo "no ENDPOINT in /etc/wireguard/vpn.env"; exit 1; }
    used=$(grep -o '10\.66\.0\.[0-9]*/32' "$CONF" | cut -d. -f4 | cut -d/ -f1 || true)
    ip=""
    for i in $(seq 2 254); do
      if ! grep -qx "$i" <<<"$used"; then ip=10.66.0.$i; break; fi
    done
    [ -n "$ip" ] || { echo "no free address"; exit 1; }
    key=$(wg genkey); pub=$(wg pubkey <<<"$key"); psk=$(wg genpsk)
    printf '\n[Peer]\n# name: %s\n# profile: %s\n# created: %s\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32,fd66:66::%s/128\n' \
      "$name" "$profile" "$(date +%s)" "$pub" "$psk" "$ip" "${ip##*.}" >> "$CONF"
    (umask 077; cat > "$DIR/$name.conf" <<EOF
[Interface]
PrivateKey = $key
Address = $ip/32

[Peer]
PublicKey = $(cat /etc/wireguard/server.pub)
PresharedKey = $psk
Endpoint = $ENDPOINT
AllowedIPs = $allowed
PersistentKeepalive = ${KEEPALIVE:-25}
EOF
)
    # Routes + DNS from the profile; a LAN-test ALLOWED override keeps its routes.
    apply "$name" "$profile"
    [ -z "${4:-}" ] || sed -i "s|^AllowedIPs = .*|AllowedIPs = $allowed|" "$DIR/$name.conf"
    reload; firewall
    logger -t vpn-peer "added $name $ip profile $profile"
    echo "added $name $ip $profile"
    ;;
  profile)
    need_peer
    profile=${3:-}
    field "$profile" 2 >/dev/null
    # Peer blocks are paragraphs: rewrite the profile line only in the block that holds this name.
    awk -v n="# name: $name" -v p="# profile: $profile" "$MINE"'BEGIN{RS=""; ORS="\n\n"}
      mine() { if ($0 ~ /# profile: /) sub(/# profile: [a-z0-9-]+/, p); else sub(n, n "\n" p) } {print}' \
      "$CONF" > "$CONF.new"
    chmod 600 "$CONF.new"; mv "$CONF.new" "$CONF"
    apply "$name" "$profile"; mark "$name"; firewall
    logger -t vpn-peer "profile $name $profile"
    echo "profile $name $profile"
    ;;
  tags)
    need_peer
    tags=${3:-}
    [[ "$tags" =~ $TAGS_RE ]] || { echo "tags: up to 8 comma-separated, lowercase letters, digits, dashes; - = none"; exit 2; }
    awk -v n="# name: $name" -v t="$tags" "$MINE"'BEGIN{RS=""; ORS="\n\n"}
      mine() { gsub(/\n# tags: [^\n]*/, ""); if (t != "-") sub(n, n "\n# tags: " t) } {print}' \
      "$CONF" > "$CONF.new"
    chmod 600 "$CONF.new"; mv "$CONF.new" "$CONF"
    logger -t vpn-peer "tags $name $tags"
    echo "tags $name $tags"
    ;;
  email)
    # Device owner's address (map vpn-mail, owner 2026-10-26); "-" = none.
    need_peer
    email=${3:-}
    [[ "$email" =~ $EMAIL_RE && ${#email} -le 254 ]] || { echo "email: an address like anna@example.org, - = none"; exit 2; }
    awk -v n="# name: $name" -v m="$email" "$MINE"'BEGIN{RS=""; ORS="\n\n"}
      mine() { gsub(/\n# email: [^\n]*/, ""); if (m != "-") sub(n, n "\n# email: " m) } {print}' \
      "$CONF" > "$CONF.new"
    chmod 600 "$CONF.new"; mv "$CONF.new" "$CONF"
    logger -t vpn-peer "email $name $email"
    echo "email $name $email"
    ;;
  disable | enable)
    need_peer
    awk -v n="# name: $name" -v on="$cmd" "$MINE"'BEGIN{RS=""; ORS="\n\n"}
      mine() { gsub(/\n# disabled: [^\n]*/, ""); if (on == "disable") sub(n, n "\n# disabled: 1") } {print}' \
      "$CONF" > "$CONF.new"
    chmod 600 "$CONF.new"; mv "$CONF.new" "$CONF"
    reload; firewall
    logger -t vpn-peer "${cmd}d $name"
    echo "${cmd}d $name"
    ;;
  sync)
    reload
    routing
    ;;
  conf)
    need_peer
    cat "$DIR/$name.conf"
    unmark "$name"
    ;;
  qr)
    need_peer
    if [ "${3:-}" = svg ]; then qrencode -t SVG -o - < "$DIR/$name.conf"; else qrencode -t ansiutf8 < "$DIR/$name.conf"; fi
    unmark "$name"
    ;;
  remove)
    need_peer
    # Drop the [Peer] block that holds the name line (blocks are separated by blank lines).
    awk -v n="# name: $name" "$MINE"'BEGIN{RS=""; ORS="\n\n"} !mine()' "$CONF" > "$CONF.new"
    chmod 600 "$CONF.new"; mv "$CONF.new" "$CONF"
    rm -f "$DIR/$name.conf"
    unmark "$name"
    reload; firewall
    logger -t vpn-peer "removed $name"
    echo "removed $name"
    ;;
  list | dump)
    declare -A hs rx tx
    while IFS=$'\t' read -r pub _ _ _ t r x _; do hs[$pub]=$t; rx[$pub]=$r; tx[$pub]=$x; done \
      < <(wg show wg0 dump | tail -n +2)
    awk '/^\[Peer\]/ {n=""; p="split"; c=0; g="-"; m="-"; x=0} /^# name:/ {n=$3} /^# profile:/ {p=$3} /^# created:/ {c=$3}
         /^# tags:/ {g=$3} /^# email:/ {m=$3} /^# disabled: 1$/ {x=1} /^PublicKey/ {k=$3}
         /^AllowedIPs/ && n {split($3, a, ","); print n, p, c, k, a[1], g, m, x; n=""}' "$CONF" |
      while read -r n p c k a g m x; do
        t=${hs[$k]:-0} ri=0
        grep -Fqx "$n" "$REIMPORT" 2>/dev/null && ri=1
        if [ "$cmd" = dump ]; then
          printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$n" "$p" "${a%/32}" "$t" "${rx[$k]:-0}" "${tx[$k]:-0}" "$c" "$g" "$ri" "$m" "$x"
        else
          if [ "$t" = 0 ]; then seen=never; else seen=$(date -d "@$t" '+%F %T'); fi
          echo "$n $p $a $seen ${g/#-/}"
        fi
      done
    ;;
  profiles)
    seed_profiles
    while IFS=$'\t' read -r n r d v6 allow desc; do
      printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$n" "$r" "$d" "$(peers_of "$n" | wc -l)" "$v6" "$allow" "$desc"
    done < "$PROFILES"
    ;;
  profile-set)
    [[ "$name" =~ ^[a-z0-9][a-z0-9-]{0,15}$ ]] || { echo "profile name: lowercase letters, digits, dashes"; exit 2; }
    routes=${3:-} dns=${4:-} v6=${5:-} allow=${6:-} desc=${*:7}
    [[ $v6 == on || $v6 == off ]] || { echo "ipv6: on or off"; exit 2; }
    [[ $v6 == off || $routes == *:* ]] || { echo "ipv6 on needs an IPv6 route, e.g. ::/0"; exit 2; }
    # Allowed destinations: "-" or CIDR[/tcp|udp/PORT[-PORT]],... (max 20); IPv6 ones only with ipv6 on.
    [ "$allow" = - ] || [ ${#allow} -le 900 ] || { echo "allow: too long"; exit 2; }
    if [ "$allow" != - ]; then
      IFS=, read -ra xs <<<"$allow"
      (( ${#xs[@]} >= 1 && ${#xs[@]} <= 20 )) || { echo "allow: 1-20 rules"; exit 2; }
      for x in "${xs[@]}"; do
        [[ $x =~ ^([0-9.]{7,15}/[0-9]{1,2}|[0-9a-f:]{2,39}/[0-9]{1,3})(/(tcp|udp)/[0-9]{1,5}(-[0-9]{1,5})?)?$ ]] \
          || { echo "allow: $x is not CIDR[/tcp|udp/PORT[-PORT]]"; exit 2; }
        [[ $x != *:* || $v6 == on ]] || { echo "allow: IPv6 rule $x needs ipv6 on"; exit 2; }
      done
    fi
    # Lengths apart: some regex libraries cap {m,n} at 255.
    [[ "$routes" =~ ^[0-9a-f.:/,]+$ && ${#routes} -le 400 ]] || { echo "routes: comma-separated CIDRs"; exit 2; }
    [[ "$dns" =~ ^[a-z0-9.:,-]+$ && ${#dns} -le 200 ]] || { echo "dns: comma-separated addresses or names, or none"; exit 2; }
    [[ "$desc" =~ $DESC_RE ]] || { echo "description: letters, digits, basic punctuation"; exit 2; }
    seed_profiles
    # Client config = routes, DNS, IPv6; allowed destinations and description live only here (no re-import)
    old=$(awk -F'\t' -v n="$name" '$1 == n {print $2 "\t" $3 "\t" $4}' "$PROFILES")
    line=$(printf '%s\t%s\t%s\t%s\t%s\t%s' "$name" "$routes" "$dns" "$v6" "$allow" "$desc")
    awk -F'\t' -v n="$name" -v l="$line" '$1 == n {print l; found=1; next} {print} END {if (!found) print l}' \
      "$PROFILES" > "$PROFILES.new"
    chmod 600 "$PROFILES.new"; mv "$PROFILES.new" "$PROFILES"
    count=0
    for p in $(peers_of "$name"); do
      apply "$p" "$name"
      [ "$old" = "$(printf '%s\t%s\t%s' "$routes" "$dns" "$v6")" ] || mark "$p"
      count=$((count + 1))
    done
    firewall
    logger -t vpn-peer "profile-set $name routes $routes dns $dns ipv6 $v6 allow $allow ($count peers)"
    echo "profile $name saved, $count peer configs updated"
    ;;
  profile-del)
    field "$name" 2 >/dev/null
    used=$(peers_of "$name" | wc -l)
    [ "$used" = 0 ] || { echo "profile $name is used by $used peers"; exit 1; }
    [ "$(wc -l < "$PROFILES")" -gt 1 ] || { echo "the last profile cannot be deleted"; exit 1; }
    awk -F'\t' -v n="$name" '$1 != n' "$PROFILES" > "$PROFILES.new"
    chmod 600 "$PROFILES.new"; mv "$PROFILES.new" "$PROFILES"; firewall
    logger -t vpn-peer "profile-del $name"
    echo "profile $name deleted"
    ;;
  health)
    # Read-only key=value lines for the portal's VPN health map. Never prints a key: only whether one is set.
    up=0 key=0 port="" peers=0 conn=0
    if wg show wg0 >/dev/null 2>&1; then
      up=1
      k=$(wg show wg0 private-key 2>/dev/null || true)
      [ -n "$k" ] && [ "$k" != "(none)" ] && key=1
      unset k
      port=$(wg show wg0 listen-port 2>/dev/null || true)
      now=$(date +%s)
      while read -r _ t; do
        peers=$((peers + 1))
        [ "${t:-0}" -gt 0 ] && [ $((now - t)) -lt 180 ] && conn=$((conn + 1))
      done < <(wg show wg0 latest-handshakes 2>/dev/null || true)
    fi
    endpoint=$(sed -n 's/^ENDPOINT=//p' /etc/wireguard/vpn.env 2>/dev/null | head -n1 || true)
    # DNS_CHECK = "SERVER NAME" (vpn.env): this host asks SERVER for NAME, as a VPN client would.
    gw=$(envval GATEWAY) gw_name=$(envval GATEWAY_NAME)
    read -r dns_server dns_name _ <<<"$(envval DNS_CHECK)" || true
    if [ -z "${dns_server:-}" ] || [ -z "${dns_name:-}" ]; then dns=unknown
    elif command -v dig >/dev/null 2>&1; then
      if [ -n "$(dig +short +time=2 +tries=1 "@$dns_server" "$dns_name" 2>/dev/null | grep -v '^;' || true)" ]; then dns=1
      else dns=0; fi
    else dns=unknown; fi
    # The LAN gateway seen from this host: its address (inside) and the internet through it (WAN). "loss rtt".
    probe() {
      command -v ping >/dev/null 2>&1 || { echo "unknown unknown"; return; }
      ping -n -q -c 3 -i 0.3 -W 1 "$1" 2>/dev/null | awk '/packet loss/ {for (i = 1; i <= NF; i++) if ($i ~ /%$/) l = $i + 0}
        /^(rtt|round-trip)/ {split($4, a, "/"); r = a[2]} END {print (l == "" ? 100 : l), (r == "" ? "unknown" : r)}'
    }
    if [ -n "$gw" ]; then read -r gw_loss gw_rtt < <(probe "$gw"); else gw_loss=unknown gw_rtt=unknown; fi
    via=ping
    if command -v ping >/dev/null 2>&1; then read -r wan_loss wan_rtt < <(probe 1.1.1.1)
    elif command -v dig >/dev/null 2>&1; then
      via=dns wan_rtt=unknown
      if [ -n "$(dig +short +time=2 +tries=1 @1.1.1.1 one.one.one.one 2>/dev/null | grep -v '^;' || true)" ]; then wan_loss=0
      else wan_loss=100; fi
    else via=none wan_loss=unknown wan_rtt=unknown; fi
    echo "gw_loss=$gw_loss"
    echo "gw_rtt_ms=$gw_rtt"
    echo "wan_loss=$wan_loss"
    echo "wan_rtt_ms=$wan_rtt"
    echo "wan_via=$via"
    echo "wg_up=$up"
    echo "key_set=$key"
    echo "listen_port=$port"
    echo "listen_port_conf=$(listen_port)"
    echo "nft_active=$(systemctl is-active nftables 2>/dev/null || true)"
    echo "ip_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo unknown)"
    echo "ipv6_forward=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo unknown)"
    # IPv6 upstream = a global address on the LAN interface and a default route (wg0's fd66:66::1 does not count).
    if [ -n "$(ip -6 addr show dev "$LAN" scope global 2>/dev/null)" ] && [ -n "$(ip -6 route show default 2>/dev/null)" ]
    then echo "ipv6_upstream=1"; else echo "ipv6_upstream=0"; fi
    # Traffic paths (map vpn-transit): addresses per leg; the transit gateway is table 66's default route.
    tif=$OUT4
    if [ "$tif" != "$LAN" ]; then
      tgw=$(ip -4 route show table 66 default 2>/dev/null | awk '{print $3; exit}')
      if [ -n "$tgw" ]; then read -r t_loss t_rtt < <(probe "$tgw"); else t_loss=unknown t_rtt=unknown; fi
      echo "transit_if=$tif"
      echo "transit_addr=$(addr4 "$tif")"
      echo "transit_gw=$tgw"
      echo "transit_loss=$t_loss"
      echo "transit_rtt_ms=$t_rtt"
    fi
    echo "lan_addr=$(addr4 "$LAN")"
    echo "tunnel_addr=$(sed -n '1,/^\[Peer\]/{s/^Address *= *//p}' "$CONF" | head -n1)"
    echo "client_dns=$(envval CLIENT_DNS)"
    echo "nat4=$(envval NAT4)"
    echo "host=$(hostname -s 2>/dev/null || true)"
    echo "lan_if=$LAN"
    echo "gateway=$gw"
    echo "gateway_name=${gw_name:-Gateway}"
    echo "dns_server=${dns_server:-}"
    echo "dns_name=${dns_name:-}"
    echo "endpoint=$endpoint"
    echo "peers=$peers"
    echo "peers_connected=$conn"
    echo "dns_ok=$dns"
    ;;
  server)
    # Read-only key=value lines for wg-admin's Server view (map vpn-standalone step 2). The public key only.
    iface() { sed -n "1,/^\[Peer\]/{s/^$1 *= *//p}" "$CONF" | head -n1; }
    ka=$(envval KEEPALIVE)
    echo "endpoint=$(envval ENDPOINT)"
    echo "listen_port=$(iface ListenPort)"
    echo "address=$(iface Address)"
    echo "mtu=$(iface MTU)"
    echo "public_key=$(cat /etc/wireguard/server.pub 2>/dev/null || true)"
    echo "keepalive=${ka:-25}"
    echo "reimport=$(sort -u "$REIMPORT" 2>/dev/null | grep -c . || true)"
    echo "peers=$(grep -c '^# name: ' "$CONF" || true)"
    echo "profiles=$(grep -c . "$PROFILES" 2>/dev/null || true)"
    echo "wg_up=$(wg show wg0 >/dev/null 2>&1 && echo 1 || echo 0)"
    echo "nft_active=$(systemctl is-active nftables 2>/dev/null || true)"
    echo "wg_tools=$(wg --version 2>/dev/null | awk '{print $2}')"
    echo "kernel=$(uname -r)"
    ;;
  server-set)
    # Server settings (map vpn-standalone step 2b). Listen port: wg0.conf, applied live (wg syncconf); the router's
    # port forward must follow it. Endpoint/keepalive: vpn.env + every client config (devices re-import).
    endpoint=${2:-} port=${3:-} ka=${4:-}
    [[ $endpoint =~ ^([a-z0-9.-]{1,253}|\[[0-9a-f:]{2,39}\]):[0-9]{1,5}$ ]] || { echo "endpoint: host:port"; exit 2; }
    [[ $port =~ ^[0-9]{1,5}$ ]] && (( 10#$port >= 1 && 10#$port <= 65535 )) || { echo "port: 1-65535"; exit 2; }
    [[ $ka =~ ^[0-9]{1,4}$ ]] && (( 10#$ka <= 3600 )) || { echo "keepalive: 0-3600 seconds"; exit 2; }
    port=$((10#$port)) ka=$((10#$ka))
    old_ep=$(envval ENDPOINT) old_ka=$(envval KEEPALIVE)
    (umask 077; { grep -Ev '^(ENDPOINT|KEEPALIVE)=' "$ENV" 2>/dev/null || true
                  printf 'ENDPOINT=%s\nKEEPALIVE=%s\n' "$endpoint" "$ka"; } > "$ENV.new")
    mv "$ENV.new" "$ENV"
    if [ "$port" != "$(listen_port)" ]; then
      sed -i "1,/^\[Peer\]/s/^ListenPort *=.*/ListenPort = $port/" "$CONF"
      reload
    fi
    count=0
    if [ "$endpoint" != "$old_ep" ] || [ "$ka" != "${old_ka:-25}" ]; then
      for f in "$DIR"/*.conf; do
        [ -f "$f" ] || continue
        awk -v e="$endpoint" -v k="$ka" '/^Endpoint = / {$0 = "Endpoint = " e}
          /^PersistentKeepalive = / {$0 = "PersistentKeepalive = " k} {print}' "$f" > "$f.new"
        chmod 600 "$f.new"; mv "$f.new" "$f"
        mark "$(basename "$f" .conf)"; count=$((count + 1))
      done
    fi
    logger -t vpn-peer "server-set endpoint $endpoint port $port keepalive $ka ($count client configs)"
    echo "server saved: endpoint $endpoint, listen port $port, keepalive $ka; $count client configs updated"
    ;;
  network)
    # Read-only key=value lines for Server > Network (map vpn-routing-mode); one iface= line per interface with IPv4.
    echo "mode=$([ "$NAT4" = off ] && echo route || echo nat)"
    echo "lan_if=$LAN"
    echo "transit_if=$OUT4"
    echo "transit_gw=$(envval TRANSIT_GW)"
    echo "gateway=$(envval GATEWAY)"
    for i in /sys/class/net/*; do
      i=${i##*/}
      [ "$i" = lo ] || [ "$i" = wg0 ] || [ -z "$(addr4 "$i")" ] || echo "iface=$i $(addr4 "$i")"
    done
    ;;
  network-set)
    # network-set nat|route IN_IF OUT_IF GW (map vpn-routing-mode). IN_IF: WireGuard UDP and this host's own traffic
    # (LAN_IF). route: peers' IPv4 routed (router: static route for 10.66.0.0/24 + outbound NAT); OUT_IF != IN_IF =
    # transit leg, policy-routed to GW. nat: masqueraded on IN_IF (router: only the UDP port forward). No client
    # config changes. "-" = no GW.
    mode=${2:-} in_if=${3:-} out_if=${4:-} gw=${5:--}
    [[ $mode =~ ^(nat|route)$ ]] || { echo "mode: nat or route"; exit 2; }
    for i in "$in_if" "$out_if"; do
      [[ $i =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,14}$ ]] && [ "$i" != wg0 ] && [ "$i" != lo ] && [ -n "$(addr4 "$i")" ] ||
        { echo "interface ${i:-?}: not an interface with an IPv4 address"; exit 2; }
    done
    if [ "$mode" = nat ] || [ "$in_if" = "$out_if" ]; then out_if="" gw=""
    else
      [[ $gw =~ ^([0-9]{1,3}[.]){3}[0-9]{1,3}$ ]] || { echo "gateway: the IPv4 next hop on $out_if"; exit 2; }
    fi
    nat=$([ "$mode" = nat ] && echo on || echo off)
    (umask 077; cp "$ENV" "$ENV.prev"
     { grep -Ev '^(NAT4|LAN_IF|TRANSIT_IF|TRANSIT_GW)=' "$ENV" || true
       printf 'NAT4=%s\nLAN_IF=%s\nTRANSIT_IF=%s\nTRANSIT_GW=%s\n' "$nat" "$in_if" "$out_if" "$gw"; } > "$ENV.new")
    mv "$ENV.new" "$ENV"
    if ! "$0" firewall >/dev/null; then  # a new process reads the new vpn.env; failed: the old settings back
      mv "$ENV.prev" "$ENV"; "$0" firewall >/dev/null || true
      echo "network not changed: the firewall did not load"; exit 1
    fi
    rm -f "$ENV.prev"
    summary="mode $mode, incoming $in_if${out_if:+, transit $out_if via $gw}"
    logger -t vpn-peer "network-set $summary"
    echo "network saved: $summary"
    ;;
  ruleset)
    cat "$NFT"  # read-only: the generated firewall (no keys in it)
    ;;
  firewall)
    peers6; firewall
    echo "firewall: $NFT loaded"
    ;;
  check)
    f=$(mktemp)
    ruleset > "$f"
    if nft -c -f "$f"; then cat "$f"; rm -f "$f"; echo "# check: OK" >&2
    else rm -f "$f"; echo "nftables check failed" >&2; exit 1; fi
    ;;
  export)
    # The whole VPN state: server + client keys, peers, profiles, vpn.env, wg-admin logins/tokens/mail/TLS key.
    # Encrypted with age; the owner types the passphrase (never stored). -a = text file, safe to copy anywhere.
    out=${2:-}
    [ -n "$out" ] && [ ! -e "$out" ] || { echo "usage: vpn-peer export FILE (a new file)"; exit 2; }
    command -v age >/dev/null || { echo "age not installed (apt-get install age)"; exit 1; }
    dirs=(etc/wireguard); [ -d /etc/wg-admin ] && dirs+=(etc/wg-admin)
    if ! (umask 077; tar -C / -czf - "${dirs[@]}" | age -p -a -o "$out"); then rm -f "$out"; exit 1; fi
    logger -t vpn-peer "export ${dirs[*]} -> $out"
    echo "exported ${dirs[*]} to $out ($(grep -c '^# name: ' "$CONF" || true) peers); keep the passphrase apart from it"
    ;;
  import)
    in=${2:-}
    [ -f "$in" ] || { echo "usage: vpn-peer import FILE (from vpn-peer export)"; exit 2; }
    command -v age >/dev/null || { echo "age not installed (apt-get install age)"; exit 1; }
    d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
    age -d -o "$d/state.tgz" "$in"
    tar -tzf "$d/state.tgz" > "$d/list"
    grep -qx 'etc/wireguard/wg0.conf' "$d/list" || { echo "no etc/wireguard/wg0.conf: not a vpn-peer export"; exit 1; }
    if grep -Evq '^etc/(wireguard|wg-admin)(/|$)' "$d/list" || grep -q '[.][.]' "$d/list"; then
      echo "unexpected paths in the export; nothing changed"; exit 1
    fi
    ts=$(date +%Y%m%d-%H%M%S) moved=""
    for x in wireguard wg-admin; do
      if grep -q "^etc/$x/" "$d/list" && [ -e "/etc/$x" ]; then mv "/etc/$x" "/etc/$x.before-import-$ts"; moved+=" /etc/$x"; fi
    done
    tar -C / -xzpf "$d/state.tgz"
    if wg show wg0 >/dev/null 2>&1; then reload; firewall; fi
    logger -t vpn-peer "import $in (old state:${moved:- none} -> .before-import-$ts)"
    echo "imported $in: $(grep -c '^# name: ' "$CONF" || true) peers; old state:${moved:- none} -> .before-import-$ts"
    echo "next: bash setup-vpn1.sh (owners, firewall, services), then systemctl restart wg-quick@wg0 wg-admin"
    ;;
  *) echo "usage: vpn-peer add|profile|tags|conf|qr|remove|list|dump|profiles|profile-set|profile-del|health|server|server-set|ruleset|firewall|check|export|import [NAME] ..."; exit 2 ;;
esac

#!/bin/bash
# wg-admin's only way to root on vpn1 (installed by setup-vpn1.sh as /usr/local/sbin/vpn-gate; sudoers lets user
# wgadmin run it): `sudo -n vpn-gate "<request>"`. Until 2026-10-26 it was the forced command of the portal's SSH key
# (SSH_ORIGINAL_COMMAND, still read). Only these requests pass to vpn-peer; everything else is refused:
#   dump | add NAME PROFILE | profile NAME PROFILE | tags NAME TAGS | remove NAME | conf NAME | qr NAME
#   enable NAME | disable NAME
#   profiles | profile-set PROFILE ROUTES DNS v6=on|off allow=RULES [DESCRIPTION] | profile-del PROFILE | health
#   server | ruleset | network
#   server-set ENDPOINT PORT KEEPALIVE | network-set nat|route IN_IF OUT_IF GW
#   reboot (handled here, not by vpn-peer: the host reboots 5 s later, so the API can still answer)
set -euo pipefail
PEER=/usr/local/sbin/vpn-peer
(( $# <= 1 )) || { echo "refused: one request argument"; exit 2; }
cmd=${SSH_ORIGINAL_COMMAND:-${1:-}}
N='[a-z0-9][a-z0-9-]{0,30}' P='[a-z0-9][a-z0-9-]{0,15}'
G='-|[a-z0-9][a-z0-9-]{0,19}(,[a-z0-9][a-z0-9-]{0,19}){0,7}'
R='[0-9a-f.:/,]+' D='[a-z0-9.:,-]+' T="[A-Za-z0-9 ,.:;()/+'-]{0,160}"  # vpn-peer checks R/D lengths
A='-|[0-9a-f.:/,tcpud-]+'  # allowed destinations: CIDR[/tcp|udp/PORT[-PORT]],... (vpn-peer checks each)
E='([a-z0-9.-]{1,253}|\[[0-9a-f:]{2,39}\]):[0-9]{1,5}'  # endpoint host:port; one inner group (BASH_REMATCH[2])
I='[A-Za-z0-9][A-Za-z0-9._-]{0,14}' V4='-|([0-9]{1,3}[.]){3}[0-9]{1,3}'  # interface name; IPv4 or "-"
READ='^(dump|profiles|health|server|ruleset|network)$'  # read-only, polled: not logged
[[ $cmd =~ $READ ]] || logger -t vpn-gate "request from ${SSH_CLIENT:-local}: ${cmd:0:200}"

if (( ${#cmd} > 800 )); then echo "refused: request too long"; exit 2
elif [[ $cmd =~ $READ ]]; then exec "$PEER" "$cmd"
elif [[ $cmd =~ ^(add|profile)\ ($N)\ ($P)$ ]]; then exec "$PEER" "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
elif [[ $cmd =~ ^tags\ ($N)\ ($G)$ ]]; then exec "$PEER" tags "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
elif [[ $cmd =~ ^email\ ($N)\ (-|[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{3,190})$ ]]; then
  exec "$PEER" email "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
elif [[ $cmd =~ ^(remove|conf|enable|disable)\ ($N)$ ]]; then exec "$PEER" "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
elif [[ $cmd =~ ^qr\ ($N)$ ]]; then exec "$PEER" qr "${BASH_REMATCH[1]}" svg
elif [[ $cmd =~ ^profile-set\ ($P)\ ($R)\ ($D)\ v6=(on|off)\ allow=($A)\ ?($T)$ ]]; then
  exec "$PEER" profile-set "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}" \
    "${BASH_REMATCH[5]}" "${BASH_REMATCH[6]}"
elif [[ $cmd =~ ^profile-del\ ($P)$ ]]; then exec "$PEER" profile-del "${BASH_REMATCH[1]}"
elif [[ $cmd =~ ^server-set\ ($E)\ ([0-9]{1,5})\ ([0-9]{1,4})$ ]]; then
  exec "$PEER" server-set "${BASH_REMATCH[1]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}"
elif [[ $cmd =~ ^network-set\ (nat|route)\ ($I)\ ($I)\ ($V4)$ ]]; then
  exec "$PEER" network-set "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}"
elif [[ $cmd == reboot ]]; then
  # A second click while the timer waits fails on the unit name: one reboot per request window.
  systemd-run --quiet --collect --on-active=5 --unit=wg-admin-reboot /bin/systemctl reboot
  echo "reboot in 5 s"
else
  echo "refused: not an allowed VPN request"; exit 2
fi

# wg-admin: WireGuard server + web UI

WireGuard + nftables + wg-admin (web UI and API; nginx TLS on :8443 -> app on 127.0.0.1:8080) on one Debian host.
Devices, profiles (full/split/hosts), firewall rules, schedules, TOTP, NAT or routed mode, health map, backups.

| File | Role |
| --- | --- |
| install.sh | Idempotent install on any Debian 12/13 host (root): packages, wg0, firewall, wg-admin, nginx, metrics |
| uninstall.sh | Removes it; data kept unless `--purge`; wg0 always stopped (no peers without the firewall) |
| vpn-peer.sh | All VPN logic (installed as /usr/local/sbin/vpn-peer) |
| vpn-gate.sh | The only root path for wg-admin (fixed requests) |
| wgadmin/ | FastAPI app + static UI |
| wg-admin.service, wg-admin.nginx.conf | App on 127.0.0.1:8080; nginx TLS front on :8443 |
| setup-vpn1.sh | (source repo only) homelab wrapper: install.sh with site values + portal SSO |

## Install on a new host
1. Debian 12/13 VM or LXC; UDP 51820 forwarded to it by the router. Unprivileged LXC: the host loads the
   `wireguard` module.
2. As root: `git clone <this repo> /root/wg-admin && bash /root/wg-admin/install.sh --endpoint vpn.example.org:51820`.
   It detects the LAN interface, gateway, DNS and LAN subnet into /etc/wireguard/vpn.env (override:
   `LAN_IF=ens18 CLIENT_DNS=10.0.0.53 bash install.sh`). TLS: self-signed until you sign /etc/wg-admin/tls.csr.
   Behind an HTTP proxy: export `http_proxy`/`https_proxy` first (apt and git use them).
3. First admin: `cd /opt/wg-admin && sudo -u wgadmin python3 -m wgadmin set-password NAME`; open https://HOST:8443/.
   Everything else (endpoint, DNS, routes, NAT/Route, mail, devices) is set in the UI.
4. Update: `git -C /root/wg-admin pull && bash /root/wg-admin/install.sh` (keys, devices and settings stay).
5. Remove: `bash uninstall.sh` (keeps keys and peers) or `bash uninstall.sh --purge` (export first).

## Two-step sign-in and schedules
- Authenticator (TOTP, Google Authenticator or any app): signed in on this page, Account > Set up authenticator,
  scan, enter a code; save the 10 recovery codes. Locked out: `sudo -u wgadmin python3 -m wgadmin totp-reset NAME`.
- Schedules: weekly hours, calendar dates, valid from / expires; pick one per device. wg-admin switches devices
  every minute in this host's local time (`timedatectl set-timezone ...`). A manual switch holds until the
  schedule's next change. Data: /etc/wg-admin/totp.json, schedules.json (600 wgadmin).

## NAT or Route
Server settings > Network. NAT (default): devices appear as this host; the router needs only the UDP port forward.
Route: devices keep their 10.66.0.N; the router needs a route for 10.66.0.0/24 to this host (and outbound NAT for
it). A second interface can carry the decrypted traffic (transit interface + next hop).

## Firewall
vpn-peer writes one table, `inet wgadmin`, to /etc/nftables.d/wgadmin.nft and replaces only that table.
On a host with its own /etc/nftables.conf, add `include "/etc/nftables.d/*.nft"` to it.
Dry run: `vpn-peer check`.

## Backup and restore
- Export (root, interactive): `vpn-peer export /root/vpn-YYYYMMDD.age`. age asks for a passphrase. The file holds
  every key; keep the passphrase somewhere else.
- Restore on a new host: install.sh (step 2), then `vpn-peer import FILE`, then install.sh again, then
  `systemctl restart wg-quick@wg0 wg-admin`. The previous state stays in /etc/wireguard.before-import-TIME.
  Devices keep working when the new host gets the same endpoint (server key comes from the export).

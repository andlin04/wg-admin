# wg-admin: WireGuard server + web UI

A self-hosted WireGuard VPN server with a web UI, installed by one script on one Debian host.

- Each device gets its own key and a connection profile.
- The server's firewall lets a device reach only what its profile allows.
- Built from WireGuard, nftables and wg-admin (a FastAPI web UI and API behind nginx with TLS on port 8443).

![Devices](docs/devices.png)

**Contents:** [Features](#features) · [Screenshots](#screenshots) · [Install](#install) ·
[Getting started](#getting-started) · [Roles](#users-groups-and-roles) · [Network](#network-nat-or-route) ·
[Firewall](#firewall) · [Backup](#backup-and-restore) · [Security](#security) ·
[Command line](#command-line) · [Files](#files) · [Changes](CHANGES.md)

## Features

### Devices
- Add one device, or many at once from a CSV file.
- Set up a phone by scanning a QR code in the WireGuard app.
- Set up a computer with a `.conf` file, or a `.zip` that includes instructions.
- Mail the setup to the device's owner.
- Disable and enable a device's VPN access with a slider; its key and setup stay. **Revoke** removes it for good.
- Tag devices and filter the list by tag.
- Each row shows name, IP, profile, on/off and status. The arrow on the right opens the rest: last handshake,
  traffic, pickers and actions. **Expand all** and **Collapse all** open or close every row.
- **Bulk edit:** tick devices, then change several settings on all of them in one go.
- Show 10, 25, 50, 100 or all rows per page.
- Status reloads when you press **Refresh**, never on a timer.
- The other tabs' lists (profiles, schedules, groups, users, server settings) also open per row or all at once.

### One config, one device
Each configuration is meant for exactly one device.

| Rule | What happens |
| --- | --- |
| **Activation deadline** | A new device must connect within its deadline (3 days by default, 1 to 30). Otherwise its VPN access is disabled. |
| **Stored config deleted** | After the device's first connection, the server deletes its copy of the config. QR, `.conf` and `.zip` are then gone; a lost config means revoke and add the device again. |
| **Copied key detection** | If one key is used from two places at the same time, the device's address flips back and forth. When it changes 3 times within 10 minutes and returns to an earlier address (A, B, A), the device's VPN access is disabled at once. |

- The device itself is not touched: the server stops accepting its key. Its setup stays, and an admin can enable
  access again with the device's slider.
- Owner and admin copy address get a mail each time access is disabled, with the addresses and times.
- Access disabled for a copied key stays disabled. Schedules don't enable it again; only an admin can.
- Limit: copied key detection needs both copies connected at the same time. A copy used while the original is
  offline is not detected.

### Access control
- **Connection profiles:**
  - split tunnel (home networks only)
  - full tunnel (all traffic)
  - single hosts and ports

  The server enforces them with nftables; they are not just client settings.
- **Schedules:** weekly hours, calendar dates, valid from and until. Device access is enabled and disabled by
  itself.

### Users and sign-in
- Two roles: **admin** and **group admin**. Group admins manage only their groups' devices.
- Sign-in hours and an expiry date per account.
- Optional authenticator app (TOTP), per account or required for a whole role.
- Password history; every user can change their own password.

### Logs and monitoring
- **Connection log:** connects, handshakes, roaming (Wi-Fi ⇄ mobile), session ends and WireGuard's own messages,
  per device. Search it in the **Log** tab.
- Group admins see the full history of the devices in their groups, and nothing else (each device has a hidden,
  fixed id that tags its log lines).
- Logs are kept locally (logrotate) and can be forwarded to a syslog server over UDP or TCP.
- **Health map:** devices, internet, router, VPN server and LAN/DNS, with live checks.
- **Prometheus metrics:** WireGuard status and the last handshake per device, written to node_exporter's
  textfile collector. Only installed if node_exporter is already on the host.
- **Audit:** every change goes to the journal. Optional: also sent to an event URL (`WGADMIN_EVENT_URL`).

### Server and admin
- **Server settings:**
  - endpoint, port and keepalive
  - NAT or routed mode, transit interface
  - firewall rules shown in readable form, with an editor
  - mail (SMTP) with a test button, and an **admin copy** address that gets every setup mail and alert
  - activation deadline
  - logging
  - reboot
- **Backup:** an encrypted export (age) with every key; restoring it on a new host keeps all devices working.
- **API:** every UI action is an API call; tokens let scripts use it.
- **Dark or light theme:** the button next to the user name. Follows the system setting until you pick one.

## Screenshots
Made-up demo data (no real names, addresses or keys).

| | |
| --- | --- |
| ![Sign in](docs/login.png) Sign in (local account; optional authenticator code) | ![Profiles](docs/profiles.png) Connection profiles: routes, DNS, allowed hosts |
| ![Schedules](docs/schedules.png) Schedules: when devices may connect | ![Server](docs/server.png) Server settings, network mode, firewall |
| ![Groups](docs/groups.png) Groups: devices, profiles and schedules for group admins | ![Users](docs/users.png) Users: roles, sign-in hours, 2-step, lockout reset |
| ![Bulk edit](docs/bulk.png) Bulk edit: several settings on the ticked devices in one go | ![Log](docs/log.png) Log: connections, WireGuard handshakes, admin actions |
| ![Logging](docs/logging.png) Server settings > Logging: days kept, size per day, syslog forward | ![Device open](docs/expanded.png) A device opened: pickers, tags as ticks, actions |
| ![Profiles open](docs/profiles-open.png) Connection profiles, all opened | ![Server open](docs/server-open.png) Server settings, all parts opened |
| ![Devices, light](docs/devices-light.png) Light theme: devices | ![Device open, light](docs/expanded-light.png) Light theme: a device opened |

## Install
`install.sh` sets up everything, WireGuard included:
- installs `wireguard-tools`, nftables, nginx and the Python packages from Debian's repositories
- creates the server key and the `wg0` interface
- starts `wg-quick@wg0` at boot

Nothing needs to be installed first; the WireGuard kernel module is part of Debian 12/13's kernel.

1. **Host:** a Debian 12/13 VM or LXC, with UDP 51820 forwarded to it by the router.
   For an unprivileged LXC, the host must load the `wireguard` module.
2. **Install** as root:
   ```
   git clone <this repo> /root/wg-admin
   bash /root/wg-admin/install.sh --endpoint vpn.example.org:51820
   ```
   - It detects the LAN interface, gateway, DNS and LAN subnet and writes them to `/etc/wireguard/vpn.env`.
     To override: `LAN_IF=ens18 CLIENT_DNS=10.0.0.53 bash install.sh`.
   - TLS is self-signed until you sign `/etc/wg-admin/tls.csr`.
   - Behind an HTTP proxy: export `http_proxy` and `https_proxy` first (apt and git use them).
3. **First admin:**
   ```
   cd /opt/wg-admin && sudo -u wgadmin python3 -m wgadmin set-password NAME
   ```
   Then open `https://HOST:8443/`. Everything else is set in the UI.
4. **Update:** `git -C /root/wg-admin pull && bash /root/wg-admin/install.sh`. Keys, devices and settings stay.
5. **Remove:** `bash uninstall.sh` keeps keys and devices; `bash uninstall.sh --purge` deletes them (export first).

## Getting started
1. **Sign in** at `https://HOST:8443/` with the first admin account.
2. **Server settings:**
   - Check the endpoint: the public name or address and port the devices dial.
   - Check the network mode (see [NAT or Route](#network-nat-or-route)).
   - Optional: set up Mail, so wg-admin can mail setups and alerts.
3. **Connection profiles:** keep the default `split` and `full`, or add your own (routes, DNS, allowed hosts and
   ports).
   - Changing a profile's routes, DNS or IPv6 marks its devices **re-import**: they need a new QR or config.
   - Allowed destinations are enforced on the server, so changing them needs no re-import.
4. **Devices > Add a device:** name (e.g. `anna-phone`), profile, and optionally group, schedule, tags, owner email
   and activation days.
   - Phone: install the WireGuard app, tap **QR**, scan it in the app.
   - Computer: download **.conf** (or the `.zip`) and import it in the WireGuard client.
   - **Notify** mails the setup to the owner.
   - The device must connect before its **activate by** time. Enabling a late device's access again gives it the
     default deadline again.
5. **Several devices at once:** tick them (the header box ticks every device on screen), then **Bulk edit**.
   - Tick the settings to change: profile, group, schedule, enabled, tags, owner email.
   - **Apply** changes every ticked device; each one gets the same checks as a single edit, and refused devices are
     listed.
   - Settings marked * may need a re-import; the panel shows which devices.
6. **Schedules (optional):** add one (e.g. `mon-fri 07:00-18:00`) and pick it on the device.
   - wg-admin checks schedules every minute in the host's local time (`timedatectl set-timezone ...`).
   - Enabling or disabling access by hand holds until the schedule's next change.
7. **Let others manage their own devices (optional):** create a group under **Groups** with its profiles and
   schedules. Then under **Users**, add a user with the role group admin and tick the group.
8. **Authenticator (optional):** **Account > Set up authenticator**, scan the QR code, enter a code, and save the 10
   recovery codes.

## Users, groups and roles

| | Admin | Group admin |
| --- | --- | --- |
| Devices | all | only in their groups; new devices only into them |
| Profiles and schedules | create and edit | use the ones linked to their groups; create schedules for them |
| Activation days on add | 1 to 30 | the default, unless Server settings allows more |
| Log tab | everything | their groups' devices only |
| Server settings, health, groups, users | yes | no |

- The server checks these permissions on every request, not just in the UI.
- **Groups tab:** a group is a set of devices plus the profiles and schedules linked to it.
- **Users tab:** add a user, set role, groups, sign-in hours and expiry; disable; reset password or authenticator;
  delete. You can also require an authenticator for a whole role.
- **Default admin:** the first account keeps its role. It can't be disabled, scheduled, expired or deleted.
- Changing a user's role, groups, state or password ends their sessions.

## Network: NAT or Route
Set under **Server settings > Network**.

| Mode | Devices appear as | The router needs |
| --- | --- | --- |
| **NAT** (default) | this host | only the UDP port forward |
| **Route** | their own `10.66.0.N` | a route for `10.66.0.0/24` to this host, and outbound NAT for it |

Optional: a second interface can carry the decrypted traffic (transit interface + next hop).

## Firewall
- `vpn-peer` writes one nftables table, `inet wgadmin`, to `/etc/nftables.d/wgadmin.nft`, and replaces only
  that table.
- A host with its own `/etc/nftables.conf` needs `include "/etc/nftables.d/*.nft"` in it.
- Dry run: `vpn-peer check`.
- By default nothing on the LAN side can open a connection to a device.
- Route mode only: to let the LAN reach a server-type device (SSH, metrics), set
  `INBOUND=SRC>DST[/tcp|udp/PORT],...` in `/etc/wireguard/vpn.env`, then run `vpn-peer firewall`.
  Example: `INBOUND=10.1.0.10/32>10.66.0.4/32/tcp/22`.

## Backup and restore
- **Export** (root, interactive): `vpn-peer export /root/vpn-YYYYMMDD.age`.
  - age asks for a passphrase. Keep it somewhere other than the file.
  - The file holds every key.
- **Restore on a new host:**
  1. Run `install.sh` (install step 2).
  2. `vpn-peer import FILE`
  3. Run `install.sh` again.
  4. `systemctl restart wg-quick@wg0 wg-admin`

  The previous state stays in `/etc/wireguard.before-import-TIME`. Devices keep working if the new host gets the
  same endpoint, because the server key comes from the export.

## Security
- **Passwords:** scrypt hashes (N=2^15, r=8, p=1, a 16-byte salt per password), never stored in clear text.
  The password history remembers the last 24 by default (Users > Sign-in policy).
- **Lockout:** 5 failed sign-ins within 15 minutes block that network address. Admins can reset it (Users > Reset
  lockout).
- **Sessions:** HttpOnly, Secure, SameSite=Strict cookie. Changes are accepted only from wg-admin's own pages.
- **Privileges:** the app runs as the unprivileged user `wgadmin`. It reaches root only through `vpn-gate`, which
  accepts a fixed set of checked requests.
- **Keys:** device keys stay on the server (mode 600). Each stored client config is deleted after the device's first
  connection.
- **Data files:** `/etc/wg-admin/` (users, access, schedules, TOTP; mode 600, owner `wgadmin`).

## Command line

| Command | Does |
| --- | --- |
| `sudo -u wgadmin python3 -m wgadmin set-password NAME` | Set a password; creates the first admin. Also the fix when locked out. Scripted: pipe the password on stdin. |
| `sudo -u wgadmin python3 -m wgadmin totp-reset NAME` | Remove a user's authenticator (lost phone). |
| `sudo -u wgadmin python3 -m wgadmin token NAME` | API token for scripts, printed once (`Authorization: Bearer wga_...`). The same NAME replaces its old token. |
| `sudo -u wgadmin python3 -m wgadmin token-revoke NAME` | Revoke an API token. |
| `vpn-peer check` | Firewall dry run. |
| `vpn-peer firewall` | Apply the firewall again. |
| `vpn-peer export FILE` / `vpn-peer import FILE` | Encrypted backup and restore. |

## Files

| File | Role |
| --- | --- |
| install.sh | Install on any Debian 12/13 host (root), safe to run again: packages, wg0, firewall, wg-admin, nginx, logging, metrics |
| uninstall.sh | Removes it; data kept unless `--purge`; wg0 always stopped (no devices without the firewall) |
| vpn-peer.sh | All VPN logic (installed as `/usr/local/sbin/vpn-peer`) |
| vpn-gate.sh | wg-admin's only way to root (a fixed set of requests) |
| wgadmin/ | FastAPI app and the static UI |
| wg-admin.service, wg-admin.nginx.conf | App on 127.0.0.1:8080; nginx TLS front on :8443 |
| wg-connlog.* | Connection log, every 30 seconds |
| wg-metrics.* | Prometheus metrics, every minute (only with node_exporter) |
| docs/ | Screenshots for this README |

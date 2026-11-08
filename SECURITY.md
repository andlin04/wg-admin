# Security

## Reporting a vulnerability
Report it privately through GitHub: this repository's **Security** tab > **Report a vulnerability**. Please don't open
a public issue for it.

## Privilege model
| Part | Runs as | Can do |
| --- | --- | --- |
| nginx | `www-data` | TLS on :8443, proxies to 127.0.0.1:8080 |
| wg-admin (FastAPI) | `wgadmin`, systemd sandbox | Reads and writes only its own files in `/etc/wg-admin/`; asks vpn-gate for everything else |
| vpn-gate | root, one process per request, systemd sandbox | Accepts a fixed list of requests, each argument checked by a strict pattern; anything else is refused |
| vpn-peer | root (called by vpn-gate, same sandbox) | WireGuard peers, nftables table `inet wgadmin`, routing, logs |
| wg-connlog, wg-metrics | root timers, systemd sandbox | Read wg0; write their state, the debug switch for WireGuard's kernel messages, the metrics file |

- **No sudo, no setuid.** wg-admin reaches root only by writing one request line to `/run/wg-admin/gate.sock`
  (`wg-admin-gate.socket`, mode 0660, group `wgadmin`). systemd starts `vpn-gate --socket` as root for that request.
- **Sandbox** (`wg-admin.service`): `NoNewPrivileges`, no capabilities, `ProtectSystem=strict` (writes only to
  `/etc/wg-admin`), private `/tmp` and `/dev`, no home directories, kernel tunables/modules/logs protected, no
  namespaces, a `@system-service` system call filter, and only Unix, IP and netlink sockets. Limits: 256 MB memory,
  64 tasks, half a CPU. Optional: `WEBUI_EGRESS` in `vpn.env` limits its outbound connections to listed networks.
- **Root side sandbox** (`wg-admin-gate@.service`): only `CAP_NET_ADMIN` and `CAP_NET_RAW` (ping for the health
  view), `NoNewPrivileges`, writes only to `/etc/wireguard`, `/etc/nftables.d`, `/etc/rsyslog.d` and
  `/etc/logrotate.d`; no kernel modules, tunables or logs, no home directories. Restarting rsyslog and the reboot
  request go through systemd. The timer jobs have the same kind of sandbox with their own paths.
- **What a compromised web UI can still do:** any request on vpn-gate's list, which is what an admin can do in the
  UI: add, change or remove devices and profiles, change server settings, reboot. It cannot run its own commands as
  root, read the server's private key or the TLS key (both root only) or change files outside `/etc/wg-admin`. A bug
  in vpn-gate or vpn-peer reaches WireGuard, the firewall and the files above, not the rest of the system.
- **No shell from user input.** wg-admin passes requests as one argument; vpn-gate matches each against its list and
  passes the checked parts to vpn-peer as separate arguments.

## Sign-in and API
- **Passwords:** scrypt (N=2^15, r=8, p=1, 16-byte salt), constant-time comparison; unknown names cost the same time.
- **Lockout:** 5 failed sign-ins in 15 minutes block the address; admins can reset it.
- **Two-step sign-in (TOTP):** optional per account, can be required per role (Users > Sign-in policy). Each code
  works once.
- **Sessions:** random token in an HttpOnly, Secure, SameSite=Strict cookie; changes only from wg-admin's own pages
  (`Sec-Fetch-Site`). Changing a password, role or groups ends the account's sessions.
- **API tokens:** `read` (GET only, no device configs, packages or QR codes) or `admin`; expire after 90 days by
  default; stored as SHA-256 hashes; shown once. Tokens from older versions count as `admin` without expiry: replace
  them with `python3 -m wgadmin token NAME read|admin`.

## Keys and data
- Device private keys are created on the server and stored mode 600 (root). A device's stored config is deleted
  after its first connection; removing a device deletes it.
- Device configs, packages and QR codes are sent with `Cache-Control: no-store`.
- `/etc/wg-admin/`: users, tokens, TOTP secrets, schedules, access, mail settings (mode 600, owner `wgadmin`); TLS
  key (600, root; read by nginx only).
- Backups (`vpn-peer export`) are encrypted with `age` and a passphrase you choose.

## Network
- The web UI port (8443) answers only `ADMIN_SOURCES` (default: private ranges) and the host itself; VPN devices
  never reach the host. Exposing 8443 to the internet is not recommended.
- TLS 1.2 and 1.3, modern ciphers. Self-signed until you sign `/etc/wg-admin/tls.csr`; no HSTS, so a self-signed
  certificate can still be accepted in the browser.
- Headers: a Content-Security-Policy that allows only the page's own files, `X-Frame-Options`,
  `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`.
- Packages come only from Debian's repositories. install.sh turns on daily security updates (unattended-upgrades,
  no automatic reboot) unless the host has its own apt setup or `AUTO_UPDATES=off`. `sudo` is not needed or
  installed.

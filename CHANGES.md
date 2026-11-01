# Changes

Newest first. `install.sh` applies an update in place; settings, keys and devices stay.

## 2026-11-01: profile changes may need a re-imported profile on the client; bulk edit shows which devices

- Only devices whose client config changes (routes, DNS or IPv6) are marked "re-import". Allowed destinations live
  on the server: changing them, or switching between profiles that differ only there, needs no re-import.
- Bulk edit: the Profile row shows how many ticked devices the chosen profile will mark ("re-import 2 of 3"); the
  confirm lists them, or says no re-import is needed.

## 2026-11-01: block rules in a profile; fewer re-imports on a profile switch

- Allowed destinations are checked in order, first match wins; a line starting with `!` blocks. Example: the
  portal's ports, then `!192.168.0.0/16`, then `0.0.0.0/0` = the portal plus the internet, no other LAN host.
  The Firewall table shows such lines as "blocked ...".
- A profile switch may need a re-imported profile on the client: only when the routes, DNS or IPv6 differ. Between
  profiles with the same ones only the server's firewall changes.
- README screenshots retaken from the current version; new ones for bulk edit, the Log tab and Server settings >
  Logging.

## 2026-11-01: connection log, Log tab, logging settings, bulk edit with several settings

### Connection log
- `wg-connlog` (systemd timer, every 30 s) logs per device: connect, handshake, roam (endpoint changed), end (no
  handshake for 180 s) and removed (disabled, schedule or revoked), with endpoint, tunnel address and traffic.
- WireGuard's own kernel messages are logged too (handshake initiation/response, invalid handshakes, retries);
  keepalive and keypair noise stays off.
- Admin actions in wg-admin are part of the same log.

### Log tab (admins)
- VPN > **Log**: search words, kind filter (problems, connections, WireGuard handshakes, admin actions), last
  1 hour to 7 days. Kernel lines are named after the device by endpoint.
- **Log** button on each device row opens the log filtered to that device.

### Server settings > Logging
- Local log `/var/log/wg-admin/vpn.log` (rsyslog), rotated daily by logrotate, kept 1-365 days (default 30).
  The Log tab reads this file, so it works without any syslog server.
- Optional parallel forward to a syslog server over UDP or TCP. A disk queue holds lines while that server is
  down, so the local log never stalls. The view shows log size per day, the oldest day and queued bytes.
- New `vpn-peer` verbs: `log HOURS`, `logging`, `logging-set DAYS HOST|- PORT udp|tcp`.
- `install.sh` now installs `rsyslog` and `logrotate` and keeps the logging settings over updates;
  `uninstall.sh` removes the timer and configs (the log file stays).

### Devices: bulk edit
- **Bulk edit (N)** opens a panel with one row per setting: profile, group, schedule, enabled, tags (replace, add,
  remove), owner email. Tick the settings to change; all of them go to every ticked device in one go.
- Order is fixed (profile first, enabled last). If a setting is refused for a device, that device stops there and
  the result names what was already set; the other devices continue.
- Settings that need the device to import its config again are marked `*` **re-import** (profile).
- API: `POST /api/peers/apply` takes `{names, changes: [{setting, value}, ...]}` (was one `setting`/`value`).
- "VPN access" is now called **Enabled**.

### Lists
- The tick-all box sits in the device table header and ticks only the rows on screen; ticks on devices that leave
  the list (filter, tag, page) are dropped, so bulk edit and owner mail act only on visible devices.
- **Show 10 / 25 / 50 / 100 / All per page** under the device, profile and schedule lists, kept per browser.

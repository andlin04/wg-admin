"""WireGuard peers and profiles on this host (map points vpn-admin, vpn-standalone; owner decisions 2026-10-26).

wg-admin runs as the unprivileged user wgadmin and reaches vpn-peer only through `sudo -n vpn-gate "<request>"`
(deploy/vpn/vpn-gate.sh): fixed requests only, so the gate's checks stay the boundary to root. Names, routes, DNS and
descriptions are checked here and again by the gate; nothing builds a shell command from free text. Client configs
hold the client's private key: callers must never log them.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import re
import subprocess
import time
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .config import Config

NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}$")
PROFILE = re.compile(r"^[a-z0-9][a-z0-9-]{0,15}$")
TAG = re.compile(r"^[a-z0-9][a-z0-9-]{0,19}$")
DNS_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]{0,62}$")
EMAIL = re.compile(r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")  # vpn-peer EMAIL_RE
DESC = re.compile(r"^[A-Za-z0-9 ,.:;()/+'-]{0,160}$")  # vpn-gate.sh allows the same set

Runner = Callable[[list[str], int], subprocess.CompletedProcess]

README = """WireGuard VPN package for {name} (profile {profile})

Phone (iOS / Android): install the WireGuard app, tap + > Scan from QR code (the QR in the VPN admin), or import
{name}.conf. Windows / macOS: install WireGuard from https://www.wireguard.com/install/, "Import tunnel(s) from
file", pick {name}.conf, Activate. Linux: copy {name}.conf to /etc/wireguard/ and run `wg-quick up {name}`.

{name}.conf holds this device's private key: keep it on this device only. Lost device: ask an admin to revoke it.
"""


class VpnError(Exception):
    pass


def _default_runner(args: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)


def check_name(name: str) -> str:
    if not NAME.match(name):
        raise VpnError("name: 1-31 lowercase letters, digits or dashes, e.g. anna-phone")
    return name


def check_profile(profile: str) -> str:
    if not PROFILE.match(profile):
        raise VpnError("profile name: 1-16 lowercase letters, digits or dashes, e.g. lab-only")
    return profile


def check_tags(tags: list[str]) -> list[str]:
    """Device tags for the filter: lowercased, deduplicated, max 8."""
    out = list(dict.fromkeys(t.strip().lower() for t in tags if t.strip()))
    if len(out) > 8 or not all(TAG.match(t) for t in out):
        raise VpnError("tags: up to 8, each 1-20 lowercase letters, digits or dashes, e.g. family")
    return out


def _items(text: str) -> list[str]:
    return [x for x in re.split(r"[\s,]+", text.strip()) if x]


def allow_rules(text: str, ipv6: bool) -> list[str]:
    """Allowed destinations (map vpn-profile-rules, owner 2026-10-27): one rule per line or comma,
    `CIDR` or `CIDR tcp|udp PORT[-PORT]` -> gate tokens `CIDR[/proto/PORT[-PORT]]`. Empty = the routes."""
    out = []
    for line in re.split(r"[\n,]", text):
        parts = line.split()
        if not parts:
            continue
        try:
            net = ipaddress.ip_network(parts[0])
        except ValueError:
            raise VpnError(f"rule {line.strip()!r}: {parts[0]!r} is not a network such as 192.168.0.10/32") from None
        if net.version == 6 and not ipv6:
            raise VpnError(f"rule {line.strip()!r}: IPv6 rules need IPv6 on")
        token = str(net)
        if len(parts) > 1:
            m = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", parts[2]) if len(parts) == 3 else None
            lo, hi = (int(m[1]), int(m[2] or m[1])) if m else (0, 0)
            if parts[1].lower() not in ("tcp", "udp") or not 1 <= lo <= hi <= 65535:
                raise VpnError(f"rule {line.strip()!r}: use CIDR, or CIDR tcp|udp PORT[-PORT]")
            token += f"/{parts[1].lower()}/{lo}" + (f"-{hi}" if hi != lo else "")
        out.append(token)
    if len(out) > 20:
        raise VpnError("allowed destinations: at most 20 rules")
    return out


def rule_text(token: str) -> str:
    """Gate token -> the form's line: 192.168.0.10/32/tcp/443 -> '192.168.0.10/32 tcp 443'."""
    addr, prefix, *rest = token.split("/")
    return " ".join([f"{addr}/{prefix}", *rest])


def profile_request(name: str, routes: str, dns: str, description: str, ipv6: bool = False, allow: str = "") -> str:
    """Checked `profile-set` gate request. routes/dns: comma- or space-separated; empty dns = no DNS line.
    ipv6: devices also get fd66:66::N and vpn1 forwards their IPv6 to the IPv6 routes (off: IPv6 is dropped).
    allow: allowed destinations (allow_rules); empty = the profile's peers may reach all its routes."""
    nets = []
    for r in _items(routes):
        try:
            nets.append(str(ipaddress.ip_network(r)))
        except ValueError:
            raise VpnError(f"route {r!r} is not a network such as 192.168.4.0/24 (host bits must be 0)") from None
    if not 1 <= len(nets) <= 20:
        raise VpnError("routes: 1-20 networks, e.g. 192.168.0.0/24 or 0.0.0.0/0")
    if ipv6 and not any(":" in n for n in nets):
        raise VpnError("IPv6 on needs an IPv6 route, e.g. ::/0")
    servers = []
    for d in _items(dns.lower()):
        try:
            servers.append(str(ipaddress.ip_address(d)))
        except ValueError:
            if not DNS_NAME.match(d):
                raise VpnError(f"DNS {d!r} is not an address or a search domain") from None
            servers.append(d)
    if len(servers) > 4:
        raise VpnError("DNS: at most 4 entries")
    description = " ".join(description.split())
    if not DESC.match(description):
        raise VpnError("description: up to 160 letters, digits, spaces and , . : ; ( ) / + ' -")
    v6 = "on" if ipv6 else "off"
    rules = ",".join(allow_rules(allow, ipv6)) or "-"
    return (f"profile-set {check_profile(name)} {','.join(nets)} {','.join(servers) or 'none'} v6={v6} allow={rules} "
            f"{description}").rstrip()


def call(cfg: Config, request: str, runner: Runner | None = None) -> str:
    """One gate request (sudo -n vpn-gate REQUEST) -> its output; a non-zero exit becomes VpnError."""
    args = ([cfg.sudo, "-n"] if cfg.sudo else []) + [cfg.gate, request]
    try:
        proc = (runner or _default_runner)(args, cfg.timeout_s)
    except subprocess.TimeoutExpired:
        raise VpnError(f"vpn-peer did not answer within {cfg.timeout_s}s") from None
    except FileNotFoundError:
        raise VpnError(f"not found: {args[0]}") from None
    if proc.returncode != 0:
        # Not stdout: for conf/qr it would be the client's private key.
        msg = (proc.stdout or "").strip() if len(proc.stdout or "") < 200 else ""
        raise VpnError(f"refused or failed (exit {proc.returncode}): {(msg or proc.stderr or '').strip()[:300]}")
    return proc.stdout or ""


def parse_dump(text: str) -> list[dict[str, Any]]:
    """`vpn-peer dump` (name profile address handshake rx tx created [tags [reimport]], tab-separated) -> peer
    dicts. reimport: the client config changed since it was last fetched (the device must import it again)."""
    peers = []
    for line in text.splitlines():
        f = line.split("\t")
        if len(f) not in (7, 8, 9, 10, 11) or not NAME.match(f[0]):
            continue
        num = [int(x) if x.isdigit() else 0 for x in f[3:7]]
        tags = [t for t in f[7].split(",") if TAG.match(t)] if len(f) >= 8 else []
        peers.append({"name": f[0], "profile": f[1], "address": f[2], "handshake": num[0] or None,
                      "rx": num[1], "tx": num[2], "created": num[3] or None, "tags": tags,
                      "reimport": len(f) >= 9 and f[8] == "1",
                      "email": f[9] if len(f) >= 10 and EMAIL.match(f[9]) else "",
                      "enabled": not (len(f) == 11 and f[10] == "1")})
    return peers


def parse_profiles(text: str) -> list[dict[str, Any]]:
    """`vpn-peer profiles` (name routes dns peers ipv6 allow description, tab-separated; older vpn-peer: no ipv6,
    no allow) -> profile dicts. allow: the form's rule lines, [] = all routes allowed."""
    out = []
    for line in text.splitlines():
        f = line.split("\t")
        if len(f) not in (5, 6, 7) or not PROFILE.match(f[0]):
            continue
        allow = f[5] if len(f) == 7 and f[5] != "-" else ""
        out.append({"name": f[0], "routes": f[1].split(","), "dns": [] if f[2] == "none" else f[2].split(","),
                    "peers": int(f[3]) if f[3].isdigit() else 0, "ipv6": len(f) >= 6 and f[4] == "on",
                    "allow": [rule_text(t) for t in allow.split(",") if t], "description": f[-1]})
    return out


def profiles(cfg: Config, runner: Runner | None = None) -> list[dict[str, Any]]:
    return parse_profiles(call(cfg, "profiles", runner))


def save_profile(cfg: Config, name: str, routes: str, dns: str, description: str,
                 runner: Runner | None = None, ipv6: bool = False, allow: str = "") -> str:
    return call(cfg, profile_request(name, routes, dns, description, ipv6, allow), runner).strip()


def delete_profile(cfg: Config, name: str, runner: Runner | None = None) -> str:
    return call(cfg, f"profile-del {check_profile(name)}", runner).strip()


def peers(cfg: Config, runner: Runner | None = None) -> list[dict[str, Any]]:
    return parse_dump(call(cfg, "dump", runner))


def add(cfg: Config, name: str, profile: str, runner: Runner | None = None) -> str:
    return call(cfg, f"add {check_name(name)} {check_profile(profile)}", runner).strip()


def set_profile(cfg: Config, name: str, profile: str, runner: Runner | None = None) -> str:
    return call(cfg, f"profile {check_name(name)} {check_profile(profile)}", runner).strip()


def set_tags(cfg: Config, name: str, tags: list[str], runner: Runner | None = None) -> str:
    return call(cfg, f"tags {check_name(name)} {','.join(check_tags(tags)) or '-'}", runner).strip()


def check_email(email: str) -> str:
    """Device owner's address (map vpn-mail); "" = none."""
    email = email.strip()
    if email and (len(email) > 254 or not EMAIL.match(email)):
        raise VpnError("email: an address like anna@example.org")
    return email


def set_email(cfg: Config, name: str, email: str, runner: Runner | None = None) -> str:
    return call(cfg, f"email {check_name(name)} {check_email(email) or '-'}", runner).strip()


def set_enabled(cfg: Config, name: str, enabled: bool, runner: Runner | None = None) -> str:
    """Disable: the peer leaves the live WireGuard config and the firewall; keys, profile, tags and email stay."""
    return call(cfg, f"{'enable' if enabled else 'disable'} {check_name(name)}", runner).strip()


BULK_MAX = 50


def parse_bulk(text: str, profiles: set[str], existing: set[str]) -> list[tuple[str, str, list[str], str]]:
    """Bulk add (map vpn-standalone step 3): CSV lines `name[,profile[,tags[,email]]]`, tags separated by spaces
    or ';'.
    Blank lines, '#' comments and a `name,...` header are skipped; profile defaults to split. All lines are checked
    before anything is created: any error -> VpnError listing the bad lines."""
    rows, errors, seen = [], [], set()
    for no, row in enumerate(csv.reader(io.StringIO(text)), 1):
        cells = [c.strip() for c in row]
        if not cells or not cells[0] or cells[0].startswith("#") or (no == 1 and cells[0].lower() == "name"):
            continue
        name, profile = cells[0].lower(), (cells[1].lower() if len(cells) > 1 and cells[1] else "split")
        try:
            check_name(name)
            tags = check_tags(re.split(r"[\s;]+", cells[2] if len(cells) > 2 else ""))
            email = check_email(cells[3] if len(cells) > 3 else "")
            if len(cells) > 4:
                raise VpnError("at most 4 columns: name, profile, tags, email")
            if profile not in profiles:
                raise VpnError(f"no profile {profile!r}")
            if name in existing or name in seen:
                raise VpnError(f"{name} exists")
        except VpnError as exc:
            errors.append(f"line {no}: {exc}")
            continue
        seen.add(name)
        rows.append((name, profile, tags, email))
    if errors:
        raise VpnError("; ".join(errors[:10]) + (f" (+{len(errors) - 10} more)" if len(errors) > 10 else ""))
    if not 1 <= len(rows) <= BULK_MAX:
        raise VpnError(f"1-{BULK_MAX} devices per bulk add")
    return rows


def remove(cfg: Config, name: str, runner: Runner | None = None) -> str:
    return call(cfg, f"remove {check_name(name)}", runner).strip()


def client_conf(cfg: Config, name: str, runner: Runner | None = None) -> str:
    return call(cfg, f"conf {check_name(name)}", runner)


def qr_svg(cfg: Config, name: str, runner: Runner | None = None) -> str:
    out = call(cfg, f"qr {check_name(name)}", runner)
    if "<svg" not in out:
        raise VpnError("vpn-peer sent no QR code")
    return out[out.index("<svg"):]


SERVER_FIELDS = (("endpoint", "Endpoint (in client configs)"), ("listen_port", "Listen port (UDP)"),
                 ("address", "Tunnel addresses (wg0)"), ("mtu", "MTU"), ("keepalive", "Client keepalive (s)"),
                 ("public_key", "Server public key"), ("peers", "Peers"), ("profiles", "Profiles"),
                 ("reimport", "Devices to re-import"), ("wg_up", "wg0 up"), ("nft_active", "nftables"),
                 ("wg_tools", "wireguard-tools"), ("kernel", "Kernel"))
EDITABLE = ("endpoint", "listen_port", "keepalive")  # server_request; the rest is fixed by install.sh


def server(cfg: Config, runner: Runner | None = None) -> list[dict[str, str]]:
    """Server view (map vpn-standalone step 2): `vpn-peer server` as labelled rows; EDITABLE ones carry `edit`."""
    h = parse_health(call(cfg, "server", runner))
    defaults = {"mtu": "default (1420)", "endpoint": "not set (vpn.env)"}
    return [{"key": k, "label": label, "value": h.get(k) or defaults.get(k, "-"), "edit": k in EDITABLE}
            for k, label in SERVER_FIELDS]


def server_request(endpoint: str, listen_port: int, keepalive: int) -> str:
    """Checked `server-set` gate request. endpoint: host:port the clients dial (a name, IPv4 or [IPv6])."""
    host, sep, port = endpoint.strip().lower().rpartition(":")
    if host.startswith("[") and host.endswith("]"):
        try:
            ok = ipaddress.ip_address(host[1:-1]).version == 6
        except ValueError:
            ok = False
    else:
        ok = bool(re.match(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$", host))
    if not (sep and ok and port.isdigit() and 1 <= int(port) <= 65535):
        raise VpnError("endpoint: host:port, e.g. vpn.example.org:51820 or [2001:db8::1]:51820")
    if not 1 <= listen_port <= 65535:
        raise VpnError("listen port: 1-65535")
    if not 0 <= keepalive <= 3600:
        raise VpnError("keepalive: 0-3600 seconds (0 = off)")
    return f"server-set {host}:{int(port)} {listen_port} {keepalive}"


def save_server(cfg: Config, endpoint: str, listen_port: int, keepalive: int, runner: Runner | None = None) -> str:
    return call(cfg, server_request(endpoint, listen_port, keepalive), runner).strip()


IFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,14}$")


def network(cfg: Config, runner: Runner | None = None) -> dict[str, Any]:
    """Server > Network (map vpn-routing-mode): mode nat|route, incoming/transit interface, transit gateway and the
    interfaces with an IPv4 address ({name, addr})."""
    out: dict[str, Any] = {"interfaces": []}
    for line in call(cfg, "network", runner).splitlines():
        k, sep, v = line.partition("=")
        if not sep:
            continue
        if k == "iface":
            name, _, addr = v.strip().partition(" ")
            out["interfaces"].append({"name": name, "addr": addr})
        elif k in ("mode", "lan_if", "transit_if", "transit_gw", "gateway"):
            out[k] = v.strip()
    return out


def network_request(mode: str, in_if: str, out_if: str, gateway: str) -> str:
    """Checked `network-set` gate request. nat: out_if/gateway ignored; route with out_if == in_if: no gateway."""
    if mode not in ("nat", "route"):
        raise VpnError("mode: nat or route")
    if mode == "nat" or not out_if:
        out_if = in_if
    for i in (in_if, out_if):
        if not IFACE_RE.match(i) or i in ("lo", "wg0"):
            raise VpnError(f"interface {i or '?'}: pick one from the list")
    gw = "-"
    if mode == "route" and out_if != in_if:
        try:
            gw = str(ipaddress.IPv4Address(gateway.strip()))
        except ValueError:
            raise VpnError(f"gateway: the IPv4 next hop on {out_if}") from None
    return f"network-set {mode} {in_if} {out_if} {gw}"


def save_network(cfg: Config, mode: str, in_if: str, out_if: str, gateway: str, runner: Runner | None = None) -> str:
    return call(cfg, network_request(mode, in_if, out_if, gateway), runner).strip()


def ruleset(cfg: Config, runner: Runner | None = None) -> str:
    return call(cfg, "ruleset", runner)


def reboot(cfg: Config, runner: Runner | None = None) -> str:
    """Server settings > Reboot (map wg-admin-reboot): the gate schedules the reboot 5 s ahead."""
    return call(cfg, "reboot", runner).strip()


HANDSHAKE_FRESH_S = 180  # a handshake younger than this = connected (WireGuard re-handshakes every 2 min)
WG_PORT = 51820


def parse_health(text: str) -> dict[str, str]:
    """`vpn-peer health` key=value lines -> dict (unknown lines skipped)."""
    out = {}
    for line in text.splitlines():
        k, sep, v = line.partition("=")
        if sep and re.match(r"^[a-z0-9_]+$", k):
            out[k] = v.strip()
    return out


def _node(id_: str, label: str, status: str, line: str, details: dict[str, Any]) -> dict[str, Any]:
    return {"id": id_, "label": label, "status": status, "line": line, "details": details}


WAN_IP = "1.1.1.1"  # pinged through the LAN gateway (GATEWAY in vpn.env)
RTT_WARN_MS = 100.0


def _probe(loss: str, rtt: str) -> tuple[str, str]:
    """(status, text) of one ping result from `vpn-peer health`: any loss = bad, rtt > 100 ms = warn."""
    try:
        lost = float(loss)
    except ValueError:
        return "unknown", "not checked"
    if lost > 0:
        return "bad", f"{lost:g}% loss"
    try:
        ms = float(rtt)
    except ValueError:
        return "ok", "answers"
    return ("warn" if ms > RTT_WARN_MS else "ok"), f"{ms:g} ms"


def _rate(value: float) -> str:
    bits = value * 8
    for unit, size in (("Gbit/s", 1e9), ("Mbit/s", 1e6), ("kbit/s", 1e3)):
        if bits >= size:
            return f"{bits / size:.1f} {unit}"
    return f"{bits:.0f} bit/s"


def _counters(net_dir: Path, lan: str) -> dict[str, int]:
    out = {}
    for dev in (lan, "wg0"):
        for d in ("rx", "tx"):
            try:
                out[f"{dev} {d}"] = int((net_dir / dev / "statistics" / f"{d}_bytes").read_text())
            except (OSError, ValueError):
                pass
    return out


def load(net_dir: Path, interval: float = 1.0, sleep: Callable[[float], None] = time.sleep, lan: str = "eth0") -> str:
    """LAN interface + wg0 throughput over `interval` seconds from the kernel's byte counters (no Prometheus)."""
    before = _counters(net_dir, lan)
    sleep(interval)
    after = _counters(net_dir, lan)
    parts = [f"{k} {_rate(max(after[k] - v, 0) / interval)}" for k, v in sorted(before.items()) if k in after]
    return ", ".join(parts) or "no counters"


def _firewall_node(h: dict[str, str], err: str, load_text: str) -> dict[str, Any]:
    """The LAN gateway seen from this host: ping to its address (inside) and to the internet through it (WAN), plus
    load. Node id stays "pfsense" (the UI's icon key); name and address come from vpn.env through vpn-peer health."""
    name, lan = h.get("gateway_name") or "Gateway", h.get("lan_if") or "eth0"
    if err:
        return _node("pfsense", name, "unknown", "vpn-peer did not answer",
                     {"Error": err, f"Load ({lan}/wg0)": load_text})
    gw_s, gw_t = _probe(h.get("gw_loss", ""), h.get("gw_rtt_ms", ""))
    wan_s, wan_t = _probe(h.get("wan_loss", ""), h.get("wan_rtt_ms", ""))
    via = "DNS resolve" if h.get("wan_via") == "dns" else "ping"
    status = next((s for s in ("bad", "warn", "unknown") if s in (gw_s, wan_s)), "ok")
    details = {f"LAN gateway {h.get('gateway') or '-'} (ping)": gw_t,
               f"Internet {WAN_IP} through {name} ({via})": wan_t,
               f"Load ({lan}/wg0, 1 s sample)": load_text,
               "Thresholds": f"any loss = bad, rtt > {RTT_WARN_MS:g} ms = warn"}
    return _node("pfsense", name, status, f"LAN gw {gw_t}, internet {wan_t}", details)


def _add_transit(pf: dict[str, Any], h: dict[str, str]) -> None:
    """The gateway's end of the transit link (TRANSIT_IF) on the same gateway node: one box per device, the links
    show the legs (owner 2026-10-29)."""
    t_gw = h.get("transit_gw") or "-"
    s, t = _probe(h.get("transit_loss", ""), h.get("transit_rtt_ms", ""))
    pf["details"][f"Transit gateway {t_gw} on {h['transit_if']} (ping)"] = t
    pf["details"]["Transit role"] = (f"firewall rules for device traffic; route back to the tunnel via "
                                     f"{h.get('transit_addr') or '-'}")
    if "Error" not in pf["details"]:  # vpn-peer answered
        pf["line"] += f", transit {t}"
        order = ("bad", "warn", "unknown", "ok")
        pf["status"] = min(pf["status"], s, key=order.index)


def health(cfg: Config, runner: Runner | None = None, now: float | None = None,
           load_text: str | None = None) -> dict[str, Any]:
    """VPN health map: devices, Internet, LAN gateway, this host, LAN/DNS, deterministic checks.
    Each node: {id, label, status ok|warn|bad|unknown, line, details}; each link: {from, to, label}."""
    now = time.time() if now is None else now
    try:
        h = parse_health(call(cfg, "health", runner))
        err = ""
    except VpnError as exc:
        h, err = {}, str(exc)
    endpoint = h.get("endpoint", "")
    wan = _node("wan", "Internet / WAN", "ok" if endpoint else "unknown",
                f"Clients connect to {endpoint}" if endpoint else "No endpoint known",
                {"Endpoint": endpoint or "-", "Note": "Server view, or ENDPOINT in /etc/wireguard/vpn.env."})
    try:
        plist = peers(cfg, runner) if not err else []
    except VpnError:
        plist = []
    conn = [p["name"] for p in plist if p["handshake"] and now - p["handshake"] < HANDSHAKE_FRESH_S]
    lan_if, host = h.get("lan_if") or "eth0", h.get("host") or "vpn1"  # node id "vpn1" = the UI's icon key
    pf = _firewall_node(h, err, load(cfg.net_dir, lan=lan_if) if load_text is None else load_text)
    if err:
        v1 = _node("vpn1", host, "bad", "vpn-peer did not answer", {"Error": err})
    else:
        port = h.get("listen_port_conf") or str(WG_PORT)  # wg0.conf's port (Server view), older vpn-peer: 51820
        checks = {"wg0 up": h.get("wg_up") == "1", "Server key set": h.get("key_set") == "1",
                  f"Listen port {port}": h.get("listen_port") == port,
                  "nftables active": h.get("nft_active") == "active", "IP forwarding": h.get("ip_forward") == "1"}
        failed = [k for k, ok in checks.items() if not ok]
        details = {k: "ok" if ok else "FAILED" for k, ok in checks.items()}
        details.update({"Listen port": h.get("listen_port") or "-", "nftables": h.get("nft_active") or "-",
                        "ip_forward": h.get("ip_forward") or "-", "IPv6 forwarding": h.get("ipv6_forward") or "-",
                        f"IPv6 upstream ({lan_if})": {"1": "yes", "0": "none: IPv6 profiles reach only the tunnel"}.get(
                            h.get("ipv6_upstream", ""), "-")})
        v1 = _node("vpn1", host, "bad" if failed else "ok",
                   "Failed: " + ", ".join(failed) if failed else f"wg0 up on :{h.get('listen_port')}, nftables on",
                   details)
    dns, server, qname = h.get("dns_ok", ""), h.get("dns_server", ""), h.get("dns_name", "")
    lan = _node("lan", "LAN / DNS", {"1": "ok", "0": "bad"}.get(dns, "unknown"),
                {"1": f"DNS {server} answers", "0": f"DNS {server} does not answer"}.get(
                    dns, "DNS not checked (DNS_CHECK in vpn.env, or dig missing)" if dns == "unknown"
                    else "No answer"),
                {"Query": f"dig @{server} {qname}" if server else "-", "Result": dns or "-"})
    never = [p["name"] for p in plist if not p["handshake"]]
    idle = [p["name"] for p in plist if p["name"] not in conn and p["name"] not in never]
    dev = _node("devices", "Devices", "unknown" if err else "ok" if plist else "warn",
                "Unknown" if err else f"{len(conn)} connected, {len(idle)} idle, {len(never)} never" if plist
                else "No devices yet",
                {"Connected (< 3 min)": ", ".join(conn) or "-", "Idle": ", ".join(idle) or "-",
                 "Never connected": ", ".join(never) or "-"})
    # Topology (map vpn-transit): each box once, top to bottom; links = what crosses them, from = who starts it
    # (owner 2026-10-29: short labels, the popups hold the rest).
    port = h.get("listen_port_conf") or str(WG_PORT)
    t_if = h.get("transit_if", "")
    links = [{"from": "devices", "to": "wan", "label": "VPN tunnel, encrypted"},
             {"from": "wan", "to": "pfsense", "label": f"incoming VPN connections, UDP {port}"},
             {"from": "pfsense", "to": "wan", "label": "outgoing VPN client traffic"},
             {"from": "pfsense", "to": "vpn1", "label": f"port forward to {lan_if}"}]
    if t_if:
        _add_transit(pf, h)
        links += [{"from": "vpn1", "to": "pfsense", "label": f"decrypted client traffic, {t_if} transit"},
                  {"from": "pfsense", "to": "lan", "label": "client traffic to LAN, firewall rules"}]
    else:
        nat = ", NAT" if h.get("nat4") == "on" else ""
        links += [{"from": "vpn1", "to": "pfsense", "label": f"client internet traffic, {lan_if}{nat}"},
                  {"from": "vpn1", "to": "lan", "label": f"decrypted client traffic, {lan_if}{nat}"}]
    return {"nodes": [dev, wan, pf, v1, lan], "links": links, "checked_at": int(now)}


def package(name: str, profile: str, conf: str) -> bytes:
    """Zip with the client config and per-OS install steps (links to the official apps, no installers)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"{name}.conf", conf)
        z.writestr("README.txt", README.format(name=name, profile=profile))
    return buf.getvalue()

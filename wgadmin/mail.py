"""Mail from wg-admin (map vpn-mail): SMTP settings in mail.json, the relay password in smtp.secret (both 600
wgadmin, created by setup-vpn1.sh; written in place: wgadmin cannot create files in /etc/wg-admin), smtplib only.
Notices carry no key material (owner 2026-10-26): device name, what changed, how to get the new config."""
from __future__ import annotations

import json
import os
import re
import smtplib
import ssl
from collections.abc import Callable
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path
from typing import Any

from .vpn import EMAIL, VpnError

HOST = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$")
SECURITY = ("none", "starttls", "ssl")
DEFAULTS: dict[str, Any] = {"from_addr": "", "host": "", "port": 25, "security": "none", "user": ""}
KINDS = {
    "changed": ("Your VPN configuration for {name} has changed",
                "The VPN settings for your device {name} have changed. The device must import its new configuration"
                " in the WireGuard app before it can connect again."),
    "ready": ("Your VPN access for {name} is ready",
              "A VPN profile has been set up for your device {name}. Import it in the WireGuard app to connect."),
}
BODY = """Hello,

{lines}

Ask your administrator for the new configuration (QR code or file). This mail holds no keys or passwords.

Kind regards,
VPN administration
"""

Sender = Callable[[dict[str, Any], str, EmailMessage], None]


def load(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    return {k: data.get(k, v) if isinstance(data, dict) else v for k, v in DEFAULTS.items()}


def _write(path: Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


def check(s: dict[str, Any]) -> dict[str, Any]:
    out = {"from_addr": str(s.get("from_addr", "")).strip(), "host": str(s.get("host", "")).strip().lower(),
           "port": s.get("port"), "security": s.get("security"), "user": str(s.get("user", "")).strip()}
    if not EMAIL.match(out["from_addr"]):
        raise VpnError("from address: a plain address like vpn@example.org")
    if not HOST.match(out["host"]):
        raise VpnError("relay host: a host name or IPv4 address")
    if not isinstance(out["port"], int) or not 1 <= out["port"] <= 65535:
        raise VpnError("port: 1-65535")
    if out["security"] not in SECURITY:
        raise VpnError("security: none, starttls or ssl")
    if len(out["user"]) > 200 or any(c.isspace() for c in out["user"]):
        raise VpnError("user: no spaces, up to 200 characters")
    return out


def save(cfg: Any, s: dict[str, Any], password: str | None) -> dict[str, Any]:
    """password None = keep the stored one, "" = clear it."""
    s = check(s)
    _write(cfg.mail_file, json.dumps(s, indent=1))
    if password is not None:
        _write(cfg.smtp_secret_file, password)
    return s


def password(cfg: Any) -> str:
    try:
        return cfg.smtp_secret_file.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def view(cfg: Any) -> dict[str, Any]:
    s = load(cfg.mail_file)
    return {**s, "password_set": bool(password(cfg)), "ready": bool(s["from_addr"] and s["host"])}


def message(s: dict[str, Any], to: str, subject: str, body: str) -> EmailMessage:
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = s["from_addr"], to, subject
    msg["Date"], msg["Message-ID"] = formatdate(localtime=True), make_msgid(domain=s["from_addr"].split("@")[1])
    msg.set_content(body)
    return msg


def notice(s: dict[str, Any], to: str, names: list[str], kind: str) -> EmailMessage:
    subject, line = KINDS[kind]
    subj = subject.format(name=names[0]) if len(names) == 1 else subject.format(name=f"{len(names)} devices")
    return message(s, to, subj, BODY.format(lines="\n\n".join(line.format(name=n) for n in names)))


def smtp_send(s: dict[str, Any], pw: str, msg: EmailMessage) -> None:
    ctx = ssl.create_default_context()
    try:
        if s["security"] == "ssl":
            conn: smtplib.SMTP = smtplib.SMTP_SSL(s["host"], s["port"], timeout=15, context=ctx)
        else:
            conn = smtplib.SMTP(s["host"], s["port"], timeout=15)
        with conn:
            if s["security"] == "starttls":
                conn.starttls(context=ctx)
            if s["user"]:
                conn.login(s["user"], pw)
            conn.send_message(msg)
    except (OSError, smtplib.SMTPException) as exc:
        raise VpnError(f"mail to {msg['To']} failed: {type(exc).__name__}: {str(exc)[:200]}") from None

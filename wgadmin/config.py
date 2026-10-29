"""wg-admin settings from the environment (/etc/wg-admin/wg-admin.env, written by setup-vpn1.sh)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default).strip()


@dataclass(frozen=True)
class Config:
    gate: str = field(default_factory=lambda: _env("WGADMIN_GATE", "/usr/local/sbin/vpn-gate"))
    sudo: str = field(default_factory=lambda: _env("WGADMIN_SUDO", "sudo"))  # "" = call the gate directly
    timeout_s: int = 30
    # Local accounts for standalone use: {name: scrypt hash}, written by `python3 -m wgadmin set-password NAME`.
    users_file: Path = field(default_factory=lambda: Path(_env("WGADMIN_USERS", "/etc/wg-admin/users.json")))
    # API tokens for scripts: {name: sha256}, written by `python3 -m wgadmin token NAME`.
    tokens_file: Path = field(default_factory=lambda: Path(_env("WGADMIN_TOKENS", "/etc/wg-admin/tokens.json")))
    # Authenticator (TOTP) per local account, set up in the UI: {name: {secret, last, recovery}}.
    totp_file: Path = field(default_factory=lambda: Path(_env("WGADMIN_TOTP", "/etc/wg-admin/totp.json")))
    # Access schedules + device assignments (schedule.py); checked every schedule_s seconds, 0 = off.
    schedules_file: Path = field(default_factory=lambda: Path(_env("WGADMIN_SCHEDULES", "/etc/wg-admin/schedules.json")))
    schedule_s: int = 60
    # Device groups, device -> group and the TOTP-by-role policy (access.py; map wg-admin-groups).
    access_file: Path = field(default_factory=lambda: Path(_env("WGADMIN_ACCESS", "/etc/wg-admin/access.json")))
    # Portal SSO: nginx on the portal host sends X-Portal-User/-Role and this secret; trusted only from these IPs.
    secret_file: Path = field(default_factory=lambda: Path(_env("WGADMIN_SECRET_FILE", "/etc/wg-admin/portal.secret")))
    trusted_proxies: tuple[str, ...] = field(
        default_factory=lambda: tuple(x for x in _env("WGADMIN_TRUSTED_PROXIES", "").replace(",", " ").split() if x))
    # Audit events to the portal (journal, Slack); empty = log only. CA file: the portal's TLS CA.
    event_url: str = field(default_factory=lambda: _env("WGADMIN_EVENT_URL", ""))
    ca_file: str = field(default_factory=lambda: _env("WGADMIN_CA_FILE", ""))
    # Mail (mail.py): SMTP settings and the relay password, both 600 wgadmin (setup-vpn1.sh creates them).
    mail_file: Path = field(default_factory=lambda: Path(_env("WGADMIN_MAIL", "/etc/wg-admin/mail.json")))
    smtp_secret_file: Path = field(default_factory=lambda: Path(_env("WGADMIN_SMTP_SECRET", "/etc/wg-admin/smtp.secret")))
    net_dir: Path = Path("/sys/class/net")
    session_s: int = 12 * 3600

    def secret(self) -> str:
        try:
            return self.secret_file.read_text(encoding="utf-8").strip()
        except OSError:
            return ""

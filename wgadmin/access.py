"""Device groups, roles and the sign-in policy (map wg-admin-groups, owner decisions 2026-10-29).

Roles per web UI account (users.json, auth.py): admin = everything; group-admin = the devices of one or more
groups, picking from the profiles and schedules an admin linked to each group, creating schedules for them. A device
is in one group or none. Portal SSO users and API tokens are admins.

File (/etc/wg-admin/access.json, 600 wgadmin, written in place: the directory is root's):
{"groups": {NAME: {"description", "profiles": [PROFILE], "schedules": [SCHEDULE]}},
 "members": {PEER: GROUP}, "totp_roles": [ROLE]}
"""
from __future__ import annotations

import json
import os
from datetime import date, datetime
from pathlib import Path
from typing import Any

from . import schedule
from .vpn import DESC, PROFILE, VpnError

ROLES = ("admin", "group-admin")


def load(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    groups = {k: {"description": v.get("description", ""), "profiles": list(v.get("profiles") or []),
                  "schedules": list(v.get("schedules") or [])}
              for k, v in (data.get("groups") or {}).items() if isinstance(v, dict)}
    members = {k: v for k, v in (data.get("members") or {}).items() if isinstance(v, str) and v in groups}
    roles = [r for r in data.get("totp_roles") or [] if r in ROLES]
    return {"groups": groups, "members": members, "totp_roles": roles}


def save(path: Path, data: dict[str, Any]) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1, sort_keys=True)


def check_group(name: str, description: str, profiles: list[str], schedules: list[str],
                known_profiles: set[str], known_schedules: set[str]) -> dict[str, Any]:
    """Form fields -> the stored group (VpnError names the bad field)."""
    if not PROFILE.match(name):
        raise VpnError("group name: 1-16 lowercase letters, digits or dashes, e.g. family")
    description = " ".join(description.split())
    if not DESC.match(description):
        raise VpnError("description: up to 160 letters, digits, spaces and , . : ; ( ) / + ' -")
    for p in profiles:
        if p not in known_profiles:
            raise VpnError(f"no connection profile {p!r}")
    for s in schedules:
        if s not in known_schedules:
            raise VpnError(f"no schedule {s!r}")
    return {"description": description, "profiles": sorted(set(profiles)), "schedules": sorted(set(schedules))}


def unlink(data: dict[str, Any], kind: str, name: str) -> None:
    """A deleted profile or schedule leaves every group (kind: profiles | schedules)."""
    for g in data["groups"].values():
        if name in g[kind]:
            g[kind].remove(name)


def schedule_groups(data: dict[str, Any], name: str) -> set[str]:
    return {g for g, v in data["groups"].items() if name in v["schedules"]}


# ---------------------------------------------------------------- accounts (the entries of users.json)
def check_account(role: str, groups: list[str], sign_in: str, expires: str, known_groups: set[str],
                  known_schedules: set[str]) -> dict[str, Any]:
    """Role, groups, sign-in schedule and expiry of an account (VpnError names the bad field)."""
    if role not in ROLES:
        raise VpnError("role: admin or group-admin")
    # A group admin without groups is allowed (owner 2026-10-29): it sees no devices until an admin assigns one.
    groups = sorted(set(groups)) if role == "group-admin" else []
    for g in groups:
        if g not in known_groups:
            raise VpnError(f"no group {g!r}")
    if sign_in and sign_in not in known_schedules:
        raise VpnError(f"no schedule {sign_in!r}")
    if expires:
        try:
            expires = date.fromisoformat(expires.strip()).isoformat()
        except ValueError:
            raise VpnError(f"expires {expires!r}: a date like 2026-12-31") from None
    return {"role": role, "groups": groups, "schedule": sign_in, "expires": expires}


def refused(account: dict[str, Any], schedules: dict[str, Any], now: datetime) -> str:
    """Why this account may not be signed in now ("" = it may): disabled, expired, outside its sign-in hours."""
    if account.get("disabled"):
        return "account disabled"
    if account.get("expires") and now.date().isoformat() > account["expires"]:
        return "account expired"
    s = schedules.get(account.get("schedule") or "")
    if account.get("schedule") and (s is None or not schedule.active(s, now)):
        return "outside this account's sign-in hours"
    return ""

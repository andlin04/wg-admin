"""Access schedules (map vpn-totp-schedules, owner 2026-10-27): named schedule profiles assigned to devices; wg-admin
switches each assigned device on or off with the existing enable/disable gate verbs (web.py runs tick() every
60 s). Deterministic, no model (rule:automation-principle). Times are this host's local time.

A schedule is on when today is inside valid-from..expires AND (it has no windows and no dates, OR a weekly window
matches now, OR today is one of its calendar dates). A manual on/off of a scheduled device is a hold: it lasts
while the schedule's own answer stays what it was at the click, so the next schedule change takes over again.

File (/etc/wg-admin/schedules.json, 600 wgadmin, written in place: the directory is root's):
{"schedules": {NAME: {"description", "weekly": [{"days": [0..6], "start": "HH:MM", "end": "HH:MM"}],
 "dates": [["YYYY-MM-DD", "YYYY-MM-DD"]], "starts": "", "expires": ""}},
 "assign": {PEER: {"schedule": NAME, "hold": null | {"enabled": bool, "while": bool}}}}
"""
from __future__ import annotations

import json
import os
import re
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

from .vpn import DESC, PROFILE, VpnError

DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
TIME = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$|^24:00$")
MAX_WINDOWS, MAX_DATES = 14, 50


# ---------------------------------------------------------------- parsing (the form's text <-> the stored form)
FULL = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")


def _day(token: str) -> int:
    """'mon', 'Monday', 'thur' -> 0..6: at least three letters of the English day name."""
    t = token.lower()
    for i, full in enumerate(FULL):
        if len(t) >= 3 and full.startswith(t):
            return i
    raise VpnError(f"day {token!r}: use mon tue wed thu fri sat sun")


def _days(text: str) -> list[int]:
    """'mon-fri', 'sat,sun', 'daily' -> sorted day numbers (0 = Monday)."""
    text = text.strip().lower()
    if text in ("daily", "every", "all", "*"):
        return list(range(7))
    out: set[int] = set()
    for part in text.split(","):
        lo, sep, hi = part.strip().partition("-")
        if not lo:
            raise VpnError(f"days {text!r}: e.g. mon-fri or sat,sun")
        a = _day(lo.strip())
        b = _day(hi.strip()) if sep else a
        out.update((a + i) % 7 for i in range((b - a) % 7 + 1))
    return sorted(out)


def _minutes(t: str) -> int:
    return int(t[:2]) * 60 + int(t[3:])


def parse_weekly(text: str) -> list[dict[str, Any]]:
    """One window per line: 'mon-fri 08:00-17:00', 'sat,sun 10:00-14:00', 'daily 22:00-06:00' (overnight),
    'mon-fri' alone = all day. Start = end means all day."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) == 1:
            parts.append("00:00-24:00")
        start, sep, end = parts[1].partition("-") if len(parts) == 2 else ("", "", "")
        if not (sep and TIME.match(start) and TIME.match(end)) or start == "24:00":
            raise VpnError(f"window {line!r}: use DAYS HH:MM-HH:MM, e.g. mon-fri 08:00-17:00")
        out.append({"days": _days(parts[0]), "start": start, "end": end})
    if len(out) > MAX_WINDOWS:
        raise VpnError(f"weekly windows: at most {MAX_WINDOWS}")
    return out


def _date(text: str, what: str) -> str:
    try:
        return date.fromisoformat(text.strip()).isoformat()
    except ValueError:
        raise VpnError(f"{what} {text.strip()!r}: a date like 2026-12-24") from None


def parse_dates(text: str) -> list[list[str]]:
    """Calendar dates, one per line or comma: '2026-12-24' or a range '2026-12-27..2027-01-02'."""
    out = []
    for item in re.split(r"[\n,]", text):
        item = item.strip()
        if not item or item.startswith("#"):
            continue
        lo, sep, hi = item.partition("..")
        a = _date(lo, "date")
        b = _date(hi, "date") if sep else a
        if b < a:
            raise VpnError(f"dates {item!r}: the range ends before it starts")
        out.append([a, b])
    if len(out) > MAX_DATES:
        raise VpnError(f"calendar dates: at most {MAX_DATES} lines")
    return out


def check(name: str, description: str, weekly: str, dates: str, starts: str, expires: str) -> dict[str, Any]:
    """Form fields -> the stored schedule (VpnError names the bad field)."""
    if not PROFILE.match(name):
        raise VpnError("schedule name: 1-16 lowercase letters, digits or dashes, e.g. school-days")
    description = " ".join(description.split())
    if not DESC.match(description):
        raise VpnError("description: up to 160 letters, digits, spaces and , . : ; ( ) / + ' -")
    s = {"description": description, "weekly": parse_weekly(weekly), "dates": parse_dates(dates),
         "starts": _date(starts, "valid from") if starts.strip() else "",
         "expires": _date(expires, "expires") if expires.strip() else ""}
    if s["starts"] and s["expires"] and s["expires"] < s["starts"]:
        raise VpnError("expires is before valid from")
    return s


def _day_text(days: list[int]) -> str:
    if days == list(range(7)):
        return "daily"
    runs, i = [], 0
    while i < len(days):
        j = i
        while j + 1 < len(days) and days[j + 1] == days[j] + 1:
            j += 1
        runs.append(DAYS[days[i]] if i == j else f"{DAYS[days[i]]}-{DAYS[days[j]]}" if j > i + 1
                    else f"{DAYS[days[i]]},{DAYS[days[j]]}")
        i = j + 1
    return ",".join(runs)


def view(name: str, s: dict[str, Any], now: datetime, used: int = 0) -> dict[str, Any]:
    """Stored schedule -> API form: the text, the same as rows for the editor's dropdowns, and whether it is on now."""
    return {"name": name, "description": s.get("description", ""),
            "windows": s.get("weekly", []), "ranges": s.get("dates", []),
            "weekly": "\n".join(f"{_day_text(w['days'])} {w['start']}-{w['end']}" for w in s.get("weekly", [])),
            "dates": "\n".join(a if a == b else f"{a}..{b}" for a, b in s.get("dates", [])),
            "starts": s.get("starts", ""), "expires": s.get("expires", ""), "on": active(s, now), "devices": used}


# ---------------------------------------------------------------- evaluation
def _in_window(w: dict[str, Any], now: datetime) -> bool:
    start, end, t = _minutes(w["start"]), _minutes(w["end"]), now.hour * 60 + now.minute
    today, yesterday = now.weekday(), (now.weekday() - 1) % 7
    if start == end:
        return today in w["days"]
    if start < end:
        return today in w["days"] and start <= t < end
    return (today in w["days"] and t >= start) or (yesterday in w["days"] and t < end)  # overnight


def active(s: dict[str, Any], now: datetime) -> bool:
    d = now.date().isoformat()
    if (s.get("starts") and d < s["starts"]) or (s.get("expires") and d > s["expires"]):
        return False
    weekly, dates = s.get("weekly", []), s.get("dates", [])
    if not weekly and not dates:
        return True
    return any(a <= d <= b for a, b in dates) or any(_in_window(w, now) for w in weekly)


def target(entry: dict[str, Any], s: dict[str, Any], now: datetime) -> bool:
    """Wanted on/off for one assigned device; clears a hold the schedule has moved past (entry is changed)."""
    on = active(s, now)
    hold = entry.get("hold")
    if hold and hold.get("while") == on:
        return bool(hold.get("enabled"))
    entry["hold"] = None
    return on


def next_change(s: dict[str, Any], now: datetime, horizon_days: int = 8) -> datetime | None:
    """First minute within the horizon where the schedule's answer differs from now (for the UI)."""
    t = now.replace(second=0, microsecond=0)
    on = active(s, t)
    for _ in range(horizon_days * 24 * 60):
        t += timedelta(minutes=1)
        if active(s, t) != on:
            return t
    return None


# ---------------------------------------------------------------- storage
def load(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    return {"schedules": dict(data.get("schedules") or {}), "assign": dict(data.get("assign") or {})}


def save(path: Path, data: dict[str, Any]) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1, sort_keys=True)


def now_local() -> datetime:
    return datetime.now().astimezone()

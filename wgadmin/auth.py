"""Who is asking (owner decision 2026-10-26: portal SSO through the proxy + a local admin login on vpn1).

Portal: nginx on the portal host checks the portal session (auth_request, admins only) and sends X-Portal-User,
X-Portal-Role and X-Wgadmin-Secret; those headers count only from a trusted proxy IP with the right secret.
Standalone: local accounts in users.json (scrypt), a session cookie held in memory (a restart signs everyone out).
users.json: {name: {hash, role, groups, schedule, expires, disabled, default}} (access.py: roles, groups, sign-in
hours); the default admin (the first account) is never demoted, disabled, scheduled, given an expiry or deleted.
Optional second factor per account (totp.py, owner 2026-10-27): totp.json {name: {secret, last, recovery}}.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any

from . import totp
from .config import Config

COOKIE = "wgadmin_session"
USER = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")
# stdlib scrypt, the parameters of the portal's app/users.py (owner 2026-10-27: best-practice user + password).
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
FAIL_LIMIT, FAIL_WINDOW_S = 5, 900


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                            maxmem=128 * SCRYPT_R * SCRYPT_N * 2, dklen=32)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


class CodeRequired(Exception):
    """Password right and the account has an authenticator: ask for the code (not counted as a failure)."""


PENDING_S = 600  # an authenticator set-up must be confirmed within 10 minutes


def check_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt, digest = stored.split("$")
        if algo != "scrypt":
            return False
        n, r, p = int(n), int(r), int(p)
        got = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=n, r=r, p=p,
                             maxmem=128 * r * n * 2, dklen=32)
    except ValueError:
        return False
    return hmac.compare_digest(got.hex(), digest)


_DUMMY = hash_password(secrets.token_urlsafe(16))  # unknown names cost as much time as known ones


class Auth:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.sessions: dict[str, tuple[str, float]] = {}
        self.fails: dict[str, list[float]] = {}
        self.pending: dict[str, tuple[str, float]] = {}  # authenticator set-up: name -> (secret, deadline)

    def _totp(self) -> dict[str, dict]:
        try:
            data = json.loads(self.cfg.totp_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return {k: v for k, v in data.items() if isinstance(v, dict) and v.get("secret")} if isinstance(data, dict) else {}

    def accounts(self) -> dict[str, dict[str, Any]]:
        """users.json -> {name: {hash, role, groups, schedule, expires, disabled, default}} (map wg-admin-groups).
        A bare hash (before roles) is an admin; in a file of that old form the first account is the default admin.
        Otherwise none may be marked: a portal-SSO host whose accounts were all made in the web UI (vpn1)."""
        try:
            data = json.loads(self.cfg.users_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        out: dict[str, dict[str, Any]] = {}
        old_form = False
        for name, v in (data.items() if isinstance(data, dict) else ()):
            old_form = old_form or isinstance(v, str)
            v = {"hash": v} if isinstance(v, str) else v
            if not isinstance(v, dict) or not isinstance(v.get("hash"), str):
                continue
            out[name] = {"hash": v["hash"], "role": v.get("role", "admin"), "groups": list(v.get("groups") or []),
                         "schedule": v.get("schedule", ""), "expires": v.get("expires", ""),
                         "disabled": bool(v.get("disabled")), "default": bool(v.get("default")),
                         "history": [h for h in v.get("history") or [] if isinstance(h, str)]}
        if old_form and not any(a["default"] for a in out.values()):
            first = next(iter(out.values()))
            first.update(default=True, role="admin", groups=[], schedule="", expires="", disabled=False)
        return out

    def save_accounts(self, accounts: dict[str, dict[str, Any]]) -> None:
        self._write(self.cfg.users_file, accounts)

    def _users(self) -> dict[str, str]:
        return {k: v["hash"] for k, v in self.accounts().items()}

    def _tokens(self) -> dict[str, str]:
        try:
            data = json.loads(self.cfg.tokens_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return {k: v for k, v in data.items() if isinstance(v, str)} if isinstance(data, dict) else {}

    @staticmethod
    def _write(path: Path, data: dict[str, Any]) -> None:
        # In place: /etc/wg-admin is root's (750), wgadmin owns only its files there, so a temp file + rename fails.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1)

    def set_password(self, name: str, password: str, history: int = 0, **fields: Any) -> None:
        """New password; a new account gets `fields` (role, groups, ...; default: admin, as the CLI makes them).
        Only the CLI's first account (no fields: install.sh) becomes the default admin; one made in the web UI
        never does (owner 2026-10-29: egonn on vpn1 got locked as default and couldn't be demoted).
        history: the last N passwords (the current one included) can't be reused; 0 = no check (the CLI's
        break-glass reset). Ends the account's sessions."""
        if not USER.match(name):
            raise ValueError("name: 1-64 letters, digits, . _ @ -")
        if len(password) < 12:
            raise ValueError("password: at least 12 characters")
        accounts = self.accounts()
        old = accounts.get(name)
        entry = old or {"role": "admin", "groups": [], "schedule": "", "expires": "", "history": [],
                        "disabled": False, **fields, "default": not accounts and not fields}
        if entry["default"]:  # the first account is the default admin, whatever was asked
            entry.update(role="admin", groups=[], schedule="", expires="", disabled=False)
        if old:
            past = [old["hash"], *old["history"]]
            if any(check_password(password, h) for h in past[:history]):
                raise ValueError(f"password: one of the last {history} passwords of this account; choose a new one")
            entry["history"] = past[:49]  # always the setting's max (50 with the current): raising it works at once
        accounts[name] = {**entry, "hash": hash_password(password)}
        self.save_accounts(accounts)
        self.drop_sessions(name)

    def drop_sessions(self, name: str) -> int:
        """End every session of an account (role, groups, password or state changed; deleted)."""
        gone = [t for t, (n, _) in list(self.sessions.items()) if n == name]
        for t in gone:
            self.sessions.pop(t, None)
        return len(gone)

    def new_token(self, name: str) -> str:
        """API token for scripts (map vpn-standalone step 3b): returned once, stored as SHA-256 (random 32 bytes
        need no slow hash). The same name replaces its old token."""
        if not USER.match(name):
            raise ValueError("name: 1-64 letters, digits, . _ @ -")
        token = "wga_" + secrets.token_urlsafe(32)
        tokens = self._tokens()
        tokens[name] = hashlib.sha256(token.encode()).hexdigest()
        self._write(self.cfg.tokens_file, tokens)
        return token

    def revoke_token(self, name: str) -> bool:
        tokens = self._tokens()
        if tokens.pop(name, None) is None:
            return False
        self._write(self.cfg.tokens_file, tokens)
        return True

    def token_user(self, authorization: str) -> str | None:
        """`Authorization: Bearer wga_...` -> "token:NAME" (shown as the user in the audit)."""
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not token.startswith("wga_"):
            return None
        digest = hashlib.sha256(token.strip().encode()).hexdigest()
        for name, stored in self._tokens().items():
            if hmac.compare_digest(digest, stored):
                return f"token:{name}"
        return None

    def _fail(self, ip: str) -> None:
        now = time.time()
        self.fails[ip] = [t for t in self.fails.get(ip, []) if now - t < FAIL_WINDOW_S] + [now]

    def _second_factor(self, name: str, code: str) -> bool:
        """An authenticator code (each time step once) or an unused recovery code (then spent)."""
        all_ = self._totp()
        entry = all_.get(name)
        if not entry:
            return False
        code = code.strip().lower()
        if totp.RECOVERY.match(code):
            digest = totp.hash_code(code)
            left = [h for h in entry.get("recovery", []) if not hmac.compare_digest(h, digest)]
            if len(left) == len(entry.get("recovery", [])):
                return False
            entry["recovery"] = left
        else:
            step = totp.verify(entry["secret"], code, int(entry.get("last", 0)))
            if step is None:
                return False
            entry["last"] = step
        self._write(self.cfg.totp_file, all_)
        return True

    def login(self, name: str, password: str, ip: str, code: str = "") -> str | None:
        """Session token, or None (wrong name/password/code, or too many failures from this IP).
        CodeRequired: password right, the account has an authenticator and no code was given."""
        now = time.time()
        stored = self._users().get(name)
        ok = check_password(password, stored or _DUMMY) and stored is not None
        if self.blocked(ip) or not ok:
            self._fail(ip)
            return None
        if name in self._totp():
            if not code.strip():
                raise CodeRequired
            if not self._second_factor(name, code):
                self._fail(ip)
                return None
        self.fails.pop(ip, None)
        token = secrets.token_urlsafe(32)
        self.sessions[token] = (name, now + self.cfg.session_s)
        return token

    def blocked(self, ip: str) -> bool:
        now = time.time()
        return len([t for t in self.fails.get(ip, []) if now - t < FAIL_WINDOW_S]) >= FAIL_LIMIT

    # ------------------------------------------------------------ authenticator set-up (signed-in local account)
    def totp_status(self, name: str) -> dict[str, Any]:
        entry = self._totp().get(name)
        return {"enabled": bool(entry), "recovery_left": len(entry.get("recovery", [])) if entry else 0}

    def totp_begin(self, name: str) -> str:
        """New secret, held in memory until totp_confirm (an existing authenticator stays until then)."""
        secret = totp.new_secret()
        self.pending[name] = (secret, time.time() + PENDING_S)
        return secret

    def totp_confirm(self, name: str, code: str) -> list[str] | None:
        """The app's first code proves the scan: store the secret, return the recovery codes (shown once)."""
        secret, deadline = self.pending.get(name, ("", 0.0))
        step = totp.verify(secret, code) if secret and deadline > time.time() else None
        if step is None:
            return None
        self.pending.pop(name, None)
        codes = totp.recovery_codes()
        all_ = self._totp()
        all_[name] = {"secret": secret, "last": step, "recovery": [totp.hash_code(c) for c in codes]}
        self._write(self.cfg.totp_file, all_)
        return codes

    def totp_disable(self, name: str, password: str, code: str, ip: str) -> bool:
        """Turn the authenticator off: password and a code again (a stolen session alone cannot)."""
        stored = self._users().get(name)
        if self.blocked(ip) or not stored or not check_password(password, stored) or not self._second_factor(name, code):
            self._fail(ip)
            return False
        return self.totp_reset(name)

    def totp_reset(self, name: str) -> bool:
        """Break-glass (`python3 -m wgadmin totp-reset NAME`) and totp_disable."""
        all_ = self._totp()
        if all_.pop(name, None) is None:
            return False
        self._write(self.cfg.totp_file, all_)
        return True

    def logout(self, token: str) -> None:
        self.sessions.pop(token, None)

    def session_user(self, token: str) -> str | None:
        found = self.sessions.get(token)
        if not found:
            return None
        if found[1] < time.time():
            self.sessions.pop(token, None)
            return None
        return found[0]

    def proxy_user(self, client_ip: str, headers: dict[str, str]) -> str | None:
        """The portal's admin, when the request comes from a trusted proxy with the shared secret."""
        secret = self.cfg.secret()
        given = headers.get("x-wgadmin-secret", "")
        if not secret or client_ip not in self.cfg.trusted_proxies or not hmac.compare_digest(given, secret):
            return None
        user = headers.get("x-portal-user", "")
        if headers.get("x-portal-role") != "admin" or not USER.match(user):
            return None
        return user

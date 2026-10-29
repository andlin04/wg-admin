"""TOTP second factor for local accounts (map vpn-totp-schedules, owner 2026-10-27): RFC 6238 with the standard
library, the defaults Google Authenticator and other apps assume (SHA-1, 30 s, 6 digits)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import struct
import subprocess
import time
import urllib.parse

STEP_S, DIGITS, WINDOW = 30, 6, 1  # WINDOW: steps accepted either side of now (clock drift)
RECOVERY_COUNT = 10
CODE = re.compile(r"^\d{6}$")
RECOVERY = re.compile(r"^[0-9a-f]{4}-[0-9a-f]{4}$")


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode()


def code_at(secret: str, step: int) -> str:
    key = base64.b32decode(secret.upper() + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** DIGITS).zfill(DIGITS)


def verify(secret: str, code: str, last_step: int = 0, now: float | None = None) -> int | None:
    """The matching time step, or None. Steps at or before last_step are refused (a code works once)."""
    code = code.replace(" ", "")
    if not CODE.match(code):
        return None
    current = int((time.time() if now is None else now) // STEP_S)
    for step in range(current - WINDOW, current + WINDOW + 1):
        if step > last_step and hmac.compare_digest(code_at(secret, step), code):
            return step
    return None


def uri(secret: str, user: str, issuer: str) -> str:
    """otpauth:// URI for the authenticator app's QR scan."""
    label = urllib.parse.quote(f"{issuer}:{user}")
    query = urllib.parse.urlencode({"secret": secret, "issuer": issuer, "algorithm": "SHA1",
                                    "digits": DIGITS, "period": STEP_S})
    return f"otpauth://totp/{label}?{query}"


def recovery_codes() -> list[str]:
    return [f"{secrets.token_hex(2)}-{secrets.token_hex(2)}" for _ in range(RECOVERY_COUNT)]


def hash_code(code: str) -> str:
    return hashlib.sha256(code.strip().lower().encode()).hexdigest()


def qr_svg(text: str) -> str:
    """QR code as SVG from qrencode (installed by install.sh); "" when it is missing (the UI shows the secret)."""
    try:
        proc = subprocess.run(["qrencode", "-t", "SVG", "-o", "-"], input=text, capture_output=True, text=True,
                              timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    out = proc.stdout or ""
    return out[out.index("<svg"):] if proc.returncode == 0 and "<svg" in out else ""

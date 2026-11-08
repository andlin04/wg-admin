"""python3 -m wgadmin set-password NAME   (local admin login for standalone use; password asked twice, never echoed;
                                          not a terminal: read from the first line of stdin)
python3 -m wgadmin token NAME [read|admin] [DAYS]
                                         (API token for scripts, printed once: `Authorization: Bearer wga_...`;
                                          default read, 90 days; DAYS 0 = never expires; the same NAME replaces
                                          its old token)
python3 -m wgadmin tokens                (token names, scopes and expiry dates)
python3 -m wgadmin token-revoke NAME
python3 -m wgadmin totp-reset NAME       (break-glass: removes NAME's authenticator; sign in with the password,
                                          then set it up again under Account)"""
from __future__ import annotations

import getpass
import sys
import time

from .auth import TOKEN_DAYS, Auth
from .config import Config


def _usage() -> int:
    print(__doc__.strip(), file=sys.stderr)
    return 2


def main(argv: list[str]) -> int:
    cmd = argv[0] if argv else ""
    if cmd == "tokens" and len(argv) == 1:
        for t in Auth(Config()).tokens():
            when = time.strftime("%Y-%m-%d", time.localtime(t["expires"])) if t["expires"] else "never"
            print(f"{t['name']}\t{t['scope']}\texpires {when}")
        return 0
    if cmd == "token" and 2 <= len(argv) <= 4:
        scope = argv[2] if len(argv) >= 3 else "read"
        days = argv[3] if len(argv) == 4 else str(TOKEN_DAYS)
        if not days.isdigit():
            return _usage()
        try:
            print(Auth(Config()).new_token(argv[1], scope, int(days)))
        except ValueError as exc:
            print(exc, file=sys.stderr)
            return 1
        return 0
    if len(argv) != 2 or cmd not in ("set-password", "token-revoke", "totp-reset"):
        return _usage()
    auth = Auth(Config())
    if cmd == "totp-reset":
        if not auth.totp_reset(argv[1]):
            print(f"{argv[1]} has no authenticator", file=sys.stderr)
            return 1
        print(f"authenticator removed for {argv[1]}")
        return 0
    if cmd == "token-revoke":
        if not auth.revoke_token(argv[1]):
            print(f"no token {argv[1]}", file=sys.stderr)
            return 1
        print(f"token {argv[1]} revoked")
        return 0
    if sys.stdin.isatty():
        pw = getpass.getpass("New password: ")
        if pw != getpass.getpass("Again: "):
            print("passwords differ", file=sys.stderr)
            return 1
    else:  # scripted installs: first line of stdin
        pw = sys.stdin.readline().rstrip("\r\n")
    try:
        auth.set_password(argv[1], pw)
    except ValueError as exc:
        print(exc, file=sys.stderr)
        return 1
    print(f"password set for {argv[1]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

"""python3 -m wgadmin set-password NAME   (local admin login for standalone use; password asked twice, never echoed;
                                          not a terminal: read from the first line of stdin)
python3 -m wgadmin token NAME            (API token for scripts, printed once: `Authorization: Bearer wga_...`;
                                          the same NAME replaces its old token)
python3 -m wgadmin token-revoke NAME
python3 -m wgadmin totp-reset NAME       (break-glass: removes NAME's authenticator; sign in with the password,
                                          then set it up again under Account)"""
from __future__ import annotations

import getpass
import sys

from .auth import Auth
from .config import Config


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] not in ("set-password", "token", "token-revoke", "totp-reset"):
        print(__doc__.strip(), file=sys.stderr)
        return 2
    auth = Auth(Config())
    if argv[0] == "totp-reset":
        if not auth.totp_reset(argv[1]):
            print(f"{argv[1]} has no authenticator", file=sys.stderr)
            return 1
        print(f"authenticator removed for {argv[1]}")
        return 0
    if argv[0] == "token":
        try:
            print(auth.new_token(argv[1]))
        except ValueError as exc:
            print(exc, file=sys.stderr)
            return 1
        return 0
    if argv[0] == "token-revoke":
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

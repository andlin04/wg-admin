"""wg-admin: the WireGuard admin web UI + API on vpn1 (map vpn-standalone, owner go 2026-10-26).

Serves at / on 127.0.0.1:8080 behind nginx on :8443 (TLS); an optional portal can show it under a prefix such as
/vpn/ through its own nginx (prefix stripped).
Every /api route needs a user (auth.py: portal SSO headers or a local session); the static UI does not.
Roles (access.py, map wg-admin-groups): admin routes check admin_of(); device routes check the device's group
against a group admin's groups (scoped_peer) on the server, never in the UI only.
Run: uvicorn --factory wgadmin.web:main_app (systemd unit wg-admin.service).
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import socket
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import access, mail, schedule, totp, vpn
from .auth import COOKIE, USER, Auth, CodeRequired, check_password
from .config import Config
from .events import Events, Sink, portal_sink

STATIC = Path(__file__).parent / "static"
log = logging.getLogger("wg-admin")


class LoginIn(BaseModel):
    name: str = Field(max_length=64)
    password: str = Field(max_length=200)
    code: str = Field("", max_length=20)  # authenticator or recovery code, when the account has one


class CodeIn(BaseModel):
    code: str = Field(max_length=20)


class TotpOffIn(BaseModel):
    password: str = Field(max_length=200)
    code: str = Field(max_length=20)


class ScheduleIn(BaseModel):
    """A schedule profile as the form sends it (schedule.check parses the text fields)."""
    name: str = Field(pattern=vpn.PROFILE.pattern)
    description: str = Field("", max_length=160)
    weekly: str = Field("", max_length=2000)
    dates: str = Field("", max_length=3000)
    starts: str = Field("", max_length=10)
    expires: str = Field("", max_length=10)
    group: str = Field("", max_length=16)  # link a new schedule to this group (a group admin must name one)


class AssignIn(BaseModel):
    schedule: str = Field("", max_length=16)  # "" = no schedule


class GroupSetIn(BaseModel):
    group: str = Field("", max_length=16)  # "" = no group (admins only)


class GroupIn(BaseModel):
    name: str = Field(pattern=vpn.PROFILE.pattern)
    description: str = Field("", max_length=160)
    profiles: list[str] = Field(default_factory=list, max_length=50)
    schedules: list[str] = Field(default_factory=list, max_length=50)


class AccountIn(BaseModel):
    """Role, groups, sign-in schedule, expiry and on/off of a web UI account (access.check_account)."""
    role: str = Field("group-admin", max_length=12)
    groups: list[str] = Field(default_factory=list, max_length=50)
    schedule: str = Field("", max_length=16)
    expires: str = Field("", max_length=10)
    disabled: bool = False


class UserIn(AccountIn):
    name: str = Field(pattern=USER.pattern)
    password: str = Field(min_length=12, max_length=200)


class PasswordIn(BaseModel):
    password: str = Field(min_length=12, max_length=200)


class OwnPasswordIn(BaseModel):
    old: str = Field(max_length=200)
    new: str = Field(min_length=12, max_length=200)


class PolicyIn(BaseModel):
    totp_roles: list[str] = Field(default_factory=list, max_length=2)
    pw_history: int | None = Field(None, ge=0, le=50)  # None: unchanged


@dataclass(frozen=True)
class Who:
    """The signed-in user: portal SSO and API tokens are admins; local accounts carry their role and groups."""
    name: str
    via: str  # portal | local | token
    role: str = "admin"
    groups: tuple[str, ...] = ()

    @property
    def admin(self) -> bool:
        return self.role == "admin"


class PeerIn(BaseModel):
    name: str = Field(pattern=vpn.NAME.pattern)
    profile: str = Field("split", pattern=vpn.PROFILE.pattern)
    tags: list[str] = Field(default_factory=list, max_length=8)
    email: str = Field("", max_length=254)
    group: str = Field("", max_length=16)  # a group admin must name one of theirs


class EmailIn(BaseModel):
    email: str = Field("", max_length=254)


class EnabledIn(BaseModel):
    enabled: bool


class BulkIn(BaseModel):
    """CSV lines name[,profile[,tags]] (vpn.parse_bulk)."""
    lines: str = Field(min_length=1, max_length=10000)


class ProfileIn(BaseModel):
    profile: str = Field(pattern=vpn.PROFILE.pattern)


class TagsIn(BaseModel):
    tags: list[str] = Field(default_factory=list, max_length=8)


class ProfileDefIn(BaseModel):
    """A profile: client routes and DNS (comma- or space-separated; vpn.profile_request checks them)."""
    name: str = Field(pattern=vpn.PROFILE.pattern)
    routes: str = Field(min_length=1, max_length=1000)
    dns: str = Field("", max_length=300)
    description: str = Field("", max_length=160)
    ipv6: bool = False
    allow: str = Field("", max_length=1000)  # allowed destinations, vpn.allow_rules; "" = all routes


class ServerIn(BaseModel):
    """Editable server settings (vpn.server_request checks them)."""
    endpoint: str = Field(min_length=3, max_length=300)
    listen_port: int
    keepalive: int


class RebootIn(BaseModel):
    """The host name the confirm dialog showed: a tab open on another server can't reboot this one."""
    host: str = Field(max_length=253)


class NetworkIn(BaseModel):
    """Server > Network (vpn.network_request checks it)."""
    mode: str = Field(max_length=5)
    in_if: str = Field(max_length=15)
    out_if: str = Field("", max_length=15)
    gateway: str = Field("", max_length=15)


class MailIn(BaseModel):
    """SMTP settings (mail.check); password None = keep the stored one, "" = clear it."""
    from_addr: str = Field(max_length=254)
    host: str = Field(max_length=253)
    port: int = 25
    security: str = "none"
    user: str = Field("", max_length=200)
    password: str | None = Field(None, max_length=500)


class MailTestIn(BaseModel):
    to: str = Field(max_length=254)


class NoticeIn(BaseModel):
    names: list[str] = Field(min_length=1, max_length=200)
    kind: str = Field("changed", pattern="^(changed|ready)$")


def create_app(cfg: Config | None = None, runner: vpn.Runner | None = None, sink: Sink | None = None,
               load_text: str | None = None, sender: mail.Sender | None = None,
               clock: Callable[[], datetime] | None = None) -> FastAPI:
    """runner/sink/load_text/sender/clock: test hooks (fake gate, captured events, fixed load line, captured mail,
    the schedules' local time)."""
    cfg = cfg or Config()
    send = sender or mail.smtp_send
    now_local = clock or schedule.now_local
    auth = Auth(cfg)
    audit = Events(sink if sink is not None else portal_sink(cfg) if cfg.event_url else None)
    sched_lock = threading.Lock()  # the 60 s check runs in a worker thread; the API edits the same file
    edit_lock = threading.Lock()  # users.json and access.json: read, change, write as one step

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI):
        async def loop() -> None:
            while True:
                await run_in_threadpool(safe_tick)
                await asyncio.sleep(cfg.schedule_s)
        task = asyncio.create_task(loop()) if cfg.schedule_s > 0 else None
        yield
        if task:
            task.cancel()

    app = FastAPI(title="wg-admin", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

    @app.middleware("http")
    async def same_origin_writes(request: Request, call_next):
        # Local sessions ride on a cookie: changes only from wg-admin's own pages (Sec-Fetch-Site), as in the portal.
        site = request.headers.get("sec-fetch-site")
        if request.method not in ("GET", "HEAD", "OPTIONS") and site and site not in ("same-origin", "none"):
            return JSONResponse({"detail": "cross-site request refused"}, status_code=403)
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        return response

    def client_ip(request: Request) -> str:
        return request.client.host if request.client else ""

    def acl() -> dict[str, Any]:
        return access.load(cfg.access_file)

    def must_enrol(name: str, role: str) -> bool:
        """The role needs an authenticator (Users > policy) and this account has none yet."""
        return role in acl()["totp_roles"] and not auth.totp_status(name)["enabled"]

    def who(request: Request) -> Who:
        """The user, else 401. A local session is checked on every request: a deleted, disabled or expired account,
        or one outside its sign-in hours, is signed out at once."""
        user = auth.proxy_user(client_ip(request), {k.lower(): v for k, v in request.headers.items()})
        if user:
            return Who(user, "portal")
        cookie = request.cookies.get(COOKIE, "")
        user = auth.session_user(cookie)
        if user:
            acct = auth.accounts().get(user)
            why = access.refused(acct, schedule.load(cfg.schedules_file)["schedules"], now_local()) if acct else "account deleted"
            if why:
                auth.logout(cookie)
                raise HTTPException(401, f"signed out: {why}")
            if must_enrol(user, acct["role"]) and not request.url.path.startswith(("/api/me", "/api/account/")):
                raise HTTPException(403, "your role needs two-step sign-in: Account > Set up authenticator first")
            return Who(user, "local", acct["role"], tuple(acct["groups"]))
        user = auth.token_user(request.headers.get("authorization", ""))
        if user:
            return Who(user, "token")
        raise HTTPException(401, "sign in required")

    def admin_of(request: Request) -> str:
        """Admin-only routes: server, network, firewall, mail settings, profiles, groups, users, bulk add."""
        w = who(request)
        if not w.admin:
            raise HTTPException(403, "admins only")
        return w.name

    def scoped_peer(request: Request, name: str) -> tuple[Who, dict[str, Any], dict[str, Any]]:
        """(user, device, access data): a group admin sees only devices in their groups (others: 404)."""
        w, data = who(request), acl()
        if not w.admin and data["members"].get(name) not in w.groups:
            raise HTTPException(404, f"no VPN peer {name!r}")
        return w, peer(name), data

    def sign_in_schedules() -> set[str]:
        return {a["schedule"] for a in auth.accounts().values() if a["schedule"]}

    def schedule_locked(w: Who, data: dict[str, Any], name: str, sign_ins: set[str]) -> str:
        """Why this user may not edit or delete a schedule ("" = may). A group admin edits only schedules linked
        to their own groups alone, and never one that sets an account's sign-in hours."""
        if w.admin:
            return ""
        linked = access.schedule_groups(data, name)
        if not linked or not linked <= set(w.groups):
            return f"schedule {name} is shared with other groups: an admin edits it"
        if name in sign_ins:
            return f"schedule {name} sets sign-in hours: an admin edits it"
        return ""

    def do(fn: Callable[..., Any], *args: Any) -> Any:
        try:
            return fn(cfg, *args, runner)
        except vpn.VpnError as exc:
            raise HTTPException(502, str(exc)) from None

    # ---------------------------------------------------------------- sign-in (standalone use)
    @app.get("/api/me")
    def me(request: Request) -> dict[str, Any]:
        w = who(request)
        return {"user": w.name, "via": w.via, "host": socket.gethostname(), "role": w.role, "groups": list(w.groups),
                "must_enrol": w.via == "local" and must_enrol(w.name, w.role)}

    @app.post("/api/login")
    def login(request: Request, body: LoginIn) -> JSONResponse:
        ip = client_ip(request)
        if auth.blocked(ip):
            raise HTTPException(429, "too many failed sign-ins: wait 15 minutes")
        try:
            token = auth.login(body.name, body.password, ip, body.code)
        except CodeRequired:
            return JSONResponse({"code_required": True})  # no cookie: the page asks for the code, sends all again
        if token is None:
            audit(body.name if len(body.name) < 65 else "?", "login", "", False, f"failed sign-in from {ip}")
            raise HTTPException(401, "wrong name, password or code" if body.code else "wrong name or password")
        acct = auth.accounts().get(body.name)
        why = access.refused(acct, schedule.load(cfg.schedules_file)["schedules"], now_local()) if acct else "no account"
        if why:  # password right: the reason may be told
            auth.logout(token)
            audit(body.name, "login", "", False, f"sign-in from {ip} refused: {why}")
            raise HTTPException(403, f"sign-in refused: {why}")
        audit(body.name, "login", "", True, f"signed in from {ip}", f"VPN: {body.name} signed in to wg-admin on {socket.gethostname()}")
        resp = JSONResponse({"user": body.name, "via": "local"})
        resp.set_cookie(COOKIE, token, max_age=cfg.session_s, secure=True, httponly=True, samesite="strict")
        return resp

    @app.post("/api/logout")
    def logout(request: Request) -> JSONResponse:
        auth.logout(request.cookies.get(COOKIE, ""))
        resp = JSONResponse({"ok": True})
        resp.delete_cookie(COOKIE, secure=True, httponly=True, samesite="strict")
        return resp

    # ---------------------------------------------------------------- authenticator (local accounts only)
    def local_user(request: Request) -> str:
        w = who(request)
        if w.via != "local":
            raise HTTPException(403, "only for wg-admin's own accounts (signed in on this page)")
        return w.name

    def new_password(name: str, password: str) -> None:
        """Own change or admin reset: the policy's password history applies to both (422 on a reuse)."""
        with edit_lock:
            try:
                auth.set_password(name, password, history=acl()["pw_history"])
            except ValueError as exc:
                raise HTTPException(422, str(exc)) from None

    @app.post("/api/account/password")
    def own_password(request: Request, body: OwnPasswordIn) -> JSONResponse:
        """Change your own password: the old one again; every session of the account ends (sign in again)."""
        user, ip = local_user(request), client_ip(request)
        if auth.blocked(ip):
            raise HTTPException(429, "too many failed attempts: wait 15 minutes")
        acct = auth.accounts().get(user)
        if not acct or not check_password(body.old, acct["hash"]):
            auth._fail(ip, user)
            audit(user, "password", user, False, f"wrong old password from {ip}")
            raise HTTPException(422, "wrong current password")
        new_password(user, body.new)
        audit(user, "password", user, True, "own password changed", f"VPN: {user} changed their wg-admin password")
        resp = JSONResponse({"ok": True})
        resp.delete_cookie(COOKIE, secure=True, httponly=True, samesite="strict")
        return resp

    @app.get("/api/account/totp")
    def totp_get(request: Request) -> dict[str, Any]:
        return auth.totp_status(local_user(request))

    @app.post("/api/account/totp/setup")
    def totp_setup(request: Request) -> dict[str, str]:
        """New secret + QR for the app; nothing changes until /confirm gets a code from it."""
        user = local_user(request)
        secret = auth.totp_begin(user)
        link = totp.uri(secret, user, f"wg-admin {socket.gethostname()}")
        return {"secret": secret, "uri": link, "qr": totp.qr_svg(link)}

    @app.post("/api/account/totp/confirm")
    def totp_confirm(request: Request, body: CodeIn) -> dict[str, Any]:
        user = local_user(request)
        codes = auth.totp_confirm(user, body.code)
        if codes is None:
            raise HTTPException(422, "code not accepted: check the phone's clock, or start the set-up again")
        audit(user, "totp-on", "", True, "authenticator set up", f"VPN: {user} set up an authenticator for wg-admin")
        return {"recovery": codes, **auth.totp_status(user)}

    @app.post("/api/account/totp/disable")
    def totp_disable(request: Request, body: TotpOffIn) -> dict[str, Any]:
        user, ip = local_user(request), client_ip(request)
        if auth.blocked(ip):
            raise HTTPException(429, "too many failed attempts: wait 15 minutes")
        if not auth.totp_disable(user, body.password, body.code, ip):
            audit(user, "totp-off", "", False, f"wrong password or code from {ip}")
            raise HTTPException(422, "wrong password or code")
        audit(user, "totp-off", "", True, "authenticator removed", f"VPN: {user} removed the wg-admin authenticator",
              f":warning: VPN: {user} removed the authenticator from their wg-admin account")
        return auth.totp_status(user)

    # ---------------------------------------------------------------- peers and profiles
    def peer(name: str) -> dict[str, Any]:
        found = next((p for p in do(vpn.peers) if p["name"] == name), None)
        if found is None:
            raise HTTPException(404, f"no VPN peer {name!r}")
        return found

    def profile(name: str) -> dict[str, Any] | None:
        return next((p for p in do(vpn.profiles) if p["name"] == name), None)

    @app.get("/api/state")
    def state(request: Request) -> dict[str, Any]:
        """Devices, profiles, schedules and groups; a group admin gets only their groups' devices and the profiles
        and schedules linked to those groups."""
        w = who(request)
        try:
            peers = vpn.peers(cfg, runner)
        except vpn.VpnError as exc:
            raise HTTPException(503, str(exc)) from None
        data, acc = schedule.load(cfg.schedules_file), acl()
        for p in peers:
            entry = data["assign"].get(p["name"]) or {}
            p["schedule"], p["hold"] = entry.get("schedule", ""), bool(entry.get("hold"))
            p["group"] = acc["members"].get(p["name"], "")
        profiles, view = do(vpn.profiles), schedules_view(data, w, acc)
        groups = {g: v for g, v in acc["groups"].items() if w.admin or g in w.groups}
        if not w.admin:
            peers = [p for p in peers if p["group"] in w.groups]
            linked = {x for v in groups.values() for x in v["profiles"]}
            profiles = [p for p in profiles if p["name"] in linked]
        return {"peers": peers, "profiles": profiles, **view, "role": w.role,
                "groups": [{"name": g, **v} for g, v in sorted(groups.items())]}

    def health() -> dict[str, Any]:
        return vpn.health(cfg, runner, load_text=load_text)

    @app.get("/api/health")
    def health_get(request: Request) -> dict[str, Any]:
        admin_of(request)
        return health()

    @app.post("/api/health/run")
    def health_run(request: Request) -> dict[str, Any]:
        """Run checks button: the same checks, the outcome audited; a bad node also lands in the journal."""
        user = admin_of(request)
        out = health()
        bad = [n for n in out["nodes"] if n["status"] == "bad"]
        summary = "; ".join(f"{n['label']}: {n['status']} ({n['line']})" for n in out["nodes"])
        audit(user, "health", "", not bad, summary,
              ("VPN health check by " + user + ": " + "; ".join(f"{n['label']} {n['line']}" for n in bad)) if bad else "")
        return out

    @app.get("/api/server")
    def server_get(request: Request) -> dict[str, Any]:
        admin_of(request)
        return {"settings": do(vpn.server)}

    @app.put("/api/server")
    def server_put(request: Request, body: ServerIn) -> dict[str, Any]:
        """Endpoint/keepalive rewrite every client config (devices re-import); the listen port needs the router's
        port forward to follow."""
        user = admin_of(request)
        try:
            vpn.server_request(body.endpoint, body.listen_port, body.keepalive)
        except vpn.VpnError as exc:
            raise HTTPException(422, str(exc)) from None
        out = do(vpn.save_server, body.endpoint, body.listen_port, body.keepalive)
        audit(user, "server-set", "", True, out, f"VPN: server settings changed by {user}: {out}",
              f":key: VPN server settings changed by {user}: {out}")
        return {"output": out, "settings": do(vpn.server)}

    @app.get("/api/network")
    def network_get(request: Request) -> dict[str, Any]:
        admin_of(request)
        return do(vpn.network)

    @app.put("/api/network")
    def network_put(request: Request, body: NetworkIn) -> dict[str, Any]:
        """NAT or routed IPv4, incoming and transit interface; applied at once (firewall + policy routing)."""
        user = admin_of(request)
        try:
            vpn.network_request(body.mode, body.in_if, body.out_if, body.gateway)
        except vpn.VpnError as exc:
            raise HTTPException(422, str(exc)) from None
        out = do(vpn.save_network, body.mode, body.in_if, body.out_if, body.gateway)
        audit(user, "network-set", "", True, out, f"VPN: network changed by {user}: {out}",
              f":key: VPN network changed by {user}: {out}")
        return {"output": out, **do(vpn.network)}

    def connected() -> list[str]:
        now = datetime.now().timestamp()
        return [p["name"] for p in do(vpn.peers)
                if p["enabled"] and p["handshake"] and now - p["handshake"] < vpn.HANDSHAKE_FRESH_S]

    @app.get("/api/server/reboot")
    def reboot_get(request: Request) -> dict[str, Any]:
        """What the confirm dialog names: this host and the devices a reboot disconnects."""
        admin_of(request)
        return {"host": socket.gethostname(), "connected": connected()}

    @app.post("/api/server/reboot")
    def reboot_post(request: Request, body: RebootIn) -> dict[str, Any]:
        user, host = admin_of(request), socket.gethostname()
        if body.host != host:
            raise HTTPException(409, f"this server is {host}, not {body.host}: reload the page")
        conn = connected()
        out = do(vpn.reboot)
        line = f"VPN: {host} rebooted by {user} ({len(conn)} devices connected: {', '.join(conn) or 'none'})"
        audit(user, "reboot", host, True, out, line, f":arrows_counterclockwise: {line}")
        return {"output": out, "connected": conn}

    @app.get("/api/server/ruleset")
    def server_ruleset(request: Request) -> dict[str, str]:
        admin_of(request)
        return {"text": do(vpn.ruleset)}

    def save_profile(user: str, body: ProfileDefIn, verb: str) -> dict[str, Any]:
        try:
            vpn.profile_request(body.name, body.routes, body.dns, body.description, body.ipv6, body.allow)
        except vpn.VpnError as exc:
            raise HTTPException(422, str(exc)) from None
        out = do(lambda c, r: vpn.save_profile(c, body.name, body.routes, body.dns, body.description, r, body.ipv6,
                                               body.allow))
        audit(user, f"profile-{verb}", body.name, True, out, f"VPN: profile {body.name} {verb} by {user}: {out}",
              f":key: VPN profile {body.name} {verb} by {user}: {out}")
        return {"output": out, "profile": profile(body.name)}

    @app.post("/api/profiles")
    def profile_add(request: Request, body: ProfileDefIn) -> dict[str, Any]:
        user = admin_of(request)
        if profile(body.name):
            raise HTTPException(409, f"profile {body.name!r} exists: edit it instead")
        return save_profile(user, body, "added")

    @app.put("/api/profiles/{name}")
    def profile_edit(request: Request, name: str, body: ProfileDefIn) -> dict[str, Any]:
        user = admin_of(request)
        if body.name != name:
            raise HTTPException(400, "renaming a profile is not supported: add a new one")
        if not profile(name):
            raise HTTPException(404, f"no VPN profile {name!r}")
        return save_profile(user, body, "changed")

    @app.delete("/api/profiles/{name}")
    def profile_delete(request: Request, name: str, confirm: str = "") -> dict[str, Any]:
        user = admin_of(request)
        if confirm.strip() != name:
            raise HTTPException(400, f'type the profile name "{name}" to confirm')
        prof = profile(name)
        if prof is None:
            raise HTTPException(404, f"no VPN profile {name!r}")
        if prof["peers"]:
            raise HTTPException(409, f"profile {name} is used by {prof['peers']} peer(s): move them first")
        out = do(vpn.delete_profile, name)
        with edit_lock:
            acc = acl()
            access.unlink(acc, "profiles", name)
            access.save(cfg.access_file, acc)
        audit(user, "profile-delete", name, True, out, f"VPN: profile {name} deleted by {user}",
              f":key: VPN profile {name} deleted by {user}")
        return {"output": out}

    @app.post("/api/peers")
    def peer_add(request: Request, body: PeerIn) -> dict[str, Any]:
        """A group admin adds devices only into one of their groups, with a profile linked to that group."""
        w, acc = who(request), acl()
        user = w.name
        if body.group and body.group not in acc["groups"]:
            raise HTTPException(404, f"no group {body.group!r}")
        if not w.admin and body.group not in w.groups:
            raise HTTPException(403, "pick one of your groups for the device")
        if not w.admin and body.profile not in acc["groups"][body.group]["profiles"]:
            raise HTTPException(403, f"profile {body.profile} is not linked to group {body.group}")
        try:
            vpn.check_tags(body.tags)
            if body.email:
                vpn.check_email(body.email)
        except vpn.VpnError as exc:
            raise HTTPException(422, str(exc)) from None
        try:
            out = vpn.add(cfg, body.name, body.profile, runner)
            if body.tags:
                out += "; " + vpn.set_tags(cfg, body.name, body.tags, runner)
            if body.email:
                out += "; " + vpn.set_email(cfg, body.name, body.email, runner)
        except vpn.VpnError as exc:
            audit(user, "add", body.name, False, str(exc))
            raise HTTPException(502, str(exc)) from None
        if body.group:
            with edit_lock:
                acc = acl()
                acc["members"][body.name] = body.group
                access.save(cfg.access_file, acc)
            out += f"; group {body.group}"
        audit(user, "add", body.name, True, out, f"VPN: peer {body.name} (profile {body.profile}) added by {user}",
              f":key: VPN peer {body.name} (profile {body.profile}) added by {user}")
        return {"output": out, "peer": peer(body.name)}

    @app.post("/api/peers/bulk")
    def peer_bulk(request: Request, body: BulkIn) -> dict[str, Any]:
        """All lines checked first; then created in order, stopping at the first failure. One audit event."""
        user = admin_of(request)
        try:
            rows = vpn.parse_bulk(body.lines, {p["name"] for p in do(vpn.profiles)}, {p["name"] for p in do(vpn.peers)})
        except vpn.VpnError as exc:
            raise HTTPException(422, str(exc)) from None
        created, error = [], ""
        for name, prof, tags, email in rows:
            try:
                vpn.add(cfg, name, prof, runner)
                if tags:
                    vpn.set_tags(cfg, name, tags, runner)
                if email:
                    vpn.set_email(cfg, name, email, runner)
            except vpn.VpnError as exc:
                error = f"{name}: {exc}"
                break
            created.append(name)
        summary = f"{len(created)} of {len(rows)} added: {', '.join(created) or '-'}" + (f"; stopped at {error}" if error else "")
        audit(user, "bulk-add", "", not error, summary, f"VPN: bulk add by {user}: {summary}",
              f":key: VPN bulk add by {user}: {summary}")
        return {"created": created, "error": error}

    @app.post("/api/peers/{name}/profile")
    def peer_profile(request: Request, name: str, body: ProfileIn) -> dict[str, Any]:
        w, _, acc = scoped_peer(request, name)
        user = w.name
        if not w.admin and body.profile not in acc["groups"][acc["members"][name]]["profiles"]:
            raise HTTPException(403, f"profile {body.profile} is not linked to group {acc['members'][name]}")
        out = do(vpn.set_profile, name, body.profile)
        audit(user, "profile", name, True, out, f"VPN: peer {name} switched to profile {body.profile} by {user}")
        return {"output": out, "peer": peer(name)}

    @app.post("/api/peers/{name}/group")
    def peer_group(request: Request, name: str, body: GroupSetIn) -> dict[str, Any]:
        """Move a device to a group ("" = none, admins only); a group admin moves only between their own groups."""
        w, _, acc = scoped_peer(request, name)
        if body.group and body.group not in acc["groups"]:
            raise HTTPException(404, f"no group {body.group!r}")
        if not w.admin and body.group not in w.groups:
            raise HTTPException(403, "group admins move devices only between their own groups")
        with edit_lock:
            acc = acl()
            if body.group:
                acc["members"][name] = body.group
            else:
                acc["members"].pop(name, None)
            access.save(cfg.access_file, acc)
        out = f"group {body.group or 'none'}"
        audit(w.name, "group-set", name, True, out, f"VPN: {name} moved to group {body.group or 'none'} by {w.name}")
        return {"output": out, "peer": peer(name)}

    @app.post("/api/peers/{name}/tags")
    def peer_tags(request: Request, name: str, body: TagsIn) -> dict[str, Any]:
        user = scoped_peer(request, name)[0].name
        try:
            vpn.check_tags(body.tags)
        except vpn.VpnError as exc:
            raise HTTPException(422, str(exc)) from None
        out = do(vpn.set_tags, name, body.tags)
        audit(user, "tags", name, True, out, f"VPN: peer {name} tagged {', '.join(body.tags) or '(none)'} by {user}")
        return {"output": out, "peer": peer(name)}

    @app.post("/api/peers/{name}/email")
    def peer_email(request: Request, name: str, body: EmailIn) -> dict[str, Any]:
        user = scoped_peer(request, name)[0].name
        try:
            vpn.check_email(body.email)
        except vpn.VpnError as exc:
            raise HTTPException(422, str(exc)) from None
        out = do(vpn.set_email, name, body.email)
        audit(user, "email", name, True, out, f"VPN: owner email of {name} set by {user}")
        return {"output": out, "peer": peer(name)}

    @app.post("/api/peers/{name}/enabled")
    def peer_enabled(request: Request, name: str, body: EnabledIn) -> dict[str, Any]:
        """VPN access on/off without touching the setup (owner 2026-10-27); takes effect at once."""
        user = scoped_peer(request, name)[0].name
        out = do(vpn.set_enabled, name, body.enabled)
        with sched_lock:  # scheduled device: the click holds until the schedule's next change
            data = schedule.load(cfg.schedules_file)
            entry = data["assign"].get(name)
            s = data["schedules"].get(entry["schedule"]) if entry else None
            if s is not None:
                entry["hold"] = {"enabled": body.enabled, "while": schedule.active(s, now_local())}
                schedule.save(cfg.schedules_file, data)
                out += f"; holds until schedule {entry['schedule']} changes"
        verb = "enabled" if body.enabled else "disabled"
        audit(user, "enable" if body.enabled else "disable", name, True, out, f"VPN: peer {name} {verb} by {user}",
              f":{'white_check_mark' if body.enabled else 'pause_button'}: VPN peer {name} {verb} by {user}")
        return {"output": out, "peer": peer(name)}

    @app.delete("/api/peers/{name}")
    def peer_remove(request: Request, name: str, confirm: str = "") -> dict[str, Any]:
        user = scoped_peer(request, name)[0].name
        if confirm.strip() != name:
            raise HTTPException(400, f'type the peer name "{name}" to confirm')
        out = do(vpn.remove, name)
        with sched_lock:
            data = schedule.load(cfg.schedules_file)
            if data["assign"].pop(name, None) is not None:
                schedule.save(cfg.schedules_file, data)
        with edit_lock:
            acc = acl()
            if acc["members"].pop(name, None) is not None:
                access.save(cfg.access_file, acc)
        audit(user, "remove", name, True, out, f"VPN: peer {name} revoked by {user}",
              f":no_entry: VPN peer {name} revoked by {user}")
        return {"output": out}

    # ---------------------------------------------------------------- access schedules (map vpn-totp-schedules)
    def schedules_view(data: dict[str, Any], w: Who, acc: dict[str, Any]) -> dict[str, Any]:
        """Schedules this user sees (group admin: those linked to their groups), each with `locked`: why the user
        may not edit it ("" = may) and `groups`: the groups it is linked to."""
        now, sign_ins = now_local(), sign_in_schedules()
        mine = {x for g in w.groups for x in acc["groups"].get(g, {}).get("schedules", [])}
        used: dict[str, int] = {}
        for entry in data["assign"].values():
            used[entry.get("schedule", "")] = used.get(entry.get("schedule", ""), 0) + 1
        views = []
        for name, s in sorted(data["schedules"].items()):
            if not w.admin and name not in mine:
                continue
            v = schedule.view(name, s, now, used.get(name, 0))
            nxt = schedule.next_change(s, now)
            v["next"] = nxt.isoformat(timespec="minutes") if nxt else ""
            v["groups"] = sorted(access.schedule_groups(acc, name))
            v["sign_in"] = name in sign_ins
            v["locked"] = schedule_locked(w, acc, name, sign_ins)
            views.append(v)
        return {"schedules": views, "now": now.isoformat(timespec="minutes"), "tz": now.tzname() or ""}

    def tick() -> list[str]:
        """Switch every scheduled device to what its schedule (or hold) wants; one audit event per switch."""
        with sched_lock:
            data = schedule.load(cfg.schedules_file)
            if not data["assign"]:
                return []
            before = json.dumps(data, sort_keys=True)
            current = {p["name"]: p for p in vpn.peers(cfg, runner)}
            now, switched = now_local(), []
            for name, entry in list(data["assign"].items()):
                s = data["schedules"].get(entry.get("schedule", ""))
                if name not in current:
                    del data["assign"][name]  # revoked outside wg-admin
                    continue
                if s is None:
                    continue
                want = schedule.target(entry, s, now)
                if current[name]["enabled"] == want:
                    continue
                verb = "on" if want else "off"
                try:
                    out = vpn.set_enabled(cfg, name, want, runner)
                except vpn.VpnError as exc:
                    line = f"VPN: schedule {entry['schedule']} could not switch {name} {verb}: {exc}"
                    audit("schedule", "schedule-" + verb, name, False, str(exc), line, f":warning: {line}")
                    continue
                switched.append(f"{name} {verb}")
                line = f"VPN: {name} switched {verb} by schedule {entry['schedule']}"
                audit("schedule", "schedule-" + verb, name, True, out, line,  # Slack too (owner 2026-10-27)
                      f":{'white_check_mark' if want else 'pause_button'}: {line}")
            if json.dumps(data, sort_keys=True) != before:
                schedule.save(cfg.schedules_file, data)
            return switched

    def safe_tick() -> None:
        try:
            tick()
        except Exception as exc:  # a gate or file error must not stop the loop; the next minute retries
            log.warning("schedule check failed: %s: %s", type(exc).__name__, exc)

    app.state.schedule_tick = tick  # tests drive it with a fake clock

    @app.get("/api/schedules")
    def schedules_get(request: Request) -> dict[str, Any]:
        return schedules_view(schedule.load(cfg.schedules_file), who(request), acl())

    def save_schedule(w: Who, body: ScheduleIn, verb: str, exists: bool) -> dict[str, Any]:
        """Admins: any schedule. Group admins: new ones are linked to one of their groups; edits only of their own
        (schedule_locked)."""
        user, acc = w.name, acl()
        if not exists and body.group and body.group not in acc["groups"]:
            raise HTTPException(404, f"no group {body.group!r}")
        if not exists and not w.admin and body.group not in w.groups:
            raise HTTPException(403, "pick one of your groups for the new schedule")
        if exists and (why := schedule_locked(w, acc, body.name, sign_in_schedules())):
            raise HTTPException(403, why)
        try:
            s = schedule.check(body.name, body.description, body.weekly, body.dates, body.starts, body.expires)
        except vpn.VpnError as exc:
            raise HTTPException(422, str(exc)) from None
        with sched_lock:
            data = schedule.load(cfg.schedules_file)
            if (body.name in data["schedules"]) != exists:
                raise HTTPException(409 if not exists else 404,
                                    f"schedule {body.name!r} exists: edit it instead" if not exists
                                    else f"no schedule {body.name!r}")
            data["schedules"][body.name] = s
            schedule.save(cfg.schedules_file, data)
        if not exists and body.group:
            with edit_lock:
                acc = acl()
                acc["groups"][body.group]["schedules"] = sorted({*acc["groups"][body.group]["schedules"], body.name})
                access.save(cfg.access_file, acc)
        v = schedule.view(body.name, s, now_local())
        summary = "; ".join(x for x in (v["weekly"].replace("\n", ", "), v["dates"].replace("\n", ", "),
                                         f"from {v['starts']}" if v["starts"] else "",
                                         f"expires {v['expires']}" if v["expires"] else "") if x) or "always on"
        audit(user, f"schedule-{verb}", body.name, True, summary, f"VPN: schedule {body.name} {verb} by {user}: {summary}")
        try:
            switched = tick()
        except vpn.VpnError as exc:  # saved; the 60 s loop applies it when the gate answers again
            switched = [f"not yet ({exc})"]
        return {"output": summary + (f"; switched {', '.join(switched)}" if switched else ""), "schedule": v}

    @app.post("/api/schedules")
    def schedule_add(request: Request, body: ScheduleIn) -> dict[str, Any]:
        return save_schedule(who(request), body, "added", exists=False)

    @app.put("/api/schedules/{name}")
    def schedule_edit(request: Request, name: str, body: ScheduleIn) -> dict[str, Any]:
        w = who(request)
        if body.name != name:
            raise HTTPException(400, "renaming a schedule is not supported: add a new one")
        return save_schedule(w, body, "changed", exists=True)

    @app.delete("/api/schedules/{name}")
    def schedule_delete(request: Request, name: str, confirm: str = "") -> dict[str, str]:
        w = who(request)
        user, sign_ins = w.name, sign_in_schedules()
        if confirm.strip() != name:
            raise HTTPException(400, f'type the schedule name "{name}" to confirm')
        if why := schedule_locked(w, acl(), name, sign_ins):
            raise HTTPException(403, why)
        if name in sign_ins:
            raise HTTPException(409, f"schedule {name} sets an account's sign-in hours (Users): change that first")
        with sched_lock:
            data = schedule.load(cfg.schedules_file)
            if name not in data["schedules"]:
                raise HTTPException(404, f"no schedule {name!r}")
            users = [p for p, e in data["assign"].items() if e.get("schedule") == name]
            if users:
                raise HTTPException(409, f"schedule {name} is used by {', '.join(users)}: set them to another first")
            del data["schedules"][name]
            schedule.save(cfg.schedules_file, data)
        with edit_lock:
            acc = acl()
            access.unlink(acc, "schedules", name)
            access.save(cfg.access_file, acc)
        audit(user, "schedule-delete", name, True, "deleted", f"VPN: schedule {name} deleted by {user}")
        return {"output": f"schedule {name} deleted"}

    @app.post("/api/peers/{name}/schedule")
    def peer_schedule(request: Request, name: str, body: AssignIn) -> dict[str, Any]:
        """Assign a schedule ("" = none: the device keeps its current on/off). Applied at once. A group admin picks
        from the schedules linked to the device's group."""
        w, _, acc = scoped_peer(request, name)
        user = w.name
        if body.schedule and not w.admin and body.schedule not in acc["groups"][acc["members"][name]]["schedules"]:
            raise HTTPException(403, f"schedule {body.schedule} is not linked to group {acc['members'][name]}")
        with sched_lock:
            data = schedule.load(cfg.schedules_file)
            if body.schedule and body.schedule not in data["schedules"]:
                raise HTTPException(404, f"no schedule {body.schedule!r}")
            if body.schedule:
                data["assign"][name] = {"schedule": body.schedule, "hold": None}
            else:
                data["assign"].pop(name, None)
            schedule.save(cfg.schedules_file, data)
        try:
            switched = tick()
        except vpn.VpnError as exc:
            raise HTTPException(502, str(exc)) from None
        out = f"schedule {body.schedule or 'none'}" + (f"; switched {', '.join(switched)}" if switched else "")
        audit(user, "schedule-set", name, True, out, f"VPN: {name} set to schedule {body.schedule or 'none'} by {user}")
        return {"output": out, "peer": peer(name)}

    # ---------------------------------------------------------------- groups (map wg-admin-groups): admins only
    def groups_view() -> dict[str, Any]:
        acc, accounts = acl(), auth.accounts()
        out = []
        for g, v in sorted(acc["groups"].items()):
            out.append({"name": g, **v, "devices": sum(1 for x in acc["members"].values() if x == g),
                        "admins": sorted(n for n, a in accounts.items() if g in a["groups"])})
        return {"groups": out}

    @app.get("/api/groups")
    def groups_get(request: Request) -> dict[str, Any]:
        admin_of(request)
        return groups_view()

    def save_group(user: str, body: GroupIn, exists: bool) -> dict[str, Any]:
        known_s = set(schedule.load(cfg.schedules_file)["schedules"])
        try:
            g = access.check_group(body.name, body.description, body.profiles, body.schedules,
                                   {p["name"] for p in do(vpn.profiles)}, known_s)
        except vpn.VpnError as exc:
            raise HTTPException(422, str(exc)) from None
        with edit_lock:
            acc = acl()
            if (body.name in acc["groups"]) != exists:
                raise HTTPException(409 if not exists else 404, f"group {body.name!r} exists: edit it instead"
                                    if not exists else f"no group {body.name!r}")
            acc["groups"][body.name] = g
            access.save(cfg.access_file, acc)
        verb = "changed" if exists else "added"
        out = f"profiles {', '.join(g['profiles']) or '-'}; schedules {', '.join(g['schedules']) or '-'}"
        audit(user, f"group-{verb}", body.name, True, out, f"VPN: group {body.name} {verb} by {user}: {out}")
        return {"output": out, **groups_view()}

    @app.post("/api/groups")
    def group_add(request: Request, body: GroupIn) -> dict[str, Any]:
        return save_group(admin_of(request), body, exists=False)

    @app.put("/api/groups/{name}")
    def group_edit(request: Request, name: str, body: GroupIn) -> dict[str, Any]:
        user = admin_of(request)
        if body.name != name:
            raise HTTPException(400, "renaming a group is not supported: add a new one")
        return save_group(user, body, exists=True)

    @app.delete("/api/groups/{name}")
    def group_delete(request: Request, name: str, confirm: str = "") -> dict[str, Any]:
        user = admin_of(request)
        if confirm.strip() != name:
            raise HTTPException(400, f'type the group name "{name}" to confirm')
        with edit_lock:
            acc = acl()
            if name not in acc["groups"]:
                raise HTTPException(404, f"no group {name!r}")
            devices = [p for p, g in acc["members"].items() if g == name]
            admins = [n for n, a in auth.accounts().items() if name in a["groups"]]
            if devices or admins:
                raise HTTPException(409, f"group {name} still has " + "; ".join(
                    x for x in (f"devices {', '.join(devices)}" if devices else "",
                                f"group admins {', '.join(admins)}" if admins else "") if x) + ": move them first")
            del acc["groups"][name]
            access.save(cfg.access_file, acc)
        audit(user, "group-delete", name, True, "deleted", f"VPN: group {name} deleted by {user}")
        return {"output": f"group {name} deleted", **groups_view()}

    # ---------------------------------------------------------------- web UI accounts: admins only
    # Safe user management (owner 2026-10-29): checked here, never only in the UI; sessions end on every change
    # of role, groups, state or password; one active admin always; the default admin keeps its role and state.
    def users_view(me: Who) -> dict[str, Any]:
        sched, now = schedule.load(cfg.schedules_file)["schedules"], now_local()
        out = []
        for n, a in auth.accounts().items():
            out.append({"name": n, "role": a["role"], "groups": a["groups"], "schedule": a["schedule"],
                        "expires": a["expires"], "disabled": a["disabled"], "default": a["default"],
                        "totp": auth.totp_status(n)["enabled"], "state": access.refused(a, sched, now) or "active",
                        "fails": auth.lockout(n)[0], "locked": auth.lockout(n)[1],
                        "you": me.via == "local" and n == me.name})
        acc = acl()
        return {"users": out, "totp_roles": acc["totp_roles"], "pw_history": acc["pw_history"]}

    def admin_left(accounts: dict[str, dict[str, Any]], w: Who) -> bool:
        """A local admin stays, or the change comes from a portal admin (portal SSO keeps admin access)."""
        if w.via == "portal":
            return True
        today = now_local().date().isoformat()
        return any(a["role"] == "admin" and not a["disabled"] and not (a["expires"] and a["expires"] < today)
                   for a in accounts.values())

    def account_fields(body: AccountIn) -> dict[str, Any]:
        try:
            return access.check_account(body.role, body.groups, body.schedule, body.expires, set(acl()["groups"]),
                                        set(schedule.load(cfg.schedules_file)["schedules"]))
        except vpn.VpnError as exc:
            raise HTTPException(422, str(exc)) from None

    def account(name: str) -> dict[str, Any]:
        a = auth.accounts().get(name)
        if a is None:
            raise HTTPException(404, f"no account {name!r}")
        return a

    def summary(a: dict[str, Any]) -> str:
        return ", ".join(x for x in (a["role"], f"groups {' '.join(a['groups'])}" if a["groups"] else "",
                                     f"sign-in {a['schedule']}" if a["schedule"] else "",
                                     f"expires {a['expires']}" if a["expires"] else "",
                                     "disabled" if a["disabled"] else "") if x)

    @app.get("/api/users")
    def users_get(request: Request) -> dict[str, Any]:
        admin_of(request)
        return users_view(who(request))

    @app.post("/api/users")
    def user_add(request: Request, body: UserIn) -> dict[str, Any]:
        user, fields = admin_of(request), account_fields(body)
        with edit_lock:
            if body.name in auth.accounts():
                raise HTTPException(409, f"account {body.name!r} exists")
            auth.set_password(body.name, body.password, **fields, disabled=body.disabled)
        out = summary(account(body.name))
        audit(user, "user-add", body.name, True, out, f"VPN: wg-admin account {body.name} added by {user}: {out}",
              f":bust_in_silhouette: VPN: wg-admin account {body.name} added by {user}: {out}")
        return {"output": out, **users_view(who(request))}

    @app.put("/api/users/{name}")
    def user_edit(request: Request, name: str, body: AccountIn) -> dict[str, Any]:
        w = who(request)
        user, fields = admin_of(request), account_fields(body)
        with edit_lock:
            accounts = auth.accounts()
            old = accounts.get(name)
            if old is None:
                raise HTTPException(404, f"no account {name!r}")
            new = {**old, **fields, "disabled": body.disabled}
            if old["default"] and (new["role"] != "admin" or new["disabled"] or new["schedule"] or new["expires"]):
                raise HTTPException(409, "the default admin cannot be demoted, disabled, scheduled or given an "
                                         "expiry: only its password and authenticator change")
            if w.via == "local" and name == w.name and (new["role"] != old["role"] or new["disabled"]):
                raise HTTPException(409, "you cannot change your own role or disable yourself: another admin can")
            accounts[name] = new
            if not admin_left(accounts, w):
                raise HTTPException(409, "at least one active admin must stay")
            auth.save_accounts(accounts)
        moved = any(new[k] != old[k] for k in ("role", "groups", "disabled"))
        dropped = auth.drop_sessions(name) if moved else 0
        out = summary(new) + (f"; {dropped} session(s) ended" if dropped else "")
        audit(user, "user-set", name, True, out, f"VPN: wg-admin account {name} changed by {user}: {out}",
              f":bust_in_silhouette: VPN: wg-admin account {name} changed by {user}: {out}")
        return {"output": out, **users_view(w)}

    @app.delete("/api/users/{name}")
    def user_delete(request: Request, name: str, confirm: str = "") -> dict[str, Any]:
        w = who(request)
        user = admin_of(request)
        if confirm.strip() != name:
            raise HTTPException(400, f'type the account name "{name}" to confirm')
        with edit_lock:
            accounts = auth.accounts()
            if name not in accounts:
                raise HTTPException(404, f"no account {name!r}")
            if accounts[name]["default"]:
                raise HTTPException(409, "the default admin cannot be deleted")
            if w.via == "local" and name == w.name:
                raise HTTPException(409, "you cannot delete your own account: another admin can")
            del accounts[name]
            if not admin_left(accounts, w):
                raise HTTPException(409, "at least one active admin must stay")
            auth.save_accounts(accounts)
        auth.totp_reset(name)
        auth.drop_sessions(name)
        audit(user, "user-delete", name, True, "deleted", f"VPN: wg-admin account {name} deleted by {user}",
              f":bust_in_silhouette: VPN: wg-admin account {name} deleted by {user}")
        return {"output": f"account {name} deleted", **users_view(w)}

    @app.post("/api/users/{name}/password")
    def user_password(request: Request, name: str, body: PasswordIn) -> dict[str, Any]:
        """Admin sets a new password (the default admin's too); the account's sessions end."""
        user = admin_of(request)
        account(name)
        new_password(name, body.password)
        audit(user, "user-password", name, True, "password reset", f"VPN: password of wg-admin account {name} reset by {user}",
              f":warning: VPN: password of wg-admin account {name} reset by {user}")
        return {"output": f"password of {name} set; its sessions ended"}

    @app.post("/api/users/{name}/unlock")
    def user_unlock(request: Request, name: str) -> dict[str, Any]:
        """Admin: reset the failed sign-in counter (per IP, 5 in 15 min) of every address that failed as this user."""
        user = admin_of(request)
        account(name)
        n = auth.reset_lockout(name)
        audit(user, "user-unlock", name, True, f"{n} address(es) cleared",
              f"VPN: sign-in lockout of wg-admin account {name} reset by {user}")
        return {"output": f"lockout of {name} reset ({n} address(es))", **users_view(who(request))}

    @app.post("/api/users/{name}/totp-reset")
    def user_totp_reset(request: Request, name: str) -> dict[str, Any]:
        """Lost phone: remove the account's authenticator; it signs in with the password and sets one up again."""
        user = admin_of(request)
        account(name)
        if not auth.totp_reset(name):
            raise HTTPException(409, f"{name} has no authenticator")
        auth.drop_sessions(name)
        audit(user, "user-totp-reset", name, True, "authenticator removed",
              f"VPN: authenticator of wg-admin account {name} removed by {user}",
              f":warning: VPN: authenticator of wg-admin account {name} removed by {user}")
        return {"output": f"authenticator of {name} removed; its sessions ended", **users_view(who(request))}

    @app.put("/api/policy")
    def policy_put(request: Request, body: PolicyIn) -> dict[str, Any]:
        """Roles that must use an authenticator: their accounts can only set one up until they have it."""
        user = admin_of(request)
        if any(r not in access.ROLES for r in body.totp_roles):
            raise HTTPException(422, "roles: admin, group-admin")
        with edit_lock:
            acc = acl()
            acc["totp_roles"] = sorted(set(body.totp_roles))
            if body.pw_history is not None:
                acc["pw_history"] = body.pw_history
            access.save(cfg.access_file, acc)
        out = (f"authenticator required for: {', '.join(acc['totp_roles']) or 'no role'}; "
               f"password history: {acc['pw_history'] or 'off'}")
        audit(user, "policy-set", "", True, out, f"VPN: {out} (set by {user})")
        return {"output": out, **users_view(who(request))}

    # ---------------------------------------------------------------- mail (map vpn-mail): notices only, no keys
    @app.get("/api/mail")
    def mail_get(request: Request) -> dict[str, Any]:
        admin_of(request)
        return mail.view(cfg)

    @app.put("/api/mail")
    def mail_put(request: Request, body: MailIn) -> dict[str, Any]:
        user = admin_of(request)
        try:
            s = mail.save(cfg, body.model_dump(exclude={"password"}), body.password)
        except vpn.VpnError as exc:
            raise HTTPException(422, str(exc)) from None
        except OSError as exc:
            raise HTTPException(500, f"cannot write the mail settings: {type(exc).__name__}") from None
        pw = "password kept" if body.password is None else "password cleared" if not body.password else "password set"
        out = f"from {s['from_addr']} via {s['host']}:{s['port']} ({s['security']}), {pw}"
        audit(user, "mail-set", "", True, out, f"VPN: mail settings changed by {user}: {out}")
        return mail.view(cfg)

    def settings() -> dict[str, Any]:
        s = mail.view(cfg)
        if not s["ready"]:
            raise HTTPException(409, "set the mail settings first (Server > Mail)")
        return s

    @app.post("/api/mail/test")
    def mail_test(request: Request, body: MailTestIn) -> dict[str, str]:
        user = admin_of(request)
        if not vpn.EMAIL.match(body.to.strip()):
            raise HTTPException(422, "to: a plain address like you@example.org")
        s = settings()
        msg = mail.message(s, body.to.strip(), "wg-admin test mail",
                           f"Test mail from wg-admin on {socket.gethostname()}, sent by {user}.\n"
                           f"Relay: {s['host']}:{s['port']} ({s['security']}).\n")
        try:
            send(s, mail.password(cfg), msg)
        except vpn.VpnError as exc:
            audit(user, "mail-test", "", False, str(exc))
            raise HTTPException(502, str(exc)) from None
        audit(user, "mail-test", "", True, f"test mail to {body.to.strip()}")
        return {"output": f"test mail sent to {body.to.strip()}"}

    @app.post("/api/mail/notice")
    def mail_notice(request: Request, body: NoticeIn) -> dict[str, Any]:
        """One mail per owner address listing that owner's ticked devices; devices without an owner are skipped."""
        w = who(request)
        user, members = w.name, acl()["members"]
        s = settings()
        known = {p["name"]: p for p in do(vpn.peers)}
        unknown = [n for n in body.names if n not in known or not (w.admin or members.get(n) in w.groups)]
        if unknown:
            raise HTTPException(404, f"no VPN peer {unknown[0]!r}")
        by_owner: dict[str, list[str]] = {}
        for n in dict.fromkeys(body.names):
            if known[n]["email"]:
                by_owner.setdefault(known[n]["email"], []).append(n)
        skipped = [n for n in dict.fromkeys(body.names) if not known[n]["email"]]
        sent, failed = [], []
        for to, names in by_owner.items():
            try:
                send(s, mail.password(cfg), mail.notice(s, to, names, body.kind))
                sent.append(to)
            except vpn.VpnError as exc:
                failed.append(str(exc))
        summary = (f"{body.kind} notice: {len(sent)} of {len(by_owner)} mails sent"
                   + (f" ({', '.join(sent)})" if sent else "") + (f"; no owner: {', '.join(skipped)}" if skipped else "")
                   + (f"; failed: {'; '.join(failed)}" if failed else ""))
        audit(user, "mail-notice", ",".join(dict.fromkeys(body.names))[:200], not failed, summary,
              f"VPN: notice mail by {user}: {summary}")
        return {"sent": sent, "skipped": skipped, "failed": failed, "output": summary}

    # Configs hold private keys: the audit records who fetched which peer, never the content.
    def private(content: str | bytes, media: str, filename: str = "") -> Response:
        headers = {"Cache-Control": "no-store"}
        if filename:
            headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        return Response(content, media_type=media, headers=headers)

    @app.get("/api/peers/{name}/conf")
    def peer_conf(request: Request, name: str) -> Response:
        user = scoped_peer(request, name)[0].name
        conf = do(vpn.client_conf, name)
        audit(user, "conf", name, True, "config downloaded", f"VPN: config of {name} downloaded by {user}")
        return private(conf, "text/plain", f"{name}.conf")

    @app.get("/api/peers/{name}/package")
    def peer_package(request: Request, name: str) -> Response:
        w, p, _ = scoped_peer(request, name)
        user = w.name
        conf = do(vpn.client_conf, name)
        audit(user, "package", name, True, "package downloaded", f"VPN: package of {name} downloaded by {user}")
        return private(vpn.package(name, p["profile"], conf), "application/zip", f"wireguard-{name}.zip")

    @app.get("/api/peers/{name}/qr")
    def peer_qr(request: Request, name: str) -> Response:
        user = scoped_peer(request, name)[0].name
        svg = do(vpn.qr_svg, name)
        audit(user, "qr", name, True, "QR shown", f"VPN: QR code of {name} shown to {user}")
        return private(svg, "image/svg+xml")

    @app.get("/health")
    def alive() -> dict[str, bool]:
        return {"ok": True}

    app.mount("/", UiFiles(directory=STATIC, html=True), name="ui")
    return app


class UiFiles(StaticFiles):
    """Static UI with Cache-Control: no-cache: without it browsers reused a stale ui.js after a deploy (owner got
    a bare "HTTP 422" from the old error handler, 2026-10-27). The ETag keeps revalidation a 304."""

    def file_response(self, *args: Any, **kwargs: Any) -> Response:
        resp = super().file_response(*args, **kwargs)
        resp.headers["Cache-Control"] = "no-cache"
        return resp


def main_app() -> FastAPI:
    """uvicorn --factory wgadmin.web:main_app"""
    logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s %(message)s")
    return create_app()

"""wg-admin: the WireGuard admin web UI + API on vpn1 (map vpn-standalone, owner go 2026-10-26).

Serves at / on 127.0.0.1:8080 behind nginx on :8443 (TLS); an optional portal can show it under a prefix such as
/vpn/ through its own nginx (prefix stripped).
Every /api route needs a user (auth.py: portal SSO headers or a local session); the static UI does not.
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
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import mail, schedule, totp, vpn
from .auth import COOKIE, Auth, CodeRequired
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


class AssignIn(BaseModel):
    schedule: str = Field("", max_length=16)  # "" = no schedule


class PeerIn(BaseModel):
    name: str = Field(pattern=vpn.NAME.pattern)
    profile: str = Field("split", pattern=vpn.PROFILE.pattern)
    tags: list[str] = Field(default_factory=list, max_length=8)
    email: str = Field("", max_length=254)


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

    def who(request: Request) -> tuple[str, str]:
        """(user, via portal|local), else 401."""
        user = auth.proxy_user(client_ip(request), {k.lower(): v for k, v in request.headers.items()})
        if user:
            return user, "portal"
        user = auth.session_user(request.cookies.get(COOKIE, ""))
        if user:
            return user, "local"
        user = auth.token_user(request.headers.get("authorization", ""))
        if user:
            return user, "token"
        raise HTTPException(401, "sign in required")

    def user_of(request: Request) -> str:
        return who(request)[0]

    def do(fn: Callable[..., Any], *args: Any) -> Any:
        try:
            return fn(cfg, *args, runner)
        except vpn.VpnError as exc:
            raise HTTPException(502, str(exc)) from None

    # ---------------------------------------------------------------- sign-in (standalone use)
    @app.get("/api/me")
    def me(request: Request) -> dict[str, str]:
        user, via = who(request)
        return {"user": user, "via": via}

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
        audit(body.name, "login", "", True, f"signed in from {ip}", f"VPN: {body.name} signed in to wg-admin on vpn1")
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
        user, via = who(request)
        if via != "local":
            raise HTTPException(403, "only for wg-admin's own accounts (signed in on this page)")
        return user

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
        user_of(request)
        try:
            peers = vpn.peers(cfg, runner)
        except vpn.VpnError as exc:
            raise HTTPException(503, str(exc)) from None
        data = schedule.load(cfg.schedules_file)
        for p in peers:
            entry = data["assign"].get(p["name"]) or {}
            p["schedule"], p["hold"] = entry.get("schedule", ""), bool(entry.get("hold"))
        return {"peers": peers, "profiles": do(vpn.profiles), **schedules_view(data)}

    def health() -> dict[str, Any]:
        return vpn.health(cfg, runner, load_text=load_text)

    @app.get("/api/health")
    def health_get(request: Request) -> dict[str, Any]:
        user_of(request)
        return health()

    @app.post("/api/health/run")
    def health_run(request: Request) -> dict[str, Any]:
        """Run checks button: the same checks, the outcome audited; a bad node also lands in the journal."""
        user = user_of(request)
        out = health()
        bad = [n for n in out["nodes"] if n["status"] == "bad"]
        summary = "; ".join(f"{n['label']}: {n['status']} ({n['line']})" for n in out["nodes"])
        audit(user, "health", "", not bad, summary,
              ("VPN health check by " + user + ": " + "; ".join(f"{n['label']} {n['line']}" for n in bad)) if bad else "")
        return out

    @app.get("/api/server")
    def server_get(request: Request) -> dict[str, Any]:
        user_of(request)
        return {"settings": do(vpn.server)}

    @app.put("/api/server")
    def server_put(request: Request, body: ServerIn) -> dict[str, Any]:
        """Endpoint/keepalive rewrite every client config (devices re-import); the listen port needs the router's
        port forward to follow."""
        user = user_of(request)
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
        user_of(request)
        return do(vpn.network)

    @app.put("/api/network")
    def network_put(request: Request, body: NetworkIn) -> dict[str, Any]:
        """NAT or routed IPv4, incoming and transit interface; applied at once (firewall + policy routing)."""
        user = user_of(request)
        try:
            vpn.network_request(body.mode, body.in_if, body.out_if, body.gateway)
        except vpn.VpnError as exc:
            raise HTTPException(422, str(exc)) from None
        out = do(vpn.save_network, body.mode, body.in_if, body.out_if, body.gateway)
        audit(user, "network-set", "", True, out, f"VPN: network changed by {user}: {out}",
              f":key: VPN network changed by {user}: {out}")
        return {"output": out, **do(vpn.network)}

    @app.get("/api/server/ruleset")
    def server_ruleset(request: Request) -> dict[str, str]:
        user_of(request)
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
        user = user_of(request)
        if profile(body.name):
            raise HTTPException(409, f"profile {body.name!r} exists: edit it instead")
        return save_profile(user, body, "added")

    @app.put("/api/profiles/{name}")
    def profile_edit(request: Request, name: str, body: ProfileDefIn) -> dict[str, Any]:
        user = user_of(request)
        if body.name != name:
            raise HTTPException(400, "renaming a profile is not supported: add a new one")
        if not profile(name):
            raise HTTPException(404, f"no VPN profile {name!r}")
        return save_profile(user, body, "changed")

    @app.delete("/api/profiles/{name}")
    def profile_delete(request: Request, name: str, confirm: str = "") -> dict[str, Any]:
        user = user_of(request)
        if confirm.strip() != name:
            raise HTTPException(400, f'type the profile name "{name}" to confirm')
        prof = profile(name)
        if prof is None:
            raise HTTPException(404, f"no VPN profile {name!r}")
        if prof["peers"]:
            raise HTTPException(409, f"profile {name} is used by {prof['peers']} peer(s): move them first")
        out = do(vpn.delete_profile, name)
        audit(user, "profile-delete", name, True, out, f"VPN: profile {name} deleted by {user}",
              f":key: VPN profile {name} deleted by {user}")
        return {"output": out}

    @app.post("/api/peers")
    def peer_add(request: Request, body: PeerIn) -> dict[str, Any]:
        user = user_of(request)
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
        audit(user, "add", body.name, True, out, f"VPN: peer {body.name} (profile {body.profile}) added by {user}",
              f":key: VPN peer {body.name} (profile {body.profile}) added by {user}")
        return {"output": out, "peer": peer(body.name)}

    @app.post("/api/peers/bulk")
    def peer_bulk(request: Request, body: BulkIn) -> dict[str, Any]:
        """All lines checked first; then created in order, stopping at the first failure. One audit event."""
        user = user_of(request)
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
        user = user_of(request)
        peer(name)
        out = do(vpn.set_profile, name, body.profile)
        audit(user, "profile", name, True, out, f"VPN: peer {name} switched to profile {body.profile} by {user}")
        return {"output": out, "peer": peer(name)}

    @app.post("/api/peers/{name}/tags")
    def peer_tags(request: Request, name: str, body: TagsIn) -> dict[str, Any]:
        user = user_of(request)
        try:
            vpn.check_tags(body.tags)
        except vpn.VpnError as exc:
            raise HTTPException(422, str(exc)) from None
        peer(name)
        out = do(vpn.set_tags, name, body.tags)
        audit(user, "tags", name, True, out, f"VPN: peer {name} tagged {', '.join(body.tags) or '(none)'} by {user}")
        return {"output": out, "peer": peer(name)}

    @app.post("/api/peers/{name}/email")
    def peer_email(request: Request, name: str, body: EmailIn) -> dict[str, Any]:
        user = user_of(request)
        try:
            vpn.check_email(body.email)
        except vpn.VpnError as exc:
            raise HTTPException(422, str(exc)) from None
        peer(name)
        out = do(vpn.set_email, name, body.email)
        audit(user, "email", name, True, out, f"VPN: owner email of {name} set by {user}")
        return {"output": out, "peer": peer(name)}

    @app.post("/api/peers/{name}/enabled")
    def peer_enabled(request: Request, name: str, body: EnabledIn) -> dict[str, Any]:
        """VPN access on/off without touching the setup (owner 2026-10-27); takes effect at once."""
        user = user_of(request)
        peer(name)
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
        user = user_of(request)
        if confirm.strip() != name:
            raise HTTPException(400, f'type the peer name "{name}" to confirm')
        peer(name)
        out = do(vpn.remove, name)
        with sched_lock:
            data = schedule.load(cfg.schedules_file)
            if data["assign"].pop(name, None) is not None:
                schedule.save(cfg.schedules_file, data)
        audit(user, "remove", name, True, out, f"VPN: peer {name} revoked by {user}",
              f":no_entry: VPN peer {name} revoked by {user}")
        return {"output": out}

    # ---------------------------------------------------------------- access schedules (map vpn-totp-schedules)
    def schedules_view(data: dict[str, Any]) -> dict[str, Any]:
        now = now_local()
        used: dict[str, int] = {}
        for entry in data["assign"].values():
            used[entry.get("schedule", "")] = used.get(entry.get("schedule", ""), 0) + 1
        views = []
        for name, s in sorted(data["schedules"].items()):
            v = schedule.view(name, s, now, used.get(name, 0))
            nxt = schedule.next_change(s, now)
            v["next"] = nxt.isoformat(timespec="minutes") if nxt else ""
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
        user_of(request)
        return schedules_view(schedule.load(cfg.schedules_file))

    def save_schedule(user: str, body: ScheduleIn, verb: str, exists: bool) -> dict[str, Any]:
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
        return save_schedule(user_of(request), body, "added", exists=False)

    @app.put("/api/schedules/{name}")
    def schedule_edit(request: Request, name: str, body: ScheduleIn) -> dict[str, Any]:
        user = user_of(request)
        if body.name != name:
            raise HTTPException(400, "renaming a schedule is not supported: add a new one")
        return save_schedule(user, body, "changed", exists=True)

    @app.delete("/api/schedules/{name}")
    def schedule_delete(request: Request, name: str, confirm: str = "") -> dict[str, str]:
        user = user_of(request)
        if confirm.strip() != name:
            raise HTTPException(400, f'type the schedule name "{name}" to confirm')
        with sched_lock:
            data = schedule.load(cfg.schedules_file)
            if name not in data["schedules"]:
                raise HTTPException(404, f"no schedule {name!r}")
            users = [p for p, e in data["assign"].items() if e.get("schedule") == name]
            if users:
                raise HTTPException(409, f"schedule {name} is used by {', '.join(users)}: set them to another first")
            del data["schedules"][name]
            schedule.save(cfg.schedules_file, data)
        audit(user, "schedule-delete", name, True, "deleted", f"VPN: schedule {name} deleted by {user}")
        return {"output": f"schedule {name} deleted"}

    @app.post("/api/peers/{name}/schedule")
    def peer_schedule(request: Request, name: str, body: AssignIn) -> dict[str, Any]:
        """Assign a schedule ("" = none: the device keeps its current on/off). Applied at once."""
        user = user_of(request)
        peer(name)
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

    # ---------------------------------------------------------------- mail (map vpn-mail): notices only, no keys
    @app.get("/api/mail")
    def mail_get(request: Request) -> dict[str, Any]:
        user_of(request)
        return mail.view(cfg)

    @app.put("/api/mail")
    def mail_put(request: Request, body: MailIn) -> dict[str, Any]:
        user = user_of(request)
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
        user = user_of(request)
        if not vpn.EMAIL.match(body.to.strip()):
            raise HTTPException(422, "to: a plain address like you@example.org")
        s = settings()
        msg = mail.message(s, body.to.strip(), "wg-admin test mail",
                           f"Test mail from wg-admin on vpn1, sent by {user}.\nRelay: {s['host']}:{s['port']} ({s['security']}).\n")
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
        user = user_of(request)
        s = settings()
        known = {p["name"]: p for p in do(vpn.peers)}
        unknown = [n for n in body.names if n not in known]
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
        user = user_of(request)
        peer(name)
        conf = do(vpn.client_conf, name)
        audit(user, "conf", name, True, "config downloaded", f"VPN: config of {name} downloaded by {user}")
        return private(conf, "text/plain", f"{name}.conf")

    @app.get("/api/peers/{name}/package")
    def peer_package(request: Request, name: str) -> Response:
        user = user_of(request)
        p = peer(name)
        conf = do(vpn.client_conf, name)
        audit(user, "package", name, True, "package downloaded", f"VPN: package of {name} downloaded by {user}")
        return private(vpn.package(name, p["profile"], conf), "application/zip", f"wireguard-{name}.zip")

    @app.get("/api/peers/{name}/qr")
    def peer_qr(request: Request, name: str) -> Response:
        user = user_of(request)
        peer(name)
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

"""Audit events: one log line each (journald on vpn1) and, when WGADMIN_EVENT_URL is set, a POST to the portal
(/api/vpn/event: audit row, journal, Slack), bearer = the shared secret. Delivery runs in a thread; a failure is
logged and never blocks the action. Never pass a client config or key in an event."""
from __future__ import annotations

import json
import logging
import ssl
import threading
import urllib.request
from collections.abc import Callable
from typing import Any

from .config import Config

log = logging.getLogger("wg-admin")
Sink = Callable[[dict[str, Any]], None]


def portal_sink(cfg: Config) -> Sink:
    def send(event: dict[str, Any]) -> None:
        try:
            ctx = ssl.create_default_context(cafile=cfg.ca_file or None)
            req = urllib.request.Request(cfg.event_url, data=json.dumps(event).encode(), method="POST",
                                         headers={"Content-Type": "application/json",
                                                  "Authorization": f"Bearer {cfg.secret()}"})
            with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                resp.read()
        except Exception as exc:  # the portal down must not block VPN admin; the log line stays
            log.warning("event to the portal failed: %s", type(exc).__name__)

    return lambda event: threading.Thread(target=send, args=(event,), daemon=True).start()


class Events:
    def __init__(self, sink: Sink | None):
        self.sink = sink

    def __call__(self, user: str, action: str, name: str, ok: bool, out: str,
                 journal: str = "", notify: str = "") -> None:
        log.info("audit user=%s action=%s name=%s ok=%s out=%s", user, action, name, ok, out[:300])
        if self.sink:
            self.sink({"user": user, "action": action, "name": name, "ok": ok, "out": out[:300],
                       "journal": journal[:500], "notify": notify[:500]})

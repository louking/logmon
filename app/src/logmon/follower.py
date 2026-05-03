"""
follower.py — Background threads that tail log files.

Architecture
------------
FollowerManager   – daemon thread; re-scans configured log dirs every 30 s,
                    spawns/restarts FileFollower threads as needed.
FileFollower      – daemon thread per log file; seeks to EOF on start, then
                    reads new lines, assembles multi-line tracebacks, persists
                    ERROR events and triggers alert suppression logic.

Each FileFollower is told explicitly which parser to use ("app" or "access")
so that app logs and access logs in the same directory are never confused.

Live-tail buffer
----------------
Lines are pushed to Redis lists keyed  logmon:tail:{app_name}:{kind}  using LPUSH
and trimmed to LOG_TAIL_LINES entries with LTRIM.  Both the follower service
and the web/app service connect to the same Redis instance, so the live-tail
API always sees current data regardless of which process handles the request.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime
from typing import Literal

import redis

log = logging.getLogger(__name__)

ParserType = Literal["app", "access"]

REDIS_KEY_PREFIX = "logmon:tail:"  # full key: logmon:tail:{app_name}:{kind}

_manager: "FollowerManager | None" = None
_redis: redis.Redis | None = None


def _get_redis(flask_app) -> redis.Redis:
    """Return a module-level Redis client, creating it on first call."""
    global _redis
    if _redis is None:
        url = flask_app.config.get("REDIS_URL", "redis://redis:6379/0")
        _redis = redis.from_url(url, decode_responses=True)
    return _redis


# ------------------------------------------------------------------ public API

def get_tail(app_name: str, n: int = 100, kind: str = "app", flask_app=None) -> list:
    """Return the n most-recent tail entries for app_name and kind from Redis.

    kind is "app" (Flask app log) or "access" (nginx access log).
    """
    r = _get_redis(flask_app)
    key = REDIS_KEY_PREFIX + app_name + ":" + kind
    # List is stored newest-first (LPUSH); LRANGE 0 n-1 gives the n newest
    raw_items = r.lrange(key, 0, n - 1)
    items = []
    for raw in raw_items:
        try:
            items.append(json.loads(raw))
        except Exception:
            items.append({"raw": raw, "level": "", "occurred_at": "", "message": raw})
    return items


def get_all_tails(n: int = 50, kind: str = "app", flask_app=None) -> dict:
    """Return the n most-recent tail entries for every known app, for the given kind."""
    r = _get_redis(flask_app)
    # Match keys for the requested kind only: logmon:tail:*:{kind}
    keys = r.keys(REDIS_KEY_PREFIX + "*:" + kind)
    result = {}
    for key in keys:
        # Strip prefix and trailing :{kind} to get the app name
        app_name = key[len(REDIS_KEY_PREFIX):]
        if app_name.endswith(":" + kind):
            app_name = app_name[: -(len(kind) + 1)]
        raw_items = r.lrange(key, 0, n - 1)
        items = []
        for raw in raw_items:
            try:
                items.append(json.loads(raw))
            except Exception:
                items.append({"raw": raw, "level": "", "occurred_at": "", "message": raw})
        result[app_name] = items
    return result


def start_follower(flask_app) -> None:
    from .diskmon import start_disk_monitor
    from .memmon import start_mem_monitor

    global _manager
    if _manager is None:
        _manager = FollowerManager(flask_app)
        _manager.start()
        log.info("FollowerManager started")

    start_disk_monitor(flask_app)
    start_mem_monitor(flask_app)


# ---------------------------------------------------------------- FileFollower

class FileFollower(threading.Thread):
    def __init__(
        self,
        app_name: str,
        filepath: str,
        parser: ParserType,
        app_cfg,
        flask_app,
    ):
        super().__init__(
            daemon=True,
            name=f"follower-{app_name}-{parser}-{os.path.basename(filepath)}",
        )
        self.app_name = app_name
        self.filepath = filepath
        self.parser = parser            # "app" or "access"
        self.app_cfg = app_cfg          # AppEntry from settings
        self.flask_app = flask_app
        self._stop_event = threading.Event()
        self._tail_maxlen = flask_app.config.get("LOG_TAIL_LINES", 500)
        self.inode: int | None = None   # set after open; used for rotation detection

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        log.info(
            "FileFollower starting: %s / %s (parser=%s)",
            self.app_name, self.filepath, self.parser,
        )
        try:
            with open(self.filepath, errors="replace") as fh:
                self.inode = os.fstat(fh.fileno()).st_ino
                fh.seek(0, 2)   # jump to end of file
                if self.parser == "app":
                    self._run_app(fh)
                else:
                    self._run_access(fh)
        except Exception:
            log.exception(
                "FileFollower crashed: %s / %s", self.app_name, self.filepath
            )

    # ---------------------------------------------------------- app log loop

    def _run_app(self, fh) -> None:
        from .logparser import is_new_app_record, parse_app_line

        pending: dict | None = None
        tb_lines: list[str] = []

        while not self._stop_event.is_set():
            line = fh.readline()

            if not line:
                if pending and tb_lines:
                    try:
                        self._commit_app(pending, tb_lines)
                    except Exception:
                        log.exception(
                            "Failed to persist traceback event for %s", self.app_name
                        )
                    pending, tb_lines = None, []
                time.sleep(0.25)
                continue

            line = line.rstrip("\n")
            self._push_redis(line, "app")

            if pending is not None:
                if not is_new_app_record(line):
                    tb_lines.append(line)
                    continue
                try:
                    self._commit_app(pending, tb_lines)
                except Exception:
                    log.exception(
                        "Failed to persist traceback event for %s", self.app_name
                    )
                pending, tb_lines = None, []

            parsed = parse_app_line(line)
            if parsed is None:
                continue

            if parsed["type"] in ("exception_start", "traceback_start"):
                # Both formats introduce a multi-line traceback — collect
                # continuation lines before persisting.
                pending = parsed
            elif parsed["level"] == "ERROR":
                # Single-line ERROR with no traceback; persist immediately.
                try:
                    self._persist_app_event(parsed, "")
                except Exception:
                    log.exception(
                        "Failed to persist error event for %s", self.app_name
                    )

    # -------------------------------------------------------- access log loop

    def _run_access(self, fh) -> None:
        from .logparser import parse_access_line

        while not self._stop_event.is_set():
            line = fh.readline()

            if not line:
                time.sleep(0.25)
                continue

            line = line.rstrip("\n")
            self._push_redis(line, "access")

            parsed = parse_access_line(line)
            if parsed is None:
                continue

            self._persist_access_event(parsed)

    # ---------------------------------------------------------------- helpers

    def _push_redis(self, raw: str, kind: str) -> None:
        """Push one line to the Redis tail list for this app."""
        from .logparser import parse_app_line, parse_access_line

        if kind == "app":
            parsed = parse_app_line(raw) or {}
            entry = {
                "raw": raw,
                "level": parsed.get("level", ""),
                "occurred_at": (
                    parsed["occurred_at"].isoformat()
                    if parsed.get("occurred_at")
                    else datetime.now().isoformat()
                ),
                "message": parsed.get("message", raw[:200]),
            }
        else:
            parsed = parse_access_line(raw) or {}
            entry = {
                "raw": raw,
                "level": "",
                "occurred_at": (
                    parsed["occurred_at"].isoformat()
                    if parsed.get("occurred_at")
                    else datetime.now().isoformat()
                ),
                "message": (
                    f"{parsed['client_ip']} {parsed.get('method','')} "
                    f"{parsed.get('path','')} {parsed.get('status_code','')}"
                    if parsed else raw[:200]
                ),
            }

        try:
            r = _get_redis(self.flask_app)
            key = REDIS_KEY_PREFIX + self.app_name + ":" + kind
            pipe = r.pipeline()
            pipe.lpush(key, json.dumps(entry))
            pipe.ltrim(key, 0, self._tail_maxlen - 1)
            pipe.execute()
        except Exception:
            log.exception("Redis push failed for %s", self.app_name)

    def _commit_app(self, event: dict, tb_lines: list[str]) -> None:
        self._persist_app_event(event, "\n".join(tb_lines))

    def _persist_app_event(self, event: dict, traceback_text: str) -> None:
        from .logparser import extract_exception_type
        from .model import db, AlertSuppression, LogEvent

        exc_type = extract_exception_type(traceback_text) if traceback_text else None

        with self.flask_app.app_context():
            le = LogEvent(
                app_name=self.app_name,
                occurred_at=event.get("occurred_at") or datetime.now(),
                level=event.get("level", "ERROR"),
                user=event.get("user"),
                ip=event.get("ip"),
                method=event.get("method"),
                url=event.get("url"),
                status_code=event.get("status_code"),
                message=event.get("message", ""),
                traceback=traceback_text or None,
                exception_type=exc_type,
            )
            db.session.add(le)
            db.session.commit()

            if exc_type:
                self._maybe_alert(le, exc_type)

    def _persist_access_event(self, parsed: dict) -> None:
        from .model import db, AccessEvent

        with self.flask_app.app_context():
            ae = AccessEvent(
                app_name=self.app_name,
                occurred_at=parsed.get("occurred_at") or datetime.now(),
                client_ip=parsed.get("client_ip"),
                ip_chain=parsed.get("ip_chain"),
                method=parsed.get("method"),
                path=parsed.get("path"),
                status_code=parsed.get("status_code"),
                bytes_sent=parsed.get("bytes_sent"),
                referer=parsed.get("referer"),
                user_agent=parsed.get("user_agent"),
            )
            db.session.add(ae)
            db.session.commit()

    def _maybe_alert(self, event, exc_type: str) -> None:
        from .model import db, AlertSuppression
        from .alerter import send_alert

        suppress_secs = (
            self.app_cfg.alert_suppress_seconds
            if self.app_cfg.alert_suppress_seconds is not None
            else self.flask_app.config["ALERT_SUPPRESS_SECONDS"]
        )
        now = datetime.now()

        row = AlertSuppression.query.filter_by(
            app_name=self.app_name,
            exception_type=exc_type,
        ).first()

        if row is None or (now - row.last_alerted_at).total_seconds() > suppress_secs:
            send_alert(self.flask_app, event)
            if row is None:
                db.session.add(AlertSuppression(
                    app_name=self.app_name,
                    exception_type=exc_type,
                    last_alerted_at=now,
                ))
            else:
                row.last_alerted_at = now
            db.session.commit()


# --------------------------------------------------------------- FollowerManager

class FollowerManager(threading.Thread):
    SCAN_INTERVAL = 30   # seconds

    def __init__(self, flask_app):
        super().__init__(daemon=True, name="follower-manager")
        self.flask_app = flask_app
        self._followers: dict[str, FileFollower] = {}   # filepath → thread

    def run(self) -> None:
        while True:
            try:
                self._scan()
            except Exception:
                log.exception("FollowerManager scan error")
            time.sleep(self.SCAN_INTERVAL)

    def _scan(self) -> None:
        log_apps: list = self.flask_app.config.get("LOG_APPS", [])
        for entry in log_apps:
            if entry.app_log_enabled:
                self._ensure_follower(entry.app_log_path, "app", entry)
            self._ensure_follower(entry.access_log_path, "access", entry)

    def _ensure_follower(self, filepath: str, parser: ParserType, entry) -> None:
        if not filepath:
            return   # disabled (e.g. app_log: false)
        if not os.path.exists(filepath):
            log.warning("Expected %s log not found, will retry: %s", parser, filepath)
            return   # not present yet; picked up on next scan
        follower = self._followers.get(filepath)
        if follower is not None and follower.is_alive():
            # Detect log rotation: if the path now points to a different inode,
            # the file was rotated — stop the stale follower so a new one starts.
            try:
                if follower.inode is not None and os.stat(filepath).st_ino != follower.inode:
                    log.info(
                        "Log rotation detected for %s (inode changed), restarting follower",
                        filepath,
                    )
                    follower.stop()
                    follower = None
            except OSError:
                pass
        if follower is None or not follower.is_alive():
            log.info("(Re)starting %s follower for %s", parser, filepath)
            f = FileFollower(entry.name, filepath, parser, entry, self.flask_app)
            f.start()
            self._followers[filepath] = f

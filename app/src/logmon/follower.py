"""
follower.py — Background threads that tail log files.

Architecture
------------
FollowerManager   – daemon thread; re-scans configured log dirs every 30 s,
                    spawns/restarts FileFollower threads as needed.
FileFollower      – daemon thread per log file; seeks to EOF on start, then
                    reads new lines, assembles multi-line tracebacks, persists
                    ERROR events and triggers alert suppression logic.

The in-memory ring buffer (per app) is exposed to the live-tail JSON API
without hitting the database.
"""
from __future__ import annotations

import glob
import logging
import os
import threading
import time
from collections import deque
from datetime import datetime, UTC

log = logging.getLogger(__name__)

# Per-app ring buffers: {app_name: deque[dict]}
_tail_buffers: dict[str, deque] = {}
_tail_lock = threading.Lock()

_manager: FollowerManager | None = None


# ------------------------------------------------------------------ public API

def get_tail(app_name: str, n: int = 100) -> list:
    with _tail_lock:
        return list(_tail_buffers.get(app_name, deque()))[-n:]


def get_all_tails(n: int = 50) -> dict:
    with _tail_lock:
        return {k: list(v)[-n:] for k, v in _tail_buffers.items()}


def start_follower(flask_app) -> None:
    global _manager
    if _manager is None:
        _manager = FollowerManager(flask_app)
        _manager.start()
        log.info("FollowerManager started")


# ---------------------------------------------------------------- FileFollower

class FileFollower(threading.Thread):
    def __init__(self, app_name: str, filepath: str, app_cfg, flask_app):
        super().__init__(
            daemon=True,
            name=f"follower-{app_name}-{os.path.basename(filepath)}",
        )
        self.app_name = app_name
        self.filepath = filepath
        self.app_cfg = app_cfg          # AppEntry from config
        self.flask_app = flask_app
        self._stop_event = threading.Event()

        with _tail_lock:
            _tail_buffers.setdefault(
                app_name,
                deque(maxlen=flask_app.config.get("LOG_TAIL_LINES", 500)),
            )

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        log.info("FileFollower starting: %s / %s", self.app_name, self.filepath)
        try:
            with open(self.filepath, errors="replace") as fh:
                fh.seek(0, 2)   # jump to end of file

                pending: dict | None = None
                tb_lines: list[str] = []

                while not self._stop_event.is_set():
                    line = fh.readline()

                    if not line:
                        # EOF — flush any open exception block, then wait
                        if pending and tb_lines:
                            self._commit(pending, tb_lines)
                            pending, tb_lines = None, []
                        time.sleep(0.25)
                        continue

                    line = line.rstrip("\n")
                    self._push_buffer(line)

                    from .logparser import is_new_app_record as is_new_record, parse_app_line as parse_line

                    if pending is not None:
                        if not is_new_record(line):
                            tb_lines.append(line)
                            continue
                        # New record arrived — flush the buffered exception
                        self._commit(pending, tb_lines)
                        pending, tb_lines = None, []

                    parsed = parse_line(line)
                    if parsed is None:
                        continue

                    if parsed["type"] == "exception_start":
                        pending = parsed
                    elif parsed["level"] == "ERROR":
                        # ERROR without a traceback (e.g. plain error log line)
                        self._persist_and_alert(parsed, "")

        except Exception:
            log.exception("FileFollower crashed: %s / %s", self.app_name, self.filepath)

    # ---------------------------------------------------------------- helpers

    def _push_buffer(self, raw: str) -> None:
        from .logparser import parse_app_line as parse_line
        parsed = parse_line(raw) or {}
        with _tail_lock:
            _tail_buffers[self.app_name].append({
                "raw": raw,
                "level": parsed.get("level", ""),
                "occurred_at": (parsed.get("occurred_at") or datetime.now(tz=UTC)).isoformat(),
                "message": parsed.get("message", raw[:200]),
            })

    def _commit(self, event: dict, tb_lines: list[str]) -> None:
        self._persist_and_alert(event, "\n".join(tb_lines))

    def _persist_and_alert(self, event: dict, traceback_text: str) -> None:
        from .logparser import extract_exception_type

        exc_type = extract_exception_type(traceback_text) if traceback_text else None

        with self.flask_app.app_context():
            from .model import db, AlertSuppression, LogEvent

            le = LogEvent(
                app_name=self.app_name,
                occurred_at=event.get("occurred_at") or datetime.now(tz=UTC),
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

    def _maybe_alert(self, event, exc_type: str) -> None:
        from .model import AlertSuppression, db
        from .alerter import send_alert

        # Per-app suppression window, falling back to global setting
        suppress_secs = (
            self.app_cfg.alert_suppress_seconds
            if self.app_cfg.alert_suppress_seconds is not None
            else self.flask_app.config["ALERT_SUPPRESS_SECONDS"]
        )
        now = datetime.now(tz=UTC)

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
            for filepath in glob.glob(os.path.join(entry.log_dir, "*.log")):
                follower = self._followers.get(filepath)
                if follower is None or not follower.is_alive():
                    log.info("(Re)starting follower for %s", filepath)
                    f = FileFollower(entry.name, filepath, entry, self.flask_app)
                    f.start()
                    self._followers[filepath] = f

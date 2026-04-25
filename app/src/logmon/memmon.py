"""
memmon.py — Background thread that collects memory and swap statistics.

Architecture
------------
MemMonitor   – daemon thread; wakes every MEM_CHECK_INTERVAL seconds,
               reads /proc/meminfo for RAM and swap usage,
               stores the result in Redis under logmon:memmon:snapshot
               (a capped list, newest-first, of JSON objects), persists
               to the MemSnapshot table, and fires suppressed alert emails
               when swap usage exceeds SWAP_ALERT_THRESHOLD_PCT percent used.

Redis keys
----------
logmon:memmon:snapshot   – LPUSH'd JSON snapshots, capped to MEM_SNAPSHOT_HISTORY
                           entries.  Each entry has the shape described in
                           _collect() below.

Alert suppression
-----------------
Uses the same AlertSuppression model as diskmon.py, with:
    app_name       = "memmon"
    exception_type = "swap"

Swap alerts use MEM_ALERT_SUPPRESS_SECONDS (default 14400 = 4 h), falling
back to ALERT_SUPPRESS_SECONDS if the mem-specific key is not set.

Host visibility
---------------
/proc/meminfo inside a container always reflects the host kernel's view of
memory — Docker containers share the host kernel, so the numbers are host
RAM and swap totals regardless of any cgroup memory limit set on the
container.  This is the correct and desired behaviour for server monitoring.
MemAvailable is used (not MemFree) so that buffer/cache is counted as
effectively free for new processes.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime

log = logging.getLogger(__name__)

REDIS_KEY = "logmon:memmon:snapshot"

_monitor: "MemMonitor | None" = None


# ------------------------------------------------------------------ public API

def start_mem_monitor(flask_app) -> None:
    global _monitor
    if _monitor is None:
        _monitor = MemMonitor(flask_app)
        _monitor.start()
        log.info("MemMonitor started")


def get_mem_snapshot(flask_app) -> dict | None:
    """Return the most-recent snapshot dict, or None if not yet collected."""
    from .follower import _get_redis
    r = _get_redis(flask_app)
    raw = r.lindex(REDIS_KEY, 0)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


# ---------------------------------------------------------------- MemMonitor

class MemMonitor(threading.Thread):
    def __init__(self, flask_app):
        super().__init__(daemon=True, name="mem-monitor")
        self.flask_app = flask_app

    def run(self) -> None:
        interval = self.flask_app.config.get("MEM_CHECK_INTERVAL", 60)
        while True:
            try:
                snapshot = _collect()
                self._store(snapshot)
                self._store_db(snapshot)
                self._check_alerts(snapshot)
            except Exception:
                log.exception("MemMonitor collection error")
            time.sleep(interval)

    def _store(self, snapshot: dict) -> None:
        from .follower import _get_redis
        maxlen = self.flask_app.config.get("MEM_SNAPSHOT_HISTORY", 1440)
        r = _get_redis(self.flask_app)
        pipe = r.pipeline()
        pipe.lpush(REDIS_KEY, json.dumps(snapshot))
        pipe.ltrim(REDIS_KEY, 0, maxlen - 1)
        pipe.execute()

    def _store_db(self, snapshot: dict) -> None:
        from .model import db, MemSnapshot

        try:
            collected_at = datetime.fromisoformat(snapshot["collected_at"])
        except (KeyError, ValueError):
            collected_at = datetime.now()

        mem  = snapshot.get("mem",  {})
        swap = snapshot.get("swap", {})

        row = MemSnapshot(
            collected_at     = collected_at,
            mem_total_kb     = mem.get("total_kb"),
            mem_available_kb = mem.get("available_kb"),
            mem_used_kb      = mem.get("used_kb"),
            mem_pct          = mem.get("pct"),
            swap_total_kb    = swap.get("total_kb"),
            swap_free_kb     = swap.get("free_kb"),
            swap_used_kb     = swap.get("used_kb"),
            swap_pct         = swap.get("pct"),
        )

        with self.flask_app.app_context():
            try:
                db.session.merge(row)
                db.session.commit()
            except Exception:
                db.session.rollback()
                log.exception("MemMonitor: failed to persist snapshot to DB")

    def _check_alerts(self, snapshot: dict) -> None:
        threshold = self.flask_app.config.get("SWAP_ALERT_THRESHOLD_PCT", 50)
        swap = snapshot.get("swap", {})
        total = swap.get("total_kb", 0) or 0
        pct   = swap.get("pct", 0) or 0
        if total > 0 and pct >= threshold:
            self._maybe_alert(swap, threshold)

    def _maybe_alert(self, swap: dict, threshold: int) -> None:
        from .model import db, AlertSuppression
        from .alerter import send_mem_alert

        suppress_secs = self.flask_app.config.get(
            "MEM_ALERT_SUPPRESS_SECONDS",
            self.flask_app.config.get("ALERT_SUPPRESS_SECONDS", 3600),
        )
        now = datetime.now()

        with self.flask_app.app_context():
            row = AlertSuppression.query.filter_by(
                app_name="memmon",
                exception_type="swap",
            ).first()

            if row is None or (now - row.last_alerted_at).total_seconds() > suppress_secs:
                send_mem_alert(self.flask_app, swap, threshold)
                if row is None:
                    db.session.add(AlertSuppression(
                        app_name="memmon",
                        exception_type="swap",
                        last_alerted_at=now,
                    ))
                else:
                    row.last_alerted_at = now
                db.session.commit()


# ---------------------------------------------------------------- collection

def _collect() -> dict:
    """
    Return a snapshot dict with shape:

    {
        "collected_at": "2025-01-01T00:00:00",
        "mem": {
            "total_kb":     8192000,
            "available_kb": 4096000,
            "used_kb":      4096000,
            "pct":          50,
        },
        "swap": {
            "total_kb": 2097152,
            "free_kb":  1048576,
            "used_kb":  1048576,
            "pct":      50,
        },
    }
    """
    info = _read_proc_meminfo()
    return {
        "collected_at": datetime.now().isoformat(timespec="seconds"),
        "mem":  _build_mem(info),
        "swap": _build_swap(info),
    }


def _read_proc_meminfo() -> dict[str, int]:
    """Parse /proc/meminfo into a dict of {key: value_in_kb}."""
    result: dict[str, int] = {}
    try:
        with open("/proc/meminfo") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2:
                    key = parts[0].rstrip(":")
                    try:
                        result[key] = int(parts[1])
                    except ValueError:
                        pass
    except OSError:
        log.warning("/proc/meminfo unavailable")
    return result


def _build_mem(info: dict[str, int]) -> dict:
    total     = info.get("MemTotal", 0)
    available = info.get("MemAvailable", info.get("MemFree", 0))
    used      = max(0, total - available)
    pct       = round(used / total * 100) if total else 0
    return {
        "total_kb":     total,
        "available_kb": available,
        "used_kb":      used,
        "pct":          pct,
    }


def _build_swap(info: dict[str, int]) -> dict:
    total = info.get("SwapTotal", 0)
    free  = info.get("SwapFree", 0)
    used  = max(0, total - free)
    pct   = round(used / total * 100) if total else 0
    return {
        "total_kb": total,
        "free_kb":  free,
        "used_kb":  used,
        "pct":      pct,
    }

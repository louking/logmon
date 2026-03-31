"""
diskmon.py — Background thread that collects disk-usage statistics.

Architecture
------------
DiskMonitor   – daemon thread; wakes every DISK_CHECK_INTERVAL seconds,
                runs `df -P` for real filesystem usage and
                `docker system df --format json` for Docker usage,
                stores the result in Redis under  logmon:diskmon:snapshot
                (a capped list, newest-first, of JSON objects), and fires
                suppressed alert emails when any real filesystem exceeds
                DISK_ALERT_THRESHOLD_PCT percent used.

Redis keys
----------
logmon:diskmon:snapshot   – LPUSH'd JSON snapshots, capped to DISK_SNAPSHOT_HISTORY
                            entries.  Each entry has the shape described in
                            _collect() below.

Alert suppression
-----------------
Uses the same AlertSuppression model as follower.py, with:
    app_name       = "diskmon"
    exception_type = the mount-point string (e.g. "/var/lib/docker")

This means the existing ALERT_SUPPRESS_SECONDS config key works for disk
alerts too, and the suppression window is shared with log-event alerts only
in the sense that they share the same table — the (app_name, exception_type)
pair is unique so they never collide.

Docker socket
-------------
The container running this thread needs:
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
Add that line to docker-compose.override.yml under the `follower` service.
If the socket is absent, Docker stats are skipped gracefully and the
snapshot's docker_* fields are null.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
from datetime import datetime

log = logging.getLogger(__name__)

REDIS_KEY = "logmon:diskmon:snapshot"
HOST_PREFIX = "/host"

_monitor: "DiskMonitor | None" = None


# ------------------------------------------------------------------ public API

def start_disk_monitor(flask_app) -> None:
    global _monitor
    if _monitor is None:
        _monitor = DiskMonitor(flask_app)
        _monitor.start()
        log.info("DiskMonitor started")


def get_disk_snapshot(flask_app) -> dict | None:
    """Return the most-recent snapshot dict, or None if not yet collected."""
    from .follower import _get_redis  # reuse the shared Redis client helper
    r = _get_redis(flask_app)
    raw = r.lindex(REDIS_KEY, 0)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


def get_disk_history(flask_app, n: int = 60) -> list[dict]:
    """Return up to n historical snapshots, newest-first."""
    from .follower import _get_redis
    r = _get_redis(flask_app)
    raws = r.lrange(REDIS_KEY, 0, n - 1)
    result = []
    for raw in raws:
        try:
            result.append(json.loads(raw))
        except Exception:
            pass
    return result


# ---------------------------------------------------------------- DiskMonitor

class DiskMonitor(threading.Thread):
    def __init__(self, flask_app):
        super().__init__(daemon=True, name="disk-monitor")
        self.flask_app = flask_app

    def run(self) -> None:
        interval = self.flask_app.config.get("DISK_CHECK_INTERVAL", 60)
        while True:
            try:
                snapshot = _collect()
                self._store(snapshot)
                self._store_db(snapshot)
                self._check_alerts(snapshot)
            except Exception:
                log.exception("DiskMonitor collection error")
            time.sleep(interval)

    # ---------------------------------------------------------------- helpers

    def _store(self, snapshot: dict) -> None:
        from .follower import _get_redis
        maxlen = self.flask_app.config.get("DISK_SNAPSHOT_HISTORY", 1440)
        r = _get_redis(self.flask_app)
        pipe = r.pipeline()
        pipe.lpush(REDIS_KEY, json.dumps(snapshot))
        pipe.ltrim(REDIS_KEY, 0, maxlen - 1)
        pipe.execute()

    def _store_db(self, snapshot: dict) -> None:
        """Persist the snapshot to the DiskSnapshot table."""
        from .model import db, DiskSnapshot

        collected_at_str = snapshot.get("collected_at")
        try:
            collected_at = datetime.fromisoformat(collected_at_str)
        except (TypeError, ValueError):
            collected_at = datetime.now()

        rows = []

        # --- one row per real filesystem ---
        for fs in snapshot.get("filesystems", []):
            rows.append(DiskSnapshot(
                collected_at = collected_at,
                mount        = fs["mount"],
                device       = fs.get("device"),
                total_kb     = fs.get("total_kb"),
                used_kb      = fs.get("used_kb"),
                avail_kb     = fs.get("avail_kb"),
                use_pct      = fs.get("use_pct"),
            ))

        # --- one sentinel row for Docker totals ---
        d = snapshot.get("docker")
        if d is not None:
            rows.append(DiskSnapshot(
                collected_at                        = collected_at,
                mount                               = "__docker__",
                docker_images_size_bytes            = d.get("images_size_bytes"),
                docker_images_reclaimable_bytes     = d.get("images_reclaimable_bytes"),
                docker_images_active                = d.get("images_active"),
                docker_containers_size_bytes        = d.get("containers_size_bytes"),
                docker_containers_active            = d.get("containers_active"),
                docker_volumes_count                = d.get("volumes_count"),
                docker_volumes_size_bytes           = d.get("volumes_size_bytes"),
                docker_volumes_reclaimable_bytes    = d.get("volumes_reclaimable_bytes"),
                docker_build_cache_size_bytes       = d.get("build_cache_size_bytes"),
                docker_build_cache_reclaimable_bytes= d.get("build_cache_reclaimable_bytes"),
            ))

        if not rows:
            return

        with self.flask_app.app_context():
            try:
                for row in rows:
                    db.session.merge(row)   # INSERT OR UPDATE on the unique constraint
                db.session.commit()
            except Exception:
                db.session.rollback()
                log.exception("DiskMonitor: failed to persist snapshot to DB")

    def _check_alerts(self, snapshot: dict) -> None:
        threshold = self.flask_app.config.get("DISK_ALERT_THRESHOLD_PCT", 85)
        for fs in snapshot.get("filesystems", []):
            pct = fs.get("use_pct", 0)
            if pct >= threshold:
                self._maybe_alert(fs, threshold)

    def _maybe_alert(self, fs: dict, threshold: int) -> None:
        from .model import db, AlertSuppression
        from .alerter import send_disk_alert

        mount = fs["mount"]
        suppress_secs = self.flask_app.config.get(
            "DISK_ALERT_SUPPRESS_SECONDS",
            self.flask_app.config.get("ALERT_SUPPRESS_SECONDS", 3600),
        )
        now = datetime.now()

        with self.flask_app.app_context():
            row = AlertSuppression.query.filter_by(
                app_name="diskmon",
                exception_type=mount,
            ).first()

            if row is None or (now - row.last_alerted_at).total_seconds() > suppress_secs:
                send_disk_alert(self.flask_app, fs, threshold)
                if row is None:
                    db.session.add(AlertSuppression(
                        app_name="diskmon",
                        exception_type=mount,
                        last_alerted_at=now,
                    ))
                else:
                    row.last_alerted_at = now
                db.session.commit()


# ---------------------------------------------------------------- collection

# Filesystems to exclude from the summary tile (pseudo/kernel fs).
_DF_EXCLUDE = frozenset([
    "tmpfs", "devtmpfs", "overlay", "shm",
    "udev", "cgroup", "cgroupfs", "pstore",
    "none", "sysfs", "proc", "devpts",
])


def _collect() -> dict:
    """
    Return a snapshot dict with shape:

    {
        "collected_at": "2025-01-01T00:00:00",
        "filesystems": [
            {
                "device":    "/dev/sda1",
                "mount":     "/",
                "total_kb":  102400,
                "used_kb":   51200,
                "avail_kb":  51200,
                "use_pct":   50,          # integer 0-100
            },
            ...
        ],
        "docker": {                        # null if Docker socket unavailable
            "images_size":         1234567,   # bytes
            "images_reclaimable":  123456,
            "containers_size":     0,
            "volumes_size":        9876,
            "volumes_reclaimable": 0,
            "build_cache_size":    0,
            "build_cache_reclaimable": 0,
            "images": [                    # verbose detail list
                {"id": "sha256:abc", "repository": "nginx", "tag": "latest",
                 "size": 142000000, "created": "2024-12-01T00:00:00Z"},
                ...
            ],
            "volumes": [
                {"name": "myapp_data", "size": 9876, "links": 1},
                ...
            ],
        },
    }
    """
    snapshot: dict = {
        "collected_at": datetime.now().isoformat(timespec="seconds"),
        "filesystems": _collect_df(),
        "docker": _collect_docker(),
    }
    return snapshot


def _collect_df() -> list[dict]:
    """Run `df -P` and return one dict per real filesystem."""
    try:
        result = subprocess.run(
            ["df", "-P", "-k"],
            capture_output=True, text=True, timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        log.warning("df command unavailable")
        return []

    host_mode = os.path.isdir(HOST_PREFIX)   # are we using the /host/ convention?

    rows = []
    lines = result.stdout.splitlines()
    for line in lines[1:]:   # skip header
        parts = line.split()
        if len(parts) < 6:
            continue
        device, total_kb, used_kb, avail_kb, use_pct_str, mount = (
            parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
        )
        # Skip pseudo filesystems
        fs_type = _get_fstype(mount)
        if fs_type and fs_type.lower() in _DF_EXCLUDE:
            continue

        # Rewrite /host/root → / and /host/mnt/x → /mnt/x for display
        if host_mode:
            if not mount.startswith(HOST_PREFIX):
                continue                      # skip all non-host mounts
            display_mount = mount[len(HOST_PREFIX):] or "/"
        else:
            # fallback: filter pseudo filesystems as before
            if device in ("tmpfs", "none", "devtmpfs", "overlay", "shm"):
                continue
            display_mount = mount
        
        try:
            use_pct = int(use_pct_str.rstrip("%"))
            
            rows.append({
                "device":        device,
                "mount":         display_mount,
                "real_mount":    mount,          # actual container path for dedup
                "total_kb":      int(total_kb),
                "used_kb":  int(used_kb),
                "avail_kb": int(avail_kb),
                "use_pct":  use_pct,
            })
        except ValueError:
            continue
    return rows


def _get_fstype(mount: str) -> str | None:
    """Try to read the fstype for a mount from /proc/mounts (Linux only)."""
    try:
        with open("/proc/mounts") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == mount:
                    return parts[2]
    except Exception:
        pass
    return None


def _collect_docker() -> dict | None:
    """
    Run `docker system df --format json` (Docker ≥ 25) for summary and
    `docker system df -v --format json` for verbose detail.
    Returns None gracefully if Docker is unavailable or the socket is absent.
    """
    if not os.path.exists("/var/run/docker.sock"):
        return None

    summary = _run_docker_df()
    if summary is None:
        return None
    verbose = _run_docker_df_verbose()

    result: dict = {
        "images_size":              summary.get("Images", {}).get("TotalCount", 0),
        "images_active":            summary.get("Images", {}).get("Active", 0),
        "images_size_bytes":        _parse_size(summary.get("Images", {}).get("Size", "0B")),
        "images_reclaimable_bytes": _parse_size(summary.get("Images", {}).get("Reclaimable", "0B")),
        "containers_active":        summary.get("Containers", {}).get("Active", 0),
        "containers_size_bytes":    _parse_size(summary.get("Containers", {}).get("Size", "0B")),
        "volumes_count":            summary.get("Volumes", {}).get("TotalCount", 0),
        "volumes_size_bytes":       _parse_size(summary.get("Volumes", {}).get("Size", "0B")),
        "volumes_reclaimable_bytes":_parse_size(summary.get("Volumes", {}).get("Reclaimable", "0B")),
        "build_cache_count":        summary.get("BuildCache", {}).get("TotalCount", 0),
        "build_cache_size_bytes":   _parse_size(summary.get("BuildCache", {}).get("Size", "0B")),
        "build_cache_reclaimable_bytes": _parse_size(summary.get("BuildCache", {}).get("Reclaimable", "0B")),
        "images":  verbose.get("images", [])  if verbose else [],
        "volumes": verbose.get("volumes", []) if verbose else [],
    }
    return result


def _run_docker_df() -> dict | None:
    """docker system df --format json → parsed summary dict."""
    try:
        result = subprocess.run(
            ["docker", "system", "df", "--format", "{{json .}}"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            log.warning("docker system df failed: %s", result.stderr[:200])
            return None
        # Output is one JSON object per line (Images, Containers, Volumes, BuildCache)
        data: dict = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                # Each object has a "Type" key
                t = obj.get("Type", "")
                data[t] = obj
            except json.JSONDecodeError:
                pass
        return data
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        log.warning("docker system df unavailable: %s", exc)
        return None


def _run_docker_df_verbose() -> dict | None:
    """docker system df -v → structured lists of images and volumes."""
    try:
        result = subprocess.run(
            ["docker", "system", "df", "-v"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return None
        return _parse_docker_df_verbose(result.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def _parse_docker_df_verbose(text: str) -> dict:
    """
    Parse the human-readable tabular output of `docker system df -v`.
    Returns {"images": [...], "volumes": [...]}.
    """
    images: list[dict] = []
    volumes: list[dict] = []

    section = None
    for line in text.splitlines():
        line_stripped = line.strip()
        if line_stripped.startswith("Images space usage"):
            section = "images"
            continue
        if line_stripped.startswith("Containers space usage"):
            section = "containers"
            continue
        if line_stripped.startswith("Local Volumes space usage"):
            section = "volumes"
            continue
        if line_stripped.startswith("Build cache usage"):
            section = "build_cache"
            continue
        if not line_stripped or line_stripped.startswith("REPOSITORY") or line_stripped.startswith("CONTAINER") or line_stripped.startswith("VOLUME") or line_stripped.startswith("CACHE"):
            continue

        parts = line_stripped.split()
        if not parts:
            continue

        if section == "images" and len(parts) >= 7:
            # REPOSITORY  TAG  IMAGE ID  CREATED  SIZE  SHARED SIZE  UNIQUE SIZE  CONTAINERS
            images.append({
                "repository": parts[0],
                "tag":        parts[1],
                "image_id":   parts[2],
                "size":       parts[4],
                "shared_size": parts[5] if len(parts) > 5 else "",
                "unique_size": parts[6] if len(parts) > 6 else "",
            })
        elif section == "volumes" and len(parts) >= 3:
            # VOLUME NAME  LINKS  SIZE
            volumes.append({
                "name":  parts[0],
                "links": parts[1],
                "size":  parts[2],
            })

    return {"images": images, "volumes": volumes}


def _parse_size(s: str) -> int:
    """
    Parse a Docker human-readable size string to bytes.
    Examples: "1.5GB", "200MB", "0B", "1.2kB".
    Returns 0 on parse failure.
    """
    if not s:
        return 0
    # Docker uses "kB", "MB", "GB", "TB"
    s = s.strip()
    # Strip trailing reclaimable annotation like "200MB (50%)"
    s = s.split("(")[0].strip()
    multipliers = {
        "b":  1,
        "kb": 1_000,
        "mb": 1_000_000,
        "gb": 1_000_000_000,
        "tb": 1_000_000_000_000,
        # IEC units sometimes appear
        "kib": 1_024,
        "mib": 1_048_576,
        "gib": 1_073_741_824,
        "tib": 1_099_511_627_776,
    }
    lower = s.lower()
    for suffix, mult in sorted(multipliers.items(), key=lambda x: -len(x[0])):
        if lower.endswith(suffix):
            try:
                return int(float(lower[: -len(suffix)].strip()) * mult)
            except ValueError:
                return 0
    try:
        return int(float(s))
    except ValueError:
        return 0

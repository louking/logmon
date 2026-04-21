"""
access_analysis.py — Shared logic for access-log analysis features.

Provides:
  - CountryCidrMapper  (lazy singleton; downloads CIDR data once at startup)
  - get_bad_actors()   (queries AccessEvent, annotates with country)
  - get_cpu_metrics()  (wraps DigitalOcean metrics API via dometrics)

Ported / adapted from louking/apache-access-summarizer.
"""

from __future__ import annotations

import logging
import threading
from bisect import bisect_right
from collections import Counter
from datetime import datetime, timezone, timedelta
from io import BytesIO
from ipaddress import IPv4Network, ip_address
from tarfile import TarFile
from typing import TYPE_CHECKING
from sqlalchemy import func

from requests import get as http_get
from requests.exceptions import RequestException

if TYPE_CHECKING:
    from flask import Flask

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Country CIDR mapper — singleton, initialised once per process
# ---------------------------------------------------------------------------

_mapper_lock = threading.Lock()
_mapper: "CountryCidrMapper | None" = None


def get_mapper() -> "CountryCidrMapper":
    """Return the process-wide CountryCidrMapper, creating it on first call."""
    global _mapper
    if _mapper is None:
        with _mapper_lock:
            if _mapper is None:           # double-checked locking
                log.info("CountryCidrMapper: downloading country CIDR data …")
                try:
                    codes = _get_iso_country_codes()
                    _mapper = CountryCidrMapper(codes)
                    log.info("CountryCidrMapper: ready (%d networks)", len(_mapper.NETWORK_MAP))
                except Exception:
                    log.exception("CountryCidrMapper: failed to initialise; country lookup disabled")
                    _mapper = _NullMapper()          # type: ignore[assignment]
    return _mapper


def warm_up_mapper() -> None:
    """Call this from create_app() (in a background thread) so the first
    request to /access doesn't stall while CIDR data downloads."""
    t = threading.Thread(target=get_mapper, daemon=True, name="cidr-mapper-warmup")
    t.start()


class _NullMapper:
    """Fallback when CIDR data can't be loaded."""
    NETWORK_MAP: list = []

    def get_country_from_ip(self, ip: str) -> str:  # noqa: D401
        return "UNKNOWN"


def _get_iso_country_codes() -> list[str]:
    url = "https://datahub.io/core/country-list/_r/-/data.csv"
    from csv import DictReader
    from io import StringIO

    for attempt in range(1, 4):
        try:
            resp = http_get(url, timeout=30)
            resp.raise_for_status()
            rdr = DictReader(StringIO(resp.text))
            return [row["Code"].lower() for row in rdr if "Code" in row]
        except Exception as exc:
            if attempt >= 3:
                raise
            log.warning("ISO country code fetch attempt %d failed: %s", attempt, exc)
    return []


class CountryCidrMapper:
    """Maps IP addresses to ISO country codes using ipdeny.com CIDR blocks.

    Ported from louking/apache-access-summarizer with minor refactoring.
    """

    def __init__(self, country_codes: list[str]) -> None:
        self.NETWORK_MAP: list[tuple[int, IPv4Network, str]] = []
        self._load(country_codes)

    # ------------------------------------------------------------------
    def _load(self, country_codes: list[str]) -> None:
        for attempt in range(1, 4):
            try:
                resp = http_get(
                    "https://www.ipdeny.com/ipblocks/data/countries/all-zones.tar.gz",
                    timeout=120,
                )
                resp.raise_for_status()
                break
            except Exception as exc:
                if attempt >= 3:
                    raise
                log.warning("CIDR tar download attempt %d failed: %s", attempt, exc)

        zones = TarFile.open(fileobj=BytesIO(resp.content), mode="r:gz")
        all_networks: list[tuple[int, IPv4Network, str]] = []

        for code in country_codes:
            try:
                member = zones.extractfile(f"./{code}.zone")
            except KeyError:
                continue
            if member is None:
                continue
            for cidr in member.read().decode("utf-8").strip().splitlines():
                cidr = cidr.strip()
                if not cidr:
                    continue
                try:
                    net = IPv4Network(cidr, strict=False)
                    all_networks.append((int(net.network_address), net, code.upper()))
                except Exception:
                    pass

        self.NETWORK_MAP = sorted(all_networks, key=lambda x: x[0])

    # ------------------------------------------------------------------
    def get_country_from_ip(self, ip: str) -> str:
        try:
            ip_obj = ip_address(ip)
            if ip_obj.version != 4:
                return "IPV6"
            ip_int = int(ip_obj)
            starts = [item[0] for item in self.NETWORK_MAP]
            i = bisect_right(starts, ip_int)
            for j in range(max(0, i - 2), i):
                _, net, code = self.NETWORK_MAP[j]
                if ip_obj in net:
                    return code
        except ValueError:
            return "INVALID"
        return "UNKNOWN"


# ---------------------------------------------------------------------------
# Bad-actor analysis — queries the AccessEvent table
# ---------------------------------------------------------------------------

def _exclude_private_ips(col, extra_ips: list | None = None):
    """Return a list of SQLAlchemy filter clauses that exclude RFC-1918,
    loopback, link-local, and any caller-supplied IPs or CIDR networks.

    Private ranges use LIKE prefix matching (DB-agnostic, no extension needed).
    The 172.16-31 range needs one clause per second-octet value because SQL
    LIKE cannot express numeric ranges.

    extra_ips: IPs or CIDR networks to exclude in addition to private ranges,
               e.g. ["203.0.113.42", "198.51.100.0/24"].  Single IPs may be
               given with or without a /32 suffix.
    """
    from ipaddress import ip_network
    from sqlalchemy import not_, func

    private_prefixes = [
        "127.",           # loopback
        "10.",            # RFC-1918 class A
        "192.168.",       # RFC-1918 class C
        "169.254.",       # link-local
        # RFC-1918 class B: 172.16.0.0 – 172.31.255.255
        *(f"172.{n}." for n in range(16, 32)),
    ]
    clauses = [not_(col.like(f"{prefix}%")) for prefix in private_prefixes]

    for entry in (extra_ips or []):
        entry = entry.strip()
        if not entry:
            continue
        try:
            net = ip_network(entry, strict=False)
        except ValueError:
            log.warning("EXCLUDED_IPS: ignoring invalid entry %r", entry)
            continue
        if net.num_addresses == 1:
            # Single host — simple equality is fastest
            clauses.append(col != str(net.network_address))
        else:
            # Network range — use INET_ATON for numeric comparison so we
            # don't need a DB CIDR extension.  Works on MySQL and MariaDB.
            # For SQLite (dev/test) INET_ATON is unavailable; fall back to
            # generating one != clause per address (only practical for /30+).
            lo = int(net.network_address)
            hi = int(net.broadcast_address)
            inet_aton = func.inet_aton(col)
            clauses.append(
                (inet_aton < lo) | (inet_aton > hi)
            )
    return clauses


def _get_excluded_ips(flask_app) -> list:
    """Return the list of extra IPs/networks to exclude, read from app config.

    Set ``EXCLUDED_IPS`` in your .cfg / environment as a comma-separated
    string of IP addresses or CIDR networks, e.g.::

        EXCLUDED_IPS = 203.0.113.42, 198.51.100.0/24

    Typical use: the server's own public IP address(es) and any monitoring or
    CDN networks that generate high volumes of legitimate traffic and should
    not be flagged as bad actors.
    """
    raw = flask_app.config.get("EXCLUDED_IPS", "")
    if not raw:
        return []
    return [entry.strip() for entry in raw.split(",") if entry.strip()]


def get_bad_actors(
    start: datetime,
    end: datetime,
    flask_app=None,
    threshold: int = 0,
    limit: int = 100,
) -> list[dict]:
    """Return IPs ranked by request count within [start, end].

    Args:
        start:      window start (timezone-aware or naive UTC)
        end:        window end
        threshold:  only return IPs with count >= threshold (0 = all)
        limit:      max rows to return

    Returns list of dicts::

        [
          {
            "ip": "1.2.3.4",
            "count": 512,
            "country": "CN",
            "error_count": 47,
            "paths": ["/wp-login.php", ...],   # top 5 paths
          },
          …
        ]
    """
    from sqlalchemy import func, not_
    from .model import db, AccessEvent  # relative import; works from views package too

    excluded = _get_excluded_ips(flask_app) if flask_app else []

    # --- aggregate by IP, excluding RFC-1918 / loopback private ranges -------
    rows = (
        db.session.query(
            AccessEvent.client_ip,
            func.count(AccessEvent.id).label("count"),
            func.sum(
                db.case((AccessEvent.status_code >= 400, 1), else_=0)
            ).label("error_count"),
        )
        .filter(
            AccessEvent.occurred_at >= start,
            AccessEvent.occurred_at <= end,
            *_exclude_private_ips(AccessEvent.client_ip, excluded),
        )
        .group_by(AccessEvent.client_ip)
        .order_by(func.count(AccessEvent.id).desc())
        .limit(limit * 4)          # fetch more than needed, filter below
        .all()
    )

    mapper = get_mapper()
    result = []

    for row in rows:
        ip = row.client_ip or ""
        count = int(row.count)
        if threshold and count < threshold:
            break        # rows are ordered by count desc, so we can stop early

        # top paths for this IP
        path_rows = (
            db.session.query(
                AccessEvent.path,
                func.count(AccessEvent.id).label("n"),
            )
            .filter(
                AccessEvent.occurred_at >= start,
                AccessEvent.occurred_at <= end,
                AccessEvent.client_ip == ip,
            )
            .group_by(AccessEvent.path)
            .order_by(func.count(AccessEvent.id).desc())
            .limit(5)
            .all()
        )

        result.append(
            {
                "ip": ip,
                "count": count,
                "error_count": int(row.error_count or 0),
                "country": mapper.get_country_from_ip(ip),
                "paths": [r.path for r in path_rows if r.path],
            }
        )
        if len(result) >= limit:
            break

    return result


def get_bad_actors_summary(threshold: int, hours: int = 24, flask_app=None) -> list[dict]:
    """Lightweight version used by the dashboard tile.

    Returns only IPs whose request count in the last `hours` hours
    meets or exceeds `threshold`, sorted by count descending.
    No per-IP path breakdown (avoids N+1 queries on the dashboard).
    """
    from datetime import timedelta
    from sqlalchemy import func
    from .model import db, AccessEvent

    excluded = _get_excluded_ips(flask_app) if flask_app else []

    end = datetime.now(timezone.utc).replace(tzinfo=None)   # naive UTC, matches stored values
    start = end - timedelta(hours=hours)

    rows = (
        db.session.query(
            AccessEvent.client_ip,
            func.count(AccessEvent.id).label("count"),
            func.sum(
                db.case((AccessEvent.status_code >= 400, 1), else_=0)
            ).label("error_count"),
        )
        .filter(
            AccessEvent.occurred_at >= start,
            AccessEvent.occurred_at <= end,
            *_exclude_private_ips(AccessEvent.client_ip, excluded),
        )
        .group_by(AccessEvent.client_ip)
        .having(func.count(AccessEvent.id) >= threshold)
        .order_by(func.count(AccessEvent.id).desc())
        .limit(20)
        .all()
    )

    mapper = get_mapper()
    return [
        {
            "ip": r.client_ip or "",
            "count": int(r.count),
            "error_count": int(r.error_count or 0),
            "country": mapper.get_country_from_ip(r.client_ip or ""),
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# CPU metrics — delegates to dometrics (known-good implementation)
# ---------------------------------------------------------------------------

def get_cpu_metrics(
    flask_app,
    start: datetime,
    end: datetime,
) -> list[dict]:
    """Return CPU utilization data points from DigitalOcean for [start, end].

    Delegates to dometrics.get_droplet_cpu_metrics / metrics2csv, which use
    numpy to correctly diff the cumulative CPU counters returned by the DO API.

    Requires ``DO_API_TOKEN`` and ``DO_HOST_ID`` in app.config.

    Returns a list of ``{"timestamp": <iso-str>, "cpu_pct": <float>}`` dicts
    suitable for Chart.js.  The first data point is always skipped (no prior
    sample to diff against), matching dometrics behaviour.  Returns [] if
    credentials are absent or the API call fails.
    """
    from csv import DictReader
    from io import StringIO
    from .dometrics import get_droplet_cpu_metrics, metrics2csv

    token   = flask_app.config.get("DO_API_TOKEN")
    host_id = flask_app.config.get("DO_HOST_ID")
    if not token or not host_id:
        log.debug("get_cpu_metrics: DO_API_TOKEN / DO_HOST_ID not configured")
        return []

    def _epoch(dt: datetime) -> int:
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())

    try:
        metrics = get_droplet_cpu_metrics(token, int(host_id), _epoch(start), _epoch(end))
        csv_text = metrics2csv(metrics)
    except Exception:
        log.exception("get_cpu_metrics: DigitalOcean API call failed")
        return []

    # metrics2csv produces rows: Time, %CPU, Used (cum msec), Total (cum msec)
    # The first row has %CPU == '' (no prior sample), so we skip it.
    points = []
    for row in DictReader(StringIO(csv_text)):
        cpu_str = row.get("%CPU", "").strip()
        if not cpu_str:
            continue    # first row — no diff available yet
        try:
            points.append({
                "timestamp": row["Time"],
                "cpu_pct":   float(cpu_str),
            })
        except (KeyError, ValueError):
            continue

    return points

# ---------------------------------------------------------------------------
# access rate — retrieves AccessEvent counts bucketed by minute, aligned to CPU timestamps
# ---------------------------------------------------------------------------

def get_access_rate(flask_app, start: datetime, end: datetime, timestamps: list[datetime]) -> list[dict]:
    """
    Count AccessEvent rows bucketed by minute, then align to CPU timestamps.

    Each CPU sample is assigned the maximum per-minute request count across
    all minute buckets that fall within its CPU interval:

    - Sub-minute CPU sampling: interval covers exactly one minute bucket,
      so adjacent samples share the same value (honest flat steps).
    - Super-minute CPU sampling: takes the peak minute within the wider
      interval, avoiding under-reporting during bursty traffic.

    Returns a list of {"timestamp": iso, "req_count": int} parallel to
    `timestamps`.
    """
    if not timestamps:
        return []

    from .model import db, AccessEvent

    # Infer CPU sample interval; fall back to 60 s if only one sample.
    if len(timestamps) > 1:
        interval_secs = int((timestamps[1] - timestamps[0]).total_seconds())
    else:
        interval_secs = 60

    with flask_app.app_context():
        bucket_expr = func.from_unixtime(
            (func.unix_timestamp(AccessEvent.occurred_at) / 60).op('DIV')(1) * 60
        )

        rows = (
            db.session.query(
                bucket_expr.label("bucket"),
                func.count(AccessEvent.id).label("req_count"),
            )
            .filter(AccessEvent.occurred_at >= start, AccessEvent.occurred_at < end)
            .group_by("bucket")
            .order_by("bucket")
            .all()
        )

        count_by_minute: dict[datetime, int] = {}
        for bucket_dt, count in rows:
            if isinstance(bucket_dt, str):
                bucket_dt = datetime.fromisoformat(bucket_dt)
            count_by_minute[bucket_dt] = count

    def _floor_to_minute(dt: datetime) -> datetime:
        return dt.replace(second=0, microsecond=0)

    def _max_in_window(ts: datetime) -> int:
        """Max per-minute count across all minutes within the CPU interval."""
        window_start = _floor_to_minute(ts)
        n_minutes = max(1, interval_secs // 60)
        return max(
            count_by_minute.get(
                window_start + timedelta(minutes=i), 0
            )
            for i in range(n_minutes)
        )

    return [
        {"timestamp": ts.isoformat(), "req_count": _max_in_window(ts)}
        for ts in timestamps
    ]
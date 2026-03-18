"""
logparser.py — Parsers for two log formats produced by the Flask app stack.

App log (*.log)
---------------
Lines emitted by the Flask app's Python logging handler.  Two recognised
shapes, plus a generic fallback:

  HTTP:
    2026-03-07 06:42:30,097 INFO: anonymous 16.58.56.214: GET http://… 404 [in …]

  Exception header (followed by a multi-line traceback):
    2026-03-06 11:20:52,360 ERROR: lking@pobox.com Exception on /admin/x [GET] [in …]
    Traceback (most recent call last):
      ...
    myapp.SomeError: message

Access log (access.log)
-----------------------
Combined Log Format written by nginx (or Apache) in front of the Flask app.
The IP field is a comma-separated X-Forwarded-For chain; the first address is
the real client origin.

  97.238.20.183, 172.28.0.1 - - [12/Mar/2026:15:26:46 -0400] \
      "GET /path HTTP/1.0" 200 83 "https://referer…" "Mozilla/5.0 …"
"""
from __future__ import annotations

import re
from datetime import datetime, timezone, timedelta

# ============================================================== shared helpers

# IPv6 must come first in the alternation: an address like 2001:db8::1 starts
# with digits, so if IPv4 were first the \d{1,3} arm would greedily consume
# "2001" and leave the rest to corrupt the surrounding match.
#
# Three arms, in order:
#   1. IPv4-mapped / IPv4-compatible  e.g. ::ffff:192.168.1.1
#      Dotted-quad tail after a colon — needs its own arm before pure IPv6.
#   2. Pure IPv6 (full or compressed)  e.g. 2001:db8::1, ::1, fe80::1%eth0
#   3. IPv4  e.g. 97.238.20.183
_IP_PATTERN = (
    r"(?:[a-fA-F0-9]{0,4}:){2,6}(?:\d{1,3}\.){3}\d{1,3}"   # IPv4-mapped IPv6
    r"|"
    r"(?:[a-fA-F0-9]{0,4}:){2,7}[a-fA-F0-9]{0,4}(?:%\w+)?" # pure IPv6 + zone ID
    r"|"
    r"(?:\d{1,3}\.){3}\d{1,3}"                                # IPv4
)

# A single captured IP address
_IP = rf"({_IP_PATTERN})"


# ================================================================= App log

_TS    = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+)"
_LEVEL = r"(DEBUG|INFO|WARNING|ERROR|CRITICAL)"
_USER  = r"(\S+)"

RE_APP_HTTP = re.compile(
    rf"^{_TS}\s+{_LEVEL}:\s+{_USER}\s+{_IP}:\s+"
    rf"(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+(\d{{3}})\s+\[in\s+([^\]]+)\]"
)

RE_APP_EXCEPTION = re.compile(
    rf"^{_TS}\s+{_LEVEL}:\s+{_USER}\s+Exception on\s+(\S+)\s+\[(\w+)\]\s+\[in\s+([^\]]+)\]"
)

RE_APP_GENERIC = re.compile(rf"^{_TS}\s+{_LEVEL}:\s+(.*)")

_APP_TS_FMT = "%Y-%m-%d %H:%M:%S,%f"


def _parse_app_ts(s: str) -> datetime:
    return datetime.strptime(s, _APP_TS_FMT)


def parse_app_line(line: str) -> dict | None:
    """
    Parse one line from a Flask app log.
    Returns a structured dict or None if the line is unrecognised.
    """
    m = RE_APP_HTTP.match(line)
    if m:
        ts, level, user, ip, method, url, status, location = m.groups()
        return dict(
            type="http",
            occurred_at=_parse_app_ts(ts),
            level=level,
            user=user,
            ip=ip,
            method=method,
            url=url,
            status_code=int(status),
            location=location,
            message=f"{method} {url} {status}",
        )

    m = RE_APP_EXCEPTION.match(line)
    if m:
        ts, level, user, path, method, location = m.groups()
        return dict(
            type="exception_start",
            occurred_at=_parse_app_ts(ts),
            level=level,
            user=user,
            ip=None,
            method=method,
            url=path,
            status_code=None,
            location=location,
            message=f"Exception on {path} [{method}]",
        )

    m = RE_APP_GENERIC.match(line)
    if m:
        ts, level, msg = m.groups()
        return dict(
            type="generic",
            occurred_at=_parse_app_ts(ts),
            level=level,
            user=None,
            ip=None,
            method=None,
            url=None,
            status_code=None,
            message=msg.strip(),
        )

    return None


def is_new_app_record(line: str) -> bool:
    """True when a line starts a new app-log record (has a leading timestamp)."""
    return bool(RE_APP_GENERIC.match(line.rstrip("\n")))


def extract_exception_type(traceback_text: str) -> str | None:
    """Return the final non-blank line of a traceback (the exception class+msg)."""
    lines = [l.rstrip() for l in traceback_text.splitlines() if l.strip()]
    return lines[-1] if lines else None


# ================================================================= Access log

# nginx Combined Log Format:
#
#   ip_list - - [day/Mon/year:HH:MM:SS ±hhmm] "METHOD path proto" status bytes
#             "referer" "user-agent"
#
# ip_list  – one or more IPs separated by ", " (X-Forwarded-For chain).
#            The first is the real client; the last is the nginx peer (docker).
# referer  – may be "-" when absent.
# bytes    – may be 0 for 304 Not Modified responses.

_ACCESS_TS = r"\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+-]\d{4})\]"
_ACCESS_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"

# IP list: one or more IPs separated by ", "
# We capture the whole list as one group, then split on ", " afterwards.
_IP_LIST = rf"((?:{_IP_PATTERN})(?:,\s*(?:{_IP_PATTERN}))*)"

RE_ACCESS = re.compile(
    rf"^{_IP_LIST}"                                              # ip chain
    rf'\s+-\s+-\s+'                                             # ident, auth (always -)
    rf"{_ACCESS_TS}\s+"                                         # [timestamp]
    rf'"(\w+)\s+(\S+)\s+HTTP/[\d\.]+"'                         # "METHOD path HTTP/x.y"
    rf'\s+(\d{{3}})'                                            # status
    rf'\s+(\d+)'                                                # bytes sent
    rf'\s+"([^"]*)"'                                            # referer
    rf'\s+"([^"]*)"'                                            # user-agent
)


def _parse_access_ts(s: str) -> datetime:
    """Parse nginx timestamp; returns timezone-aware datetime."""
    return datetime.strptime(s, _ACCESS_TS_FMT)


def parse_access_line(line: str) -> dict | None:
    """
    Parse one line from an nginx Combined Format access log.
    Returns a structured dict or None if the line is unrecognised.

    The 'client_ip' field is always the first (leftmost) address in the
    X-Forwarded-For chain — i.e. the real originating client, not the
    Docker network peer.  'ip_chain' preserves the full original list for
    reference.
    """
    m = RE_ACCESS.match(line)
    if not m:
        return None

    ip_chain_raw, ts_raw, method, path, status, nbytes, referer, ua = m.groups()

    # First IP in the chain = real client origin
    ips = [s.strip() for s in ip_chain_raw.split(",")]
    client_ip = ips[0]

    occurred_at = _parse_access_ts(ts_raw)

    return dict(
        type="access",
        occurred_at=occurred_at,
        client_ip=client_ip,
        ip_chain=ip_chain_raw,
        method=method,
        path=path,
        status_code=int(status),
        bytes_sent=int(nbytes),
        referer=referer if referer != "-" else None,
        user_agent=ua if ua != "-" else None,
    )

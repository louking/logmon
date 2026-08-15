# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

logmon is a Flask application that tails logs from multiple Flask apps in a Docker Compose stack, displays them in a dashboard, and emails alerts when new exception types appear. It also monitors disk usage and memory/swap, analyzes access logs for bad actors, and shows CPU utilization via the DigitalOcean API. SNS/SES webhook notifications are displayed alongside log events.

## Commands

### Build and run (Docker Compose)

```bash
docker compose up -d --build         # build and start all services
docker compose up -d                 # start without rebuilding
docker compose logs -f app           # tail app service logs
docker compose logs -f follower      # tail follower service logs
```

Development mode (hot-reload via volume mount in `docker-compose.dev.yml`):
```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --build
```

### Database migrations (inside the container)

```bash
docker compose exec app flask --app app db migrate -m "description"
docker compose exec app flask --app app db upgrade
```

First-time init:
```bash
docker compose exec app flask --app app db init
docker compose exec app flask --app app db migrate -m "init"
docker compose exec app flask --app app db upgrade
```

### User management

```bash
docker compose exec app flask --app app create-user --admin
```

## Architecture

### Services and their roles

| Service | Role |
|---|---|
| `app` | Serves the Flask web UI, SNS webhook, and JSON API. Scaled freely. Uses `app_server.py` as WSGI entrypoint. |
| `follower` | Single-instance daemon that tails log files and collects disk and memory stats. Runs `flask run-follower`. |
| `redis` | Shared ephemeral live-tail buffer between `app` and `follower`. |
| `db` | MySQL. |
| `crond` | Cron jobs for maintenance (backups, log pruning). |
| `web` | nginx reverse proxy + phpMyAdmin. |

`app` and `follower` use the **same Docker image** but different commands. The follower must remain a single instance — scaling it creates duplicate tail threads.

### Two entry points, one app factory

- `app_server.py` — WSGI entrypoint for gunicorn (`init_for_operation=True`, includes ProxyFix).
- `app.py` — Flask CLI entrypoint for `flask` commands only (`init_for_operation=False`, includes Flask-Migrate setup).

Both call `logmon.create_app()` from `logmon/__init__.py`.

### Background threads (follower container only)

`app.py` registers the `flask run-follower` CLI command that starts three daemon thread managers:

- **`FollowerManager`** (`follower.py`) — rescans `LOG_APPS` every 30 seconds and spawns/restarts a `FileFollower` thread per log file. Each `FileFollower` seeks to EOF on start, then tails the file. App logs are parsed for errors/exceptions (multi-line tracebacks are assembled before persisting). Access log lines are parsed and persisted as `AccessEvent` rows. Both kinds push to Redis for the live-tail API.
- **`DiskMonitor`** (`diskmon.py`) — runs `df -P` and `docker system df` every `DISK_CHECK_INTERVAL` seconds. Stores snapshots in Redis and persists to `DiskSnapshot` (DB). Sends suppressed alert emails when a filesystem exceeds `DISK_ALERT_THRESHOLD_PCT`.
- **`MemMonitor`** (`memmon.py`) — reads `/proc/meminfo` every `MEM_CHECK_INTERVAL` seconds. Stores snapshots in Redis and persists to `MemSnapshot` (DB). Sends suppressed alert emails when swap usage exceeds `SWAP_ALERT_THRESHOLD_PCT`. `/proc/meminfo` always reflects the host kernel's memory, not the container's cgroup limit.

### Configuration loading

`settings.py` defines the `AppEntry` dataclass (one per monitored app) and `_load_logapps()` which reads `config/logapps.yml` at startup. The `Production` / `Development` classes read DB credentials from Docker secret files at `/run/secrets/`, injecting passwords into the connection URL so they never appear in environment variables or `docker inspect` output.

### Two databases

| Key | Bind | Tables |
|---|---|---|
| `DATABASE_URL` | default | `LogEvent`, `AccessEvent`, `AlertSuppression`, `SnsNotification`, `DiskSnapshot`, `MemSnapshot` |
| `USERS_DATABASE_URL` | `users` | `User`, `Role` — shared with other apps, managed externally |

Flask-Migrate only runs against the default DB. The `db` object is imported from `loutilities.user.model`, not created locally — this is why `model.py` imports `db` from loutilities.

### Alert suppression

Log alerts, disk alerts, and swap alerts all share the `AlertSuppression` table. Disk alerts use `app_name="diskmon"` with `exception_type` set to the mount-point string. Swap alerts use `app_name="memmon"` with `exception_type="swap"`. This allows the same suppress-and-reset logic to work for all three.

### Access analysis

`access_analysis.py` queries the `AccessEvent` table directly — no aggregation job needed. On startup, `warm_up_mapper()` downloads CIDR-to-country data from ipdeny.com in a background thread. Private/RFC-1918 ranges are automatically excluded from bad-actor results.

### Adding a monitored app

Two files must be updated in sync:
1. `docker-compose.override.yml` — add a bind mount under `follower: volumes:` (container path is arbitrary but must match step 2).
2. `config/logapps.yml` — add an entry with `log_dir:` set to the container-side path from step 1.

The FollowerManager picks up new files within 30 seconds without a restart.

### Gitignored config files

- `docker-compose.override.yml` — host bind-mounts and environment variables (copy from `.example`)
- `config/logapps.yml` — monitored app definitions (copy from `.example`)
- `config/*.txt` — Docker secret files (Flask secret key, DB passwords, SMTP password, SNS webhook key)

## Tests

```bash
pytest
```

Run from the repo root; `pytest.ini` puts `app/src` on `sys.path` (`testpaths = test`). `test/conftest.py` sets `APP_NAME`/`APP_VER` (normally supplied by Docker Compose's `.env`) since `logmon/__init__.py`/`version.py` read them at import time — same pattern as `members`'/`contracts`' `test/conftest.py` (see those repos' `CLAUDE.md`).

**No `create_app()`/`app`/`dbapp`/`client` fixtures — this suite is intentionally bare-app-only.** `create_app()` unconditionally queries the `Application` table for `g.loutility` (the same ordering gotcha documented in `members`'/`contracts`' `CLAUDE.md`), spawns a real background thread that hits the network (`access_analysis.warm_up_mapper()`), and wires up Flask-Assets/Flask-Mail/Flask-Security — none of it needed to exercise the module-level logic this suite targets. `test/conftest.py`'s `bareapp`/`bare_dbapp` fixtures are a bare `Flask('logmon')` with just `logmon.model.db` bound (default bind + the `users` bind, since `loutilities.user.model.Application`/`Interest`/`User`/`Role` share it) and `db.create_all()` run directly — unlike `members`, logmon's own tables have no MySQL-only `server_default`, so no sqlite-incompatible-table exclusion set is needed. Blueprint/view code (`views/*.py`, all built on `loutilities`' `DbCrudApiInterestsRolePermissions`/`MethodView` machinery) is not covered by this suite, same exclusion rationale as `members`.

Coverage by module:
- **`logparser.py`** — both log grammars (`parse_app_line`'s `http`/`exception_start`/`traceback_start`/`generic` shapes, `parse_access_line`'s nginx Combined Format), plus `is_new_app_record`/`extract_exception_type`, entirely pure-function, no fixtures needed.
- **`alerter.py`** — `send_alert`/`send_disk_alert`/`send_mem_alert`. `loutilities.flask_helpers.mailer.sendmail` is imported *inside* each alerter function body, not at module scope, so tests patch `loutilities.flask_helpers.mailer.sendmail` directly (patching `logmon.alerter.sendmail` would not take effect, since the import re-resolves the attribute on every call) — same re-import-per-call pattern shows up in `access_analysis.get_cpu_metrics` (patch target `logmon.dometrics.*`, not `logmon.access_analysis.*`).
- **`settings.py`** — `AppEntry` (`app_log`'s `False`/`"false"`-string/`None`/filename normalisation, absolute-vs-relative path resolution), `_read_secret`, `_inject_password`, `_load_logapps` (YAML parsing via `monkeypatch.setattr(settings, 'LOGAPPS_PATH', ...)`).
- **`model.py`** — `to_dict()` on each model, and `AlertSuppression`'s `(app_name, exception_type)` unique constraint (the mechanism shared by log/disk/swap alert suppression).
- **`diskmon.py`** — `_parse_size`, `_parse_docker_df_verbose`, `_collect_df` in both fallback and host (`/host/` bind-mount) modes (`subprocess.run`/`os.path.isdir`/`_get_fstype` monkeypatched), `DiskMonitor._maybe_alert` suppression window, `_check_alerts`, `_store_db`.
- **`memmon.py`** — `_read_proc_meminfo` (via `monkeypatch.setattr(memmon, 'open', ..., raising=False)`, since `/proc/meminfo` is opened directly with no module-level indirection), `_build_mem`/`_build_swap`, `MemMonitor._maybe_alert`/`_check_alerts`/`_store_db`.
- **`access_analysis.py`** — `CountryCidrMapper.get_country_from_ip` (built via `object.__new__` with a hand-set `NETWORK_MAP`, bypassing `__init__`'s real CIDR download), `_get_iso_country_codes` (mocked `http_get`), `_exclude_private_ips` (the CIDR-range extra-IP branch uses MySQL-only `func.inet_aton()` — checked structurally via compiled-SQL text rather than executed against sqlite; the single-host branch is exercised end-to-end), `get_bad_actors`/`get_bad_actors_summary` against a real sqlite `AccessEvent` table with `get_mapper()` patched to a fixed fake, `get_cpu_metrics`. `get_access_rate()` is excluded — it also relies on MySQL-only `func.unix_timestamp()`/`from_unixtime()`.
- **`follower.py`** — `get_tail`/`get_all_tails` and `FileFollower._push_redis` against `test/fakeredis_client.py`'s `FakeRedis` (patched in everywhere via `follower._get_redis`, which `diskmon.py`/`memmon.py` also import fresh per call — patching it once covers all three), `FileFollower._persist_app_event`/`_persist_access_event`/`_maybe_alert` (including the per-app `alert_suppress_seconds` override), and `FollowerManager._ensure_follower`'s start/rotation/dead-thread logic with `FileFollower` swapped for an in-test dummy class (real threads are never started).
- **`dometrics.py`** — `metrics2csv`'s cumulative-counter diffing (including the numpy `0/0 → NaN → skip-row` case when two samples share identical cumulative totals).

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

logmon is a Flask application that tails logs from multiple Flask apps in a Docker Compose stack, displays them in a dashboard, and emails alerts when new exception types appear. It also monitors disk usage, analyzes access logs for bad actors, and shows CPU utilization via the DigitalOcean API. SNS/SES webhook notifications are displayed alongside log events.

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
| `follower` | Single-instance daemon that tails log files and collects disk stats. Runs `flask run-follower`. |
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

`app.py` registers the `flask run-follower` CLI command that starts two daemon thread managers:

- **`FollowerManager`** (`follower.py`) — rescans `LOG_APPS` every 30 seconds and spawns/restarts a `FileFollower` thread per log file. Each `FileFollower` seeks to EOF on start, then tails the file. App logs are parsed for errors/exceptions (multi-line tracebacks are assembled before persisting). Access log lines are parsed and persisted as `AccessEvent` rows. Both kinds push to Redis for the live-tail API.
- **`DiskMonitor`** (`diskmon.py`) — runs `df -P` and `docker system df` every `DISK_CHECK_INTERVAL` seconds. Stores snapshots in Redis and persists to `DiskSnapshot` (DB). Sends suppressed alert emails when a filesystem exceeds `DISK_ALERT_THRESHOLD_PCT`.

### Configuration loading

`settings.py` defines the `AppEntry` dataclass (one per monitored app) and `_load_logapps()` which reads `config/logapps.yml` at startup. The `Production` / `Development` classes read DB credentials from Docker secret files at `/run/secrets/`, injecting passwords into the connection URL so they never appear in environment variables or `docker inspect` output.

### Two databases

| Key | Bind | Tables |
|---|---|---|
| `DATABASE_URL` | default | `LogEvent`, `AccessEvent`, `AlertSuppression`, `SnsNotification`, `DiskSnapshot` |
| `USERS_DATABASE_URL` | `users` | `User`, `Role` — shared with other apps, managed externally |

Flask-Migrate only runs against the default DB. The `db` object is imported from `loutilities.user.model`, not created locally — this is why `model.py` imports `db` from loutilities.

### Alert suppression

Both log alerts and disk alerts share the `AlertSuppression` table. Disk alerts use `app_name="diskmon"` with `exception_type` set to the mount-point string. This allows the same suppress-and-reset logic to work for both.

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

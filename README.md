# logmon

A Flask application that tails logs from multiple Flask apps in a Docker
Compose stack, displays them in a dashboard, and emails alerts when new
exception types appear. Access logs (nginx or Apache Combined Log Format) are also tailed and stored
for traffic/firewall analysis. SNS/SES notifications are received via webhook
and shown alongside the log events.

---

## Repository layout

```
logmon/
├── docker-compose.yml               # main stack (committed)
├── docker-compose.override.yml      # secrets + log mounts (gitignored)
├── docker-compose.override.yml.example
├── .gitignore
├── config/
│   ├── logapps.yml                  # app-name → log-dir map (gitignored)
│   └── logapps.yml.example
└── app/
    ├── Dockerfile
    └── src/
        ├── app_server.py            # WSGI entry point for gunicorn
        ├── app.py                   # application factory + CLI commands
        ├── settings.py              # configuration + AppEntry dataclass
        ├── model.py                 # SQLAlchemy models (merge into your own)
        ├── follower.py              # background log-tail threads + Redis buffer
        ├── diskmon.py               # background disk + Docker usage monitor
        ├── logparser.py             # app log + access log parsers
        ├── alerter.py               # email alert sender
        ├── access_analysis.py       # bad-actor queries + CPU metrics wrapper
        ├── dometrics.py             # DigitalOcean CPU metrics API client
        ├── requirements.txt
        ├── views/
        │   ├── auth.py              # super-admin role check
        │   ├── dashboard.py
        │   ├── disk.py              # disk detail + history views
        │   ├── logs.py
        │   ├── sns.py
        │   ├── api.py               # JSON API for live tail, stats, and disk usage
        │   └── access.py            # bad-actor report + CPU utilization views
        ├── templates/
        │   ├── base.jinja2
        │   ├── dashboard.jinja2
        │   ├── disk_detail.jinja2
        │   ├── disk_history.jinja2
        │   ├── live_tail.jinja2
        │   ├── logs_index.jinja2
        │   ├── app_log.jinja2
        │   ├── event_detail.jinja2
        │   ├── sns.jinja2
        │   ├── 403.jinja2
        │   ├── access/
        │   ├── bad_actors.jinja2
        │   ├── cpu.jinja2
        │   └── (security/ templates provided by loutilities)
        └── static/
            └── css/
                └── main.css
```

---

## Services

| Service | Purpose |
| --- | --- |
| `app` | Serves the dashboard UI, SNS webhook, live-tail API, and access-analysis pages |
| `follower` | Tails log files; pushes lines to Redis and events to DB; collects disk usage stats |
| `redis` | Shared live-tail ring buffer between `app` and `follower` |
| `db` | MySQL database (replace stub with your own service definition) |

`app` and `follower` use the same Docker image but different commands.
`follower` is always a single instance — scaling it would create duplicate
tail threads. `app` can be scaled freely.

---

## First-time setup

### 1. Create the gitignored config files

```bash
cp docker-compose.override.yml.example docker-compose.override.yml
cp config/logapps.yml.example config/logapps.yml
```

Edit both files:

**`docker-compose.override.yml`** — fill in non-secret environment variables:

* `DATABASE_URL` — logmon's own MySQL DB (username and host only, no password)
* `USERS_DATABASE_URL` — shared users DB reachable via the `users` Docker network
* `REDIS_URL` — defaults to `redis://redis:6379/0`, matching the compose service name
* SMTP settings (`MAIL_SERVER`, `MAIL_USERNAME`, etc.), `ALERT_RECIPIENTS`, and optionally `ALERT_FROM` (dedicated sender address for alert emails; falls back to `MAIL_DEFAULT_SENDER`)
* `DO_API_TOKEN` — DigitalOcean personal access token (required for CPU utilization charts)
* `DO_HOST_ID` — integer droplet ID shown in the DigitalOcean control panel (required for CPU utilization charts)
* `BAD_ACTOR_THRESHOLD` — minimum requests in the window before an IP appears in the dashboard alert tile (default: `200`)
* `BAD_ACTOR_WINDOW_HOURS` — how many hours back the dashboard tile looks (default: `24`)
* `EXCLUDED_IPS` — comma-separated list of IP addresses or CIDR networks to exclude from bad-actor analysis entirely (e.g. the server's own public IP or a CDN/monitoring network). Both single IPs (`203.0.113.42`) and networks (`198.51.100.0/24`) are accepted.
* `volumes:` under `follower:` — one bind mount per monitored app:

  ```
  - /opt/apps/myapp/logs:/logs/myapp:ro
  ```

  On Windows with spaces in the path, quote the whole string:

  ```
  - "C:/Users/you/My Apps/myapp/logs:/logs/myapp:ro"
  ```

**Disk monitoring** — the `follower` service collects disk and Docker usage
stats every 60 seconds and shows them on the dashboard. The disk detail page
(`/disk/detail`) breaks down usage by filesystem and Docker component
(images, volumes, build cache). The disk history page (`/disk/history`)
charts usage over time for each filesystem and Docker component.

Because `diskmon` runs inside the container, it can only see filesystems that
are mounted into the `follower` container. To monitor real host volumes, add
read-only bind mounts under a `/host/` prefix in `docker-compose.override.yml`:

```yaml
follower:
  volumes:
    - /:/host/root:ro            # monitor host /
    - /mnt/data:/host/mnt/data:ro   # monitor host /mnt/data
```

`diskmon` detects the `/host/` prefix and strips it for display, so `/host/root`
appears as `/` in the dashboard.

To enable Docker image and volume stats, also mount the Docker socket and
ensure the `docker-cli` package is installed in the image (it is, by default):

```yaml
# Linux
- /var/run/docker.sock:/var/run/docker.sock:ro

# Windows (Docker Desktop) — use the named pipe with forward-slash syntax:
- //./pipe/docker_engine:/var/run/docker.sock
```

If the socket is absent, filesystem stats still work but Docker breakdowns
are omitted.

The following environment variables control disk monitoring behaviour
(all optional, defaults shown):

| Variable | Default | Meaning |
|---|---|---|
| `DISK_ALERT_THRESHOLD_PCT` | `85` | % used at which an alert email is sent |
| `DISK_ALERT_SUPPRESS_SECONDS` | `14400` | seconds between repeat alerts for the same mount (4 h); overrides `ALERT_SUPPRESS_SECONDS` for disk alerts |
| `DISK_CHECK_INTERVAL` | `60` | seconds between collection runs |
| `DISK_SNAPSHOT_HISTORY` | `1440` | snapshots kept in Redis (24 h at 1-per-min) |
| `DISK_EXCLUDE_MOUNTS` | _(none)_ | comma-separated mount points to hide from the UI and suppress alerts for (e.g. `/boot,/boot/efi`) |

**Secret files** — create these before running `docker compose up`.
All are gitignored. Generate random values with:
`python -c "import secrets; print(secrets.token_hex(32))"`

| File | Contents |
| --- | --- |
| `config/secret-key.txt` | Flask `SECRET_KEY` |
| `config/security-password-salt.txt` | Flask-Security password salt |
| `config/mail-password.txt` | SMTP password |
| `config/snswebhook-key.txt` | SNS webhook shared secret |
| `config/db/root-password.txt` | MySQL root password |
| `config/db/appdb-password.txt` | MySQL password for the logmon user |
| `config/db/users-password.txt` | MySQL password for the shared users DB user |

Passwords are injected into DB connection strings at startup from the secret
files, so they never appear in environment variables (which are visible via
`docker inspect`).

**`config/logapps.yml`** — one entry per app, using the container-side path:

```yaml
apps:
  myapp:
    log_dir: /logs/myapp
    # Optional overrides:
    # app_log: myapp.log          # default: {appname}.log  (bare name joined to log_dir)
    # access_log: access.log      # default: access.log     (bare name joined to log_dir)
    # access_log: /var/log/apache2/myapp_access.log  # absolute path — used as-is
    # alert_suppress_seconds: 1800
```

The follower expects two files per app directory:

* `{appname}.log` — Flask app log (parsed for errors and exceptions)
* `access.log` — Apache or nginx Combined Log Format access log (parsed for traffic analysis)

### 2. Create the external Docker network (once, on the host)

```bash
docker network create users
```

The `users` network connects logmon to your shared users DB. In the other
stack's `docker-compose.yml`:

```yaml
networks:
  users:
    external: true
    name: users
```

### 3. Build and start

```bash
docker compose up -d --build
```

### 4. Run database migrations (logmon DB only)

First run — initialise the migrations folder:

```bash
docker compose exec app flask --app app db init
docker compose exec app flask --app app db migrate -m "init"
docker compose exec app flask --app app db upgrade
```

Subsequent runs after model changes:

```bash
docker compose exec app flask --app app db migrate -m "description"
docker compose exec app flask --app app db upgrade
```

> The **users DB is never migrated by logmon** — it is managed by your
> other apps. logmon only reads and writes User/Role rows there.

### 5. Create your first user

Users must hold the **`super-admin`** role to access logmon.

```bash
docker compose exec app flask --app app create-user --admin
# Enter email and password at the prompts
# --admin assigns the super-admin role
```

### 6. Open the dashboard

Navigate to `http://yourhost:8000` (or whatever port your nginx exposes).

---

## Adding a new monitored app

1. Add a bind mount in `docker-compose.override.yml` under `follower: volumes:`:

   ```yaml
   - /opt/apps/newapp/logs:/logs/newapp:ro
   ```
2. Add an entry in `config/logapps.yml`:

   ```yaml
   apps:
     newapp:
       log_dir: /logs/newapp
   ```
3. `docker compose up -d` — the FollowerManager re-scans every 30 s and picks
   up the new files automatically without a restart.

---

## Live tail

The live-tail page polls `/api/tail/<app_name>` every 2 seconds. Lines are
pushed to Redis by the `follower` service and read back by the `app` service,
so the tail works correctly across the two separate processes.

Two Redis keys are maintained per app — `logmon:tail:{app_name}:app` and
`logmon:tail:{app_name}:access` — stored newest-first as JSON lists, each
capped at `LOG_TAIL_LINES` entries (default 500). The live-tail page lets
you switch between the two. The data is ephemeral — Redis has no persistence
configured, so the tail resets if Redis restarts.

---

## SNS webhook

Point your SNS HTTP/HTTPS subscription at:

```
POST https://yourhost/sns/webhook
```

The app auto-confirms `SubscriptionConfirmation` requests. All subsequent
`Notification` POSTs are stored (deduplicated by `MessageId`) and shown at
`/sns/`. The webhook endpoint does not require login or the super-admin role,
but is protected by a shared secret key.

The key is read from `config/snswebhook-key.txt`. Include it as a query
parameter when creating the SNS HTTP subscription:

```
https://yourhost/sns/webhook?key=<contents of snswebhook-key.txt>
```

SNS will include the `?key=` parameter in every POST it makes. Requests
with a missing or incorrect key are rejected with 403. If the secret file
is empty the key check is disabled (development only).

Restrict accepted topic ARNs via `SNS_TOPIC_ARNS` in `docker-compose.override.yml`.

---

## Alert suppression

When an exception type is seen for the first time in an app, an email is sent
to `ALERT_RECIPIENTS`. Further occurrences of the **same exception type in the
same app** are suppressed for `ALERT_SUPPRESS_SECONDS` (default 3600 s = 1 h).

After the suppression window expires the next occurrence triggers a fresh email.

Per-app override in `config/logapps.yml`:

```yaml
apps:
  noisyapp:
    log_dir: /logs/noisyapp
    alert_suppress_seconds: 7200   # 2 hours for this app
```

Disk usage alerts use a separate suppression window controlled by
`DISK_ALERT_SUPPRESS_SECONDS` (default 14400 s = 4 h) so that a nearly-full
disk does not flood the same inbox as application exceptions. If
`DISK_ALERT_SUPPRESS_SECONDS` is not set, `ALERT_SUPPRESS_SECONDS` is used
as a fallback.

---

## Disk usage

The **Disk Usage** page (`/disk/detail`) shows:

* **Filesystems** — mount point, device, total/used/available size, and a
  colour-coded usage bar (green → yellow → red as usage approaches
  `DISK_ALERT_THRESHOLD_PCT`).
* **Docker** — aggregated sizes for images, containers, volumes, and build
  cache, with reclaimable amounts shown separately.
* **Images** — per-image repository, tag, and size breakdown.
* **Volumes** — per-volume name and size, sorted largest to smallest.

A summary tile on the dashboard shows the same filesystem bars and a Docker
totals strip, refreshed every 60 seconds.

### Alert emails

An alert email is sent to `ALERT_RECIPIENTS` when any monitored filesystem
reaches `DISK_ALERT_THRESHOLD_PCT` percent used. Repeat alerts for the same
mount are suppressed for `DISK_ALERT_SUPPRESS_SECONDS` (default 4 h).

### Disk history

The **Disk History** page (`/disk/history`) charts filesystem usage percentage
and Docker component sizes over the last 7 or 30 days. Each filesystem gets
its own chart with a dashed threshold line at `DISK_ALERT_THRESHOLD_PCT`.
The Docker chart overlays images, volumes, build cache, and container sizes
on a single chart.

History data is stored in the `disk_snapshot` table (one row per filesystem
per collection run, plus a `__docker__` sentinel row for Docker totals). The
`/api/disk/history` endpoint exposes this data directly:

```
GET /api/disk/history?hours=168          # all filesystems, last 7 days
GET /api/disk/history?mount=/&hours=720  # single mount, last 30 days
GET /api/disk/history?docker=1&hours=168 # Docker totals, last 7 days
```

Rows accumulate indefinitely. To purge data older than 90 days:

```sql
DELETE FROM disk_snapshot WHERE collected_at < NOW() - INTERVAL 90 DAY;
```

---

## Bad actor analysis

The **Bad Actors** page (`/access/`) identifies IP addresses making unusually
high numbers of requests in a chosen time window — useful for building firewall
block lists. Private/internal IP ranges (RFC-1918, loopback, link-local) are
automatically excluded so internal health-checks and proxy traffic don't appear
in the results.

### Configuration

```yaml
environment:
  BAD_ACTOR_THRESHOLD: 200            # requests in window before flagging
  BAD_ACTOR_WINDOW_HOURS: 24          # look-back window for dashboard tile
  EXCLUDED_IPS: 203.0.113.42, 198.51.100.0/24   # IPs or CIDR networks to exclude
```

### Using the page

1. Set a **From / To** window (or use the 1 h / 6 h / 24 h / 3 d / 7 d shortcuts).
2. Set a **Min requests** threshold — only IPs meeting or exceeding this count
   are shown.
3. Click **Analyse**.

Results show each IP's total request count, 4xx/5xx error count, country of
origin, and the top 5 paths requested. Columns are sortable by clicking their
headers.

### iptables export

The page generates a ready-to-run shell script of `iptables -I INPUT -s <ip> -j DROP`
commands covering all flagged IPs. To target specific IPs only, tick their
checkboxes — the script updates immediately. Click **Copy** to put it on the
clipboard, then paste and run it on your server.

To make rules permanent after running the script (Debian/Ubuntu):

```
iptables-save > /etc/iptables/rules.v4
```

### Dashboard alert tile

If any external IP exceeds `BAD_ACTOR_THRESHOLD` requests within the last
`BAD_ACTOR_WINDOW_HOURS` hours, a red alert tile appears on the dashboard
showing the top offenders with a link to the full report. The tile is hidden
when no IPs breach the threshold. It refreshes every 30 seconds alongside the
other dashboard panels.

Configure the threshold, window, and excluded IPs in `docker-compose.override.yml`
as shown in the Configuration section above.

### Country lookup

Country codes are resolved from IP addresses using CIDR block data downloaded
from [ipdeny.com](https://www.ipdeny.com/) at startup. The download (~100 MB)
runs in a background thread so the first page load is not delayed. If the
download fails, country codes fall back to `UNKNOWN` and all other
functionality continues normally.

---

## CPU utilization

The **CPU Utilization** page (`/access/cpu`) displays a time-series chart of
server CPU usage fetched from the DigitalOcean monitoring API. It requires
`DO_API_TOKEN` and `DO_HOST_ID` to be set (see configuration above).

### Using the page

1. Set a **From / To** window (or use the quick-range shortcuts).
2. Click **Load**.

The chart shows CPU % over time. On multi-day windows, the x-axis labels
include the date (`Mar 25 / 14:32`) at each displayed tick. Hovering anywhere
over the chart shows a tooltip with the exact timestamp and CPU percentage for
the nearest data point — the cursor does not need to be directly over the line.

Summary tiles show average CPU, peak CPU, and the number of data points in the
window.

If `DO_API_TOKEN` or `DO_HOST_ID` are not configured, the page shows a
warning and returns no data. No error is raised so the rest of the application
is unaffected.

> **How CPU % is calculated:** The DigitalOcean API returns cumulative
> CPU milliseconds per mode (idle, user, system, …). logmon diffs consecutive
> samples and computes `(used[i] − used[i−1]) / (total[i] − total[i−1]) × 100`,
> which matches the methodology used by the DigitalOcean control panel. The
> first sample in each window is skipped as there is no prior value to diff
> against.

---

## Access control

All views except `/sns/webhook` require:

1. Login via Flask-Security-Too
2. The `super-admin` role on the authenticated user

Users without the role see a 403 page with a sign-out link. The required role
name is defined as `REQUIRED_ROLE` in `views/auth.py` — change it there if your
project uses a different name.

---

## Database architecture

| Database | Bind key | Models |
| --- | --- | --- |
| `DATABASE_URL` | (default) | `LogEvent`, `AccessEvent`, `AlertSuppression`, `SnsNotification`, `DiskSnapshot` |
| `USERS_DATABASE_URL` | `users` | `User`, `Role` — shared with other apps |

Flask-Migrate runs only against the default DB. The `model.py` file provided
contains both groups of models — merge the logmon-specific ones into your
existing `model.py` and remove the `from app import db` import line since `db`
will already be in scope.

The `AccessEvent` table is populated by the `follower` service as it tails
access logs. Both the bad-actor report and the dashboard tile query this table
directly — no separate aggregation job is needed. For large deployments,
adding a composite index on `(occurred_at, client_ip)` will improve query
performance:

```sql
CREATE INDEX ix_access_event_time_ip
    ON access_event (occurred_at, client_ip);
```

The `DiskSnapshot` table stores one row per filesystem per collection run, plus
a `__docker__` sentinel row for Docker totals. Rows accumulate indefinitely;
see [Disk history](#disk-history) above for purge instructions.

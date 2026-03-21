# logmon

A Flask application that tails logs from multiple Flask apps in a Docker
Compose stack, displays them in a dashboard, and emails alerts when new
exception types appear.  nginx access logs are also tailed and stored for
traffic/firewall analysis.  SNS/SES notifications are received via webhook
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
        ├── wsgi.py                  # WSGI entry point + CLI commands
        ├── app.py                   # application factory
        ├── config.py                # all configuration + AppEntry dataclass
        ├── model.py                 # SQLAlchemy models (merge into your own)
        ├── follower.py              # background log-tail threads + Redis buffer
        ├── logparser.py             # app log + access log parsers
        ├── alerter.py               # email alert sender
        ├── requirements.txt
        ├── views/
        │   ├── auth.py              # super-admin role check
        │   ├── dashboard.py
        │   ├── logs.py
        │   ├── sns.py
        │   └── api.py               # JSON API for live tail
        ├── templates/
        │   ├── base.jinja2
        │   ├── dashboard.jinja2
        │   ├── live_tail.jinja2
        │   ├── logs_index.jinja2
        │   ├── app_log.jinja2
        │   ├── event_detail.jinja2
        │   ├── sns.jinja2
        │   ├── 403.jinja2
        │   └── security/
        │       └── login_user.jinja2
        └── static/
            └── css/
                └── main.css
```

---

## Services

| Service | Purpose |
|---------|---------|
| `app` | Serves the dashboard UI, SNS webhook, and live-tail API |
| `follower` | Tails log files; pushes lines to Redis and events to DB |
| `redis` | Shared live-tail ring buffer between `app` and `follower` |
| `db` | MySQL database (replace stub with your own service definition) |

`app` and `follower` use the same Docker image but different commands.
`follower` is always a single instance — scaling it would create duplicate
tail threads.  `app` can be scaled freely.

---

## First-time setup

### 1. Create the gitignored config files

```bash
cp docker-compose.override.yml.example docker-compose.override.yml
cp config/logapps.yml.example config/logapps.yml
```

Edit both files:

**`docker-compose.override.yml`** — fill in:
- `SECRET_KEY` and `SECURITY_PASSWORD_SALT`
  (generate with `python -c "import secrets; print(secrets.token_hex(32))"`)
- `DATABASE_URL` — logmon's own MySQL DB
- `USERS_DATABASE_URL` — shared users DB reachable via the `users` Docker network
- `REDIS_URL` — defaults to `redis://redis:6379/0`, matching the compose service name
- SMTP settings and `ALERT_RECIPIENTS`
- `volumes:` under `follower:` — one bind mount per monitored app:
  ```yaml
  - /opt/apps/myapp/logs:/logs/myapp:ro
  ```
  On Windows with spaces in the path, quote the whole string:
  ```yaml
  - "C:/Users/you/My Apps/myapp/logs:/logs/myapp:ro"
  ```

**`config/logapps.yml`** — one entry per app, using the container-side path:
```yaml
apps:
  myapp:
    log_dir: /logs/myapp
    # Optional overrides:
    # app_log: myapp.log          # default: {appname}.log
    # access_log: access.log      # default: access.log
    # alert_suppress_seconds: 1800
```

The follower expects two files per app directory:
- `{appname}.log` — Flask app log (parsed for errors and exceptions)
- `access.log` — nginx Combined Format access log (parsed for traffic analysis)

### 2. Create the external Docker network (once, on the host)

```bash
docker network create users
```

The `users` network connects logmon to your shared users DB.  In the other
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
docker compose exec app flask db init
docker compose exec app flask db migrate -m "init"
docker compose exec app flask db upgrade
```

Subsequent runs after model changes:
```bash
docker compose exec app flask db migrate -m "description"
docker compose exec app flask db upgrade
```

> The **users DB is never migrated by logmon** — it is managed by your
> other apps.  logmon only reads and writes User/Role rows there.

### 5. Create your first user

Users must hold the **`super-admin`** role to access logmon.

```bash
docker compose exec app flask create-user --admin
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

The live-tail page polls `/api/tail/<app_name>` every 2 seconds.  Lines are
pushed to Redis by the `follower` service and read back by the `app` service,
so the tail works correctly across the two separate processes.

The Redis key is `logmon:tail:{app_name}`, stored newest-first as a JSON list
capped at `LOG_TAIL_LINES` entries (default 500).  The data is ephemeral —
Redis has no persistence configured, so the tail resets if Redis restarts.

---

## SNS webhook

Point your SNS HTTP/HTTPS subscription at:

```
POST https://yourhost/sns/webhook
```

The app auto-confirms `SubscriptionConfirmation` requests.  All subsequent
`Notification` POSTs are stored (deduplicated by `MessageId`) and shown at
`/sns/`.  The webhook endpoint is intentionally public — it does not require
login or the super-admin role.

Restrict accepted topic ARNs via `SNS_TOPIC_ARNS` in `docker-compose.override.yml`.

---

## Alert suppression

When an exception type is seen for the first time in an app, an email is sent
to `ALERT_RECIPIENTS`.  Further occurrences of the **same exception type in the
same app** are suppressed for `ALERT_SUPPRESS_SECONDS` (default 3600 s = 1 h).

After the suppression window expires the next occurrence triggers a fresh email.

Per-app override in `config/logapps.yml`:
```yaml
apps:
  noisyapp:
    log_dir: /logs/noisyapp
    alert_suppress_seconds: 7200   # 2 hours for this app
```

---

## Access control

All views except `/sns/webhook` require:
1. Login via Flask-Security-Too
2. The `super-admin` role on the authenticated user

Users without the role see a 403 page with a sign-out link.  The required role
name is defined as `REQUIRED_ROLE` in `views/auth.py` — change it there if your
project uses a different name.

---

## Database architecture

| Database | Bind key | Models |
|----------|----------|--------|
| `DATABASE_URL` | (default) | `LogEvent`, `AccessEvent`, `AlertSuppression`, `SnsNotification` |
| `USERS_DATABASE_URL` | `users` | `User`, `Role` — shared with other apps |

Flask-Migrate runs only against the default DB.  The `model.py` file provided
contains both groups of models — merge the logmon-specific ones (`LogEvent`,
`AccessEvent`, `AlertSuppression`, `SnsNotification`) into your existing
`model.py` and remove the `from app import db` import line since `db` will
already be in scope.

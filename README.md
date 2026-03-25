# logmon

A Flask application that tails logs from multiple Flask apps in a Docker
Compose stack, displays them in a dashboard, and emails alerts when new
exception types appear.  Access logs (nginx or Apache Combined Log Format) are also tailed and stored
for traffic/firewall analysis.  SNS/SES notifications are received via webhook
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
        │   └── (security/ templates provided by loutilities)
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

**`docker-compose.override.yml`** — fill in non-secret environment variables:
- `DATABASE_URL` — logmon's own MySQL DB (username and host only, no password)
- `USERS_DATABASE_URL` — shared users DB reachable via the `users` Docker network
- `REDIS_URL` — defaults to `redis://redis:6379/0`, matching the compose service name
- SMTP settings (`MAIL_SERVER`, `MAIL_USERNAME`, etc.), `ALERT_RECIPIENTS`, and optionally `ALERT_FROM` (dedicated sender address for alert emails; falls back to `MAIL_DEFAULT_SENDER`)
- `volumes:` under `follower:` — one bind mount per monitored app:
  ```yaml
  - /opt/apps/myapp/logs:/logs/myapp:ro
  ```
  On Windows with spaces in the path, quote the whole string:
  ```yaml
  - "C:/Users/you/My Apps/myapp/logs:/logs/myapp:ro"
  ```

**Secret files** — create these before running `docker compose up`.
All are gitignored.  Generate random values with:
`python -c "import secrets; print(secrets.token_hex(32))"`

| File | Contents |
|------|----------|
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
- `{appname}.log` — Flask app log (parsed for errors and exceptions)
- `access.log` — Apache or nginx Combined Log Format access log (parsed for traffic analysis)

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
> other apps.  logmon only reads and writes User/Role rows there.

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

The live-tail page polls `/api/tail/<app_name>` every 2 seconds.  Lines are
pushed to Redis by the `follower` service and read back by the `app` service,
so the tail works correctly across the two separate processes.

Two Redis keys are maintained per app — `logmon:tail:{app_name}:app` and
`logmon:tail:{app_name}:access` — stored newest-first as JSON lists, each
capped at `LOG_TAIL_LINES` entries (default 500).  The live-tail page lets
you switch between the two.  The data is ephemeral — Redis has no persistence
configured, so the tail resets if Redis restarts.

---

## SNS webhook

Point your SNS HTTP/HTTPS subscription at:

```
POST https://yourhost/sns/webhook
```

The app auto-confirms `SubscriptionConfirmation` requests.  All subsequent
`Notification` POSTs are stored (deduplicated by `MessageId`) and shown at
`/sns/`.  The webhook endpoint does not require login or the super-admin role,
but is protected by a shared secret key.

The key is read from `config/snswebhook-key.txt`.  Include it as a query
parameter when creating the SNS HTTP subscription:

```
https://yourhost/sns/webhook?key=<contents of snswebhook-key.txt>
```

SNS will include the `?key=` parameter in every POST it makes.  Requests
with a missing or incorrect key are rejected with 403.  If the secret file
is empty the key check is disabled (development only).

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

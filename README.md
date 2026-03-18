# logmon

A Flask application that tails logs from multiple Flask apps in a Docker
Compose stack, displays them in a dashboard, and emails alerts when new
exception types appear.  SNS/SES notifications are received via webhook and
shown alongside the log events.

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
        ├── app_server.py
        ├── app.py
        ├── config.py
        ├── model.py
        ├── follower.py
        ├── parser.py
        ├── alerter.py
        ├── requirements.txt
        ├── views/
        │   ├── dashboard.py
        │   ├── logs.py
        │   ├── sns.py
        │   └── api.py
        ├── templates/
        └── static/
```

---

## First-time setup

### 1. Create the gitignored config files

```bash
cp docker-compose.override.yml.example docker-compose.override.yml
cp config/logapps.yml.example config/logapps.yml
```

Edit both files:

**`docker-compose.override.yml`** — fill in:
- `SECRET_KEY` and `SECURITY_PASSWORD_SALT` (use `python -c "import secrets; print(secrets.token_hex(32))"`)
- `DATABASE_URL` — logmon's own Postgres (defined in `docker-compose.yml`)
- `USERS_DATABASE_URL` — connection string for the shared users DB, reachable
  via the external `users` Docker network (e.g. `postgresql://user:pass@usersdb/users`)
- SMTP settings and `ALERT_RECIPIENTS`
- `volumes:` — add one bind mount per monitored app:
  ```yaml
  - /opt/apps/myapp/logs:/logs/myapp:ro
  ```

**`config/logapps.yml`** — one entry per app, matching the container-side mount path:
```yaml
apps:
  myapp:
    log_dir: /logs/myapp
```

<!-- ### 2. Create the external Docker network (once, on the host)

The `users` network must already exist before you bring the stack up.  If your
users DB lives in another Compose stack, that stack's `docker-compose.yml`
should declare it as a named network and you create it once:

```bash
docker network create users
```

Then in the other stack's `docker-compose.yml`:
```yaml
networks:
  users:
    external: true
    name: users
``` -->

### 3. Build and start

```bash
docker compose up -d --build
```

### 4. Run database migrations (logmon DB only)

```bash
docker compose exec app flask db upgrade
```

On first run you also need to initialise the migrations folder:
```bash
docker compose exec app flask db init
docker compose exec app flask db migrate -m "init"
docker compose exec app flask db upgrade
```

> The **users DB is never migrated by logmon** — it is managed by your
> other apps.  logmon only reads and writes User/Role rows there via
> Flask-Security-Too.

### 5. Create your first user

```bash
docker compose exec app flask create-user --admin
# Enter email and password at the prompts
```

### 6. Open the dashboard

Navigate to `http://yourhost:8000` (or whatever port you expose).

---

## Adding a new monitored app

1. Bind-mount its log directory in `docker-compose.override.yml`:
   ```yaml
   volumes:
     - /opt/apps/newapp/logs:/logs/newapp:ro
   ```
2. Add it to `config/logapps.yml`:
   ```yaml
   apps:
     newapp:
       log_dir: /logs/newapp
   ```
3. `docker compose up -d` — the FollowerManager re-scans every 30 s and will
   pick up the new directory automatically without a full restart.

---

## SNS webhook

Point your SNS HTTP/HTTPS subscription at:

```
POST https://yourhost/sns/webhook
```

The app auto-confirms the `SubscriptionConfirmation` request.  All subsequent
`Notification` POSTs are stored (deduplicated by `MessageId`) and shown at
`/sns/`.

Restrict accepted topic ARNs via `SNS_TOPIC_ARNS` in `docker-compose.override.yml`.

---

## Alert suppression

When an exception type is seen for the first time in an app, an email is sent
to `ALERT_RECIPIENTS`.  Further occurrences of the **same exception type in the
same app** are suppressed for `ALERT_SUPPRESS_SECONDS` (default 3600 s = 1 h).

After the suppression window expires the next occurrence triggers a fresh email.

You can override the window per-app in `config/logapps.yml`:
```yaml
apps:
  noisyapp:
    log_dir: /logs/noisyapp
    alert_suppress_seconds: 7200   # 2 hours for this app
```

---

## Two-database architecture

| Database | Bind key | Purpose |
|----------|----------|---------|
| `DATABASE_URL` | (default) | LogEvent, AlertSuppression, SnsNotification |
| `USERS_DATABASE_URL` | `users` | User, Role — shared with other apps |

Flask-Migrate is configured to run **only against the default DB**.  The users
DB schema is owned by your other apps; logmon never runs migrations on it.

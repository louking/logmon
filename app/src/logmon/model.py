'''
model - database models for application
===========================================
'''

# standard
from datetime import datetime
from collections import OrderedDict

# pypi
from flask import g
from sqlalchemy import text
from sqlalchemy.schema import FetchedValue
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy import func

# home grown
# need to use a single SQLAlchemy() instance, so pull from loutilities.user.model
from loutilities.user.model import db, LocalUserMixin, ManageLocalTables, EMAIL_LEN
from loutilities.user.tablefiles import FilesMixin

# set up database - SQLAlchemy() must be done after app.config SQLALCHEMY_* assignments
Table = db.Table
Index = db.Index
Column = db.Column
Integer = db.Integer
Float = db.Float
Boolean = db.Boolean
String = db.String
Text = db.Text
Date = db.Date
Time = db.Time
DateTime = db.DateTime
Sequence = db.Sequence
Enum = db.Enum
Interval = db.Interval
UniqueConstraint = db.UniqueConstraint
ForeignKey = db.ForeignKey
relationship = db.relationship
backref = db.backref
object_mapper = db.object_mapper
func = db.func
Base = db.Model

class LogEvent(Base):
    """Persisted log event — errors and exceptions only."""
    __tablename__ = "log_event"

    id = db.Column(db.Integer, primary_key=True)
    app_name = db.Column(db.String(128), nullable=False, index=True)
    occurred_at = db.Column(db.DateTime, nullable=False, index=True)
    level = db.Column(db.String(16), nullable=False)
    user = db.Column(db.String(255))
    ip = db.Column(db.String(64))
    method = db.Column(db.String(16))
    url = db.Column(db.String(1024))
    status_code = db.Column(db.Integer)
    message = db.Column(db.Text)
    traceback = db.Column(db.Text)
    exception_type = db.Column(db.String(512), index=True)
    created_at = db.Column(db.DateTime, default=datetime.now)

    def to_dict(self):
        return {
            "id": self.id,
            "app_name": self.app_name,
            "occurred_at": self.occurred_at.isoformat() if self.occurred_at else None,
            "level": self.level,
            "user": self.user,
            "ip": self.ip,
            "method": self.method,
            "url": self.url,
            "status_code": self.status_code,
            "message": self.message,
            "traceback": self.traceback,
            "exception_type": self.exception_type,
        }


class AlertSuppression(Base):
    """Tracks when we last emailed about a particular (app, exception_type) pair."""
    __tablename__ = "alert_suppression"

    id = db.Column(db.Integer, primary_key=True)
    app_name = db.Column(db.String(128), nullable=False)
    exception_type = db.Column(db.String(512), nullable=False)
    last_alerted_at = db.Column(db.DateTime, nullable=False)

    __table_args__ = (
        db.UniqueConstraint("app_name", "exception_type", name="uq_app_exc"),
    )


class SnsNotification(Base):
    __tablename__ = "sns_notification"

    id = db.Column(db.Integer, primary_key=True)
    received_at = db.Column(db.DateTime, default=datetime.now, index=True)
    notification_type = db.Column(db.String(64))
    topic_arn = db.Column(db.String(512))
    subject = db.Column(db.String(512))
    message = db.Column(db.Text)
    message_id = db.Column(db.String(256), unique=True)
    raw_payload = db.Column(db.Text)

    def to_dict(self):
        return {
            "id": self.id,
            "received_at": self.received_at.isoformat(),
            "notification_type": self.notification_type,
            "topic_arn": self.topic_arn,
            "subject": self.subject,
            "message": self.message,
            "message_id": self.message_id,
        }

class AccessEvent(Base):
    """One line from an access log."""
    __tablename__ = "access_event"

    id = db.Column(db.Integer, primary_key=True)
    app_name = db.Column(db.String(128), nullable=False, index=True)
    occurred_at = db.Column(db.DateTime, nullable=False, index=True)
    client_ip = db.Column(db.String(64), index=True)   # first IP in X-Forwarded-For
    ip_chain = db.Column(db.String(256))               # full forwarded chain
    method = db.Column(db.String(16))
    path = db.Column(db.Text)
    status_code = db.Column(db.Integer, index=True)
    bytes_sent = db.Column(db.Integer)
    referer = db.Column(db.String(1024))
    user_agent = db.Column(db.String(512))
    created_at = db.Column(db.DateTime, default=datetime.now)

    def to_dict(self):
        return {
            "id": self.id,
            "app_name": self.app_name,
            "occurred_at": self.occurred_at.isoformat() if self.occurred_at else None,
            "client_ip": self.client_ip,
            "ip_chain": self.ip_chain,
            "method": self.method,
            "path": self.path,
            "status_code": self.status_code,
            "bytes_sent": self.bytes_sent,
            "referer": self.referer,
            "user_agent": self.user_agent,
        }

class DiskSnapshot(Base):
    """
    One persisted disk-usage sample per filesystem (or Docker sentinel) per
    collection run.

    Real filesystem rows
    --------------------
    mount, device, total_kb, used_kb, avail_kb, use_pct are populated.
    docker_* columns are NULL.

    Docker sentinel row  (mount == "__docker__")
    --------------------------------------------
    device / total_kb / used_kb / avail_kb / use_pct are NULL.
    docker_* columns are populated with the aggregated Docker totals.
    images / volumes detail is intentionally NOT stored here — it is
    verbose and already available on demand via `docker system df -v`.

    Retention
    ---------
    Rows accumulate over time.  Add a periodic purge if needed — e.g. keep only
    the last 90 days.  A future flask CLI command `flask disk-purge --days 90`
    could do this.  For now, operators can run:

        DELETE FROM disk_snapshot WHERE collected_at < NOW() - INTERVAL 90 DAY;

    """
    __tablename__ = "disk_snapshot"

    id           = db.Column(db.Integer, primary_key=True)
    collected_at = db.Column(db.DateTime, nullable=False, index=True,
                             default=datetime.now)

    # ---- real filesystem columns (NULL on __docker__ sentinel row) ----
    mount    = db.Column(db.String(512), nullable=False, index=True)
    device   = db.Column(db.String(256))
    total_kb = db.Column(db.BigInteger)
    used_kb  = db.Column(db.BigInteger)
    avail_kb = db.Column(db.BigInteger)
    use_pct  = db.Column(db.Integer)          # 0-100

    # ---- Docker sentinel columns (NULL on real filesystem rows) ----
    docker_images_size_bytes              = db.Column(db.BigInteger)
    docker_images_reclaimable_bytes       = db.Column(db.BigInteger)
    docker_images_active                  = db.Column(db.Integer)
    docker_containers_size_bytes          = db.Column(db.BigInteger)
    docker_containers_active              = db.Column(db.Integer)
    docker_volumes_count                  = db.Column(db.Integer)
    docker_volumes_size_bytes             = db.Column(db.BigInteger)
    docker_volumes_reclaimable_bytes      = db.Column(db.BigInteger)
    docker_build_cache_size_bytes         = db.Column(db.BigInteger)
    docker_build_cache_reclaimable_bytes  = db.Column(db.BigInteger)

    __table_args__ = (
        # Enforce at most one row per (mount, collected_at) so that re-runs
        # within the same second don't duplicate data.
        db.UniqueConstraint("mount", "collected_at", name="uq_disk_mount_ts"),
    )

    def to_dict(self) -> dict:
        return {
            "id":           self.id,
            "collected_at": self.collected_at.isoformat() if self.collected_at else None,
            "mount":        self.mount,
            "device":       self.device,
            "total_kb":     self.total_kb,
            "used_kb":      self.used_kb,
            "avail_kb":     self.avail_kb,
            "use_pct":      self.use_pct,
            "docker": {
                "images_size_bytes":             self.docker_images_size_bytes,
                "images_reclaimable_bytes":      self.docker_images_reclaimable_bytes,
                "images_active":                 self.docker_images_active,
                "containers_size_bytes":         self.docker_containers_size_bytes,
                "containers_active":             self.docker_containers_active,
                "volumes_count":                 self.docker_volumes_count,
                "volumes_size_bytes":            self.docker_volumes_size_bytes,
                "volumes_reclaimable_bytes":     self.docker_volumes_reclaimable_bytes,
                "build_cache_size_bytes":        self.docker_build_cache_size_bytes,
                "build_cache_reclaimable_bytes": self.docker_build_cache_reclaimable_bytes,
            } if self.mount == "__docker__" else None,
        }

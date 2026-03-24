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

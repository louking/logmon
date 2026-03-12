'''
models - database models for application
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

class LogEntry(Base):
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=func.now())
    source = Column(String(100))
    content = Column(Text)
    is_error = Column(Boolean, default=False)

class SNSEvent(Base):
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=func.now())
    content = Column(Text)
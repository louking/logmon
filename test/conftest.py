import os

import pytest
from flask import Flask

# APP_NAME/APP_VER are normally supplied by Docker Compose's .env; set them here so
# logmon.version (read at import time) and logmon/__init__.py (appname = environ['APP_NAME'])
# also work for local/CI pytest runs -- same pattern as members' test/conftest.py.
os.environ.setdefault('APP_NAME', 'logmon')
os.environ.setdefault('APP_VER', '0.0.0')

from logmon.model import db

from fakeredis_client import FakeRedis


@pytest.fixture
def fake_redis():
    """A fresh in-memory Redis stand-in; see fakeredis_client.py."""
    return FakeRedis()


# logmon.create_app() is not used by this suite: it unconditionally queries the
# Application table (for g.loutility, same gotcha documented in members/contracts'
# CLAUDE.md), spawns a real background thread that hits the network
# (access_analysis.warm_up_mapper), and wires up Flask-Assets/Flask-Mail/Flask-Security.
# None of that is needed to exercise the module-level logic this suite targets --
# a bare Flask app with just logmon.model.db bound is enough (see bareapp/bare_dbapp).
@pytest.fixture
def bareapp():
    """Minimal Flask app with logmon's db bound, no blueprints/extensions registered."""
    app = Flask('logmon')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    # loutilities.user.model.Application/Interest/User/Role share logmon's db object via the 'users' bind
    app.config['SQLALCHEMY_BINDS'] = {'users': 'sqlite:///:memory:'}
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['TESTING'] = True
    db.init_app(app)
    yield app


@pytest.fixture
def bare_dbapp(bareapp):
    """bareapp fixture with a fresh in-memory database created for the test."""
    with bareapp.app_context():
        db.create_all()
        yield bareapp

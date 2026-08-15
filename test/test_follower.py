'''
test_follower - test logmon.follower
=========================================================
'''

import json
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from logmon import follower
from logmon.follower import get_tail, get_all_tails, FileFollower, FollowerManager
from logmon.model import db, AlertSuppression, LogEvent, AccessEvent
from logmon.settings import AppEntry


@pytest.fixture
def redis_patched(monkeypatch, fake_redis):
    """Patches follower._get_redis everywhere it's imported from (diskmon.py
    and memmon.py both do `from .follower import _get_redis` fresh on every
    call, so patching the attribute here covers them too)."""
    monkeypatch.setattr(follower, '_get_redis', lambda flask_app=None: fake_redis)
    return fake_redis


# ----------------------------------------------------------------------
# get_tail / get_all_tails
# ----------------------------------------------------------------------

def test_get_tail_returns_newest_first_decoded_entries(redis_patched):
    key = follower.REDIS_KEY_PREFIX + 'myapp:app'
    redis_patched.lpush(key, json.dumps({'message': 'first'}))
    redis_patched.lpush(key, json.dumps({'message': 'second'}))   # pushed after -> newest

    items = get_tail('myapp', n=10, kind='app')
    assert [i['message'] for i in items] == ['second', 'first']


def test_get_tail_wraps_undecodable_entries(redis_patched):
    key = follower.REDIS_KEY_PREFIX + 'myapp:app'
    redis_patched.lpush(key, 'not json')

    items = get_tail('myapp', n=10, kind='app')
    assert items == [{'raw': 'not json', 'level': '', 'occurred_at': '', 'message': 'not json'}]


def test_get_all_tails_groups_by_app_and_filters_by_kind(redis_patched):
    redis_patched.lpush(follower.REDIS_KEY_PREFIX + 'app1:app', json.dumps({'message': 'a1'}))
    redis_patched.lpush(follower.REDIS_KEY_PREFIX + 'app2:app', json.dumps({'message': 'a2'}))
    redis_patched.lpush(follower.REDIS_KEY_PREFIX + 'app1:access', json.dumps({'message': 'access-only'}))

    result = get_all_tails(n=10, kind='app')
    assert set(result) == {'app1', 'app2'}
    assert result['app1'][0]['message'] == 'a1'


# ----------------------------------------------------------------------
# FileFollower._push_redis
# ----------------------------------------------------------------------

def _new_follower(flask_app, app_name='myapp', filepath='/logs/myapp/myapp.log', parser='app', app_cfg=None):
    return FileFollower(app_name, filepath, parser, app_cfg, flask_app)


def test_push_redis_app_line_extracts_level_and_message(bareapp, redis_patched):
    ff = _new_follower(bareapp)
    line = '2026-03-07 06:42:30,097 INFO: anonymous 16.58.56.214: GET /x 200 [in v.py:1]'
    ff._push_redis(line, 'app')

    key = follower.REDIS_KEY_PREFIX + 'myapp:app'
    entry = json.loads(redis_patched.lrange(key, 0, -1)[0])
    assert entry['raw'] == line
    assert entry['level'] == 'INFO'
    assert entry['message'] == 'GET /x 200'


def test_push_redis_unrecognised_app_line_falls_back_to_truncated_raw(bareapp, redis_patched):
    ff = _new_follower(bareapp)
    ff._push_redis('totally unparseable line', 'app')

    key = follower.REDIS_KEY_PREFIX + 'myapp:app'
    entry = json.loads(redis_patched.lrange(key, 0, -1)[0])
    assert entry['level'] == ''
    assert entry['message'] == 'totally unparseable line'


def test_push_redis_access_line_builds_summary_message(bareapp, redis_patched):
    ff = _new_follower(bareapp, parser='access')
    line = '97.238.20.183 - - [12/Mar/2026:15:26:46 -0400] "GET /path HTTP/1.0" 200 83 "-" "-"'
    ff._push_redis(line, 'access')

    key = follower.REDIS_KEY_PREFIX + 'myapp:access'
    entry = json.loads(redis_patched.lrange(key, 0, -1)[0])
    assert entry['message'] == '97.238.20.183 GET /path 200'


# ----------------------------------------------------------------------
# FileFollower persistence
# ----------------------------------------------------------------------

@pytest.fixture
def flask_app_for_follower(bare_dbapp):
    bare_dbapp.config['ALERT_SUPPRESS_SECONDS'] = 3600
    return bare_dbapp


def test_persist_app_event_with_traceback_creates_logevent_and_alerts(flask_app_for_follower, monkeypatch):
    calls = []
    monkeypatch.setattr('logmon.alerter.send_alert', lambda *a, **k: calls.append(a))

    app_cfg = AppEntry(name='myapp', log_dir='/logs/myapp')
    ff = _new_follower(flask_app_for_follower, app_cfg=app_cfg)
    event = dict(occurred_at=datetime(2026, 3, 6, 11, 20, 52), level='ERROR',
                 user='lking@pobox.com', method='GET', url='/x', status_code=None,
                 message='Exception on /x [GET]')
    tb = 'Traceback (most recent call last):\nValueError: boom'

    ff._persist_app_event(event, tb)

    row = LogEvent.query.one()
    assert row.app_name == 'myapp'
    assert row.exception_type == 'ValueError: boom'
    assert row.traceback == tb
    assert len(calls) == 1
    assert AlertSuppression.query.filter_by(app_name='myapp', exception_type='ValueError: boom').count() == 1


def test_persist_app_event_without_traceback_does_not_alert(flask_app_for_follower, monkeypatch):
    calls = []
    monkeypatch.setattr('logmon.alerter.send_alert', lambda *a, **k: calls.append(a))

    app_cfg = AppEntry(name='myapp', log_dir='/logs/myapp')
    ff = _new_follower(flask_app_for_follower, app_cfg=app_cfg)
    event = dict(occurred_at=datetime.now(), level='ERROR', message='single-line error')

    ff._persist_app_event(event, '')

    row = LogEvent.query.one()
    assert row.exception_type is None
    assert calls == []


def test_persist_app_event_alert_suppressed_within_window(flask_app_for_follower, monkeypatch):
    calls = []
    monkeypatch.setattr('logmon.alerter.send_alert', lambda *a, **k: calls.append(a))

    app_cfg = AppEntry(name='myapp', log_dir='/logs/myapp')
    ff = _new_follower(flask_app_for_follower, app_cfg=app_cfg)
    tb = 'Traceback (most recent call last):\nValueError: boom'
    event = dict(occurred_at=datetime.now(), level='ERROR', message='x')

    ff._persist_app_event(dict(event), tb)
    ff._persist_app_event(dict(event), tb)   # same exception type, still within window

    assert len(calls) == 1
    assert LogEvent.query.count() == 2   # both events persisted; only the alert is suppressed


def test_persist_app_event_uses_app_cfg_alert_suppress_seconds_override(flask_app_for_follower, monkeypatch):
    # app_cfg.alert_suppress_seconds, when set, wins over the global
    # ALERT_SUPPRESS_SECONDS -- set the global impossibly high and the
    # per-app override to 0 so a second alert fires immediately.
    flask_app_for_follower.config['ALERT_SUPPRESS_SECONDS'] = 999999
    calls = []
    monkeypatch.setattr('logmon.alerter.send_alert', lambda *a, **k: calls.append(a))

    app_cfg = AppEntry(name='myapp', log_dir='/logs/myapp', alert_suppress_seconds=0)
    ff = _new_follower(flask_app_for_follower, app_cfg=app_cfg)
    tb = 'Traceback (most recent call last):\nValueError: boom'
    event = dict(occurred_at=datetime.now(), level='ERROR', message='x')

    ff._persist_app_event(dict(event), tb)
    ff._persist_app_event(dict(event), tb)

    assert len(calls) == 2


def test_persist_access_event_creates_accessevent(flask_app_for_follower):
    ff = _new_follower(flask_app_for_follower, parser='access')
    parsed = dict(occurred_at=datetime(2026, 3, 12, 15, 26, 46), client_ip='97.238.20.183',
                  ip_chain='97.238.20.183', method='GET', path='/foo', status_code=200,
                  bytes_sent=83, referer=None, user_agent='Mozilla/5.0')

    ff._persist_access_event(parsed)

    row = AccessEvent.query.one()
    assert row.app_name == 'myapp'
    assert row.client_ip == '97.238.20.183'
    assert row.path == '/foo'


# ----------------------------------------------------------------------
# FollowerManager._ensure_follower — start/rotation/skip logic
# ----------------------------------------------------------------------

def _make_dummy_follower_cls():
    class DummyFollower:
        instances = []

        def __init__(self, app_name, filepath, parser, app_cfg, flask_app):
            self.app_name = app_name
            self.filepath = filepath
            self.parser = parser
            self.app_cfg = app_cfg
            self.flask_app = flask_app
            self.inode = None
            self.started = False
            self.stopped = False
            self._alive = True
            DummyFollower.instances.append(self)

        def start(self):
            self.started = True

        def is_alive(self):
            return self._alive and not self.stopped

        def stop(self):
            self.stopped = True

    return DummyFollower


def os_stat_ino(path):
    import os
    return os.stat(path).st_ino


@pytest.fixture
def manager(bareapp, monkeypatch):
    DummyFollower = _make_dummy_follower_cls()
    monkeypatch.setattr(follower, 'FileFollower', DummyFollower)
    mgr = FollowerManager(bareapp)
    mgr.DummyFollower = DummyFollower   # stash for assertions
    return mgr


def test_ensure_follower_skips_disabled_path(manager):
    manager._ensure_follower('', 'app', SimpleNamespace(name='myapp'))
    assert manager.DummyFollower.instances == []
    assert manager._followers == {}


def test_ensure_follower_skips_missing_file(manager, monkeypatch, tmp_path):
    missing = str(tmp_path / 'does-not-exist.log')
    manager._ensure_follower(missing, 'app', SimpleNamespace(name='myapp'))
    assert manager.DummyFollower.instances == []


def test_ensure_follower_starts_new_follower_for_existing_file(manager, tmp_path):
    logfile = tmp_path / 'myapp.log'
    logfile.write_text('hello\n')

    manager._ensure_follower(str(logfile), 'app', SimpleNamespace(name='myapp'))

    assert len(manager.DummyFollower.instances) == 1
    f = manager.DummyFollower.instances[0]
    assert f.started is True
    assert manager._followers[str(logfile)] is f


def test_ensure_follower_does_not_restart_alive_follower_with_same_inode(manager, tmp_path, monkeypatch):
    logfile = tmp_path / 'myapp.log'
    logfile.write_text('hello\n')
    path = str(logfile)

    manager._ensure_follower(path, 'app', SimpleNamespace(name='myapp'))
    first = manager.DummyFollower.instances[0]
    first.inode = os_stat_ino(path)

    manager._ensure_follower(path, 'app', SimpleNamespace(name='myapp'))

    assert len(manager.DummyFollower.instances) == 1   # no second follower created
    assert manager._followers[path] is first


def test_ensure_follower_restarts_on_log_rotation(manager, tmp_path, monkeypatch):
    logfile = tmp_path / 'myapp.log'
    logfile.write_text('hello\n')
    path = str(logfile)

    manager._ensure_follower(path, 'app', SimpleNamespace(name='myapp'))
    first = manager.DummyFollower.instances[0]
    first.inode = os_stat_ino(path)

    # simulate rotation: os.stat() now reports a different inode for the same path
    monkeypatch.setattr(follower.os, 'stat', lambda p: SimpleNamespace(st_ino=first.inode + 1))

    manager._ensure_follower(path, 'app', SimpleNamespace(name='myapp'))

    assert first.stopped is True
    assert len(manager.DummyFollower.instances) == 2
    assert manager._followers[path] is manager.DummyFollower.instances[1]


def test_ensure_follower_restarts_dead_follower(manager, tmp_path):
    logfile = tmp_path / 'myapp.log'
    logfile.write_text('hello\n')
    path = str(logfile)

    manager._ensure_follower(path, 'app', SimpleNamespace(name='myapp'))
    first = manager.DummyFollower.instances[0]
    first._alive = False   # thread crashed

    manager._ensure_follower(path, 'app', SimpleNamespace(name='myapp'))

    assert len(manager.DummyFollower.instances) == 2


def test_scan_starts_followers_for_each_configured_app(manager, tmp_path):
    applog = tmp_path / 'myapp.log'
    applog.write_text('x\n')
    accesslog = tmp_path / 'access.log'
    accesslog.write_text('x\n')

    entry = AppEntry(name='myapp', log_dir=str(tmp_path))
    manager.flask_app.config['LOG_APPS'] = [entry]

    manager._scan()

    paths_seen = {f.filepath for f in manager.DummyFollower.instances}
    assert paths_seen == {str(applog), str(accesslog)}


def test_scan_skips_app_log_when_disabled(manager, tmp_path):
    accesslog = tmp_path / 'access.log'
    accesslog.write_text('x\n')

    entry = AppEntry(name='wpapp', log_dir=str(tmp_path), app_log=False)
    manager.flask_app.config['LOG_APPS'] = [entry]

    manager._scan()

    parsers_seen = {(f.filepath, f.parser) for f in manager.DummyFollower.instances}
    assert parsers_seen == {(str(accesslog), 'access')}

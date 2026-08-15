'''
test_model - test logmon.model
=========================================================
'''

from datetime import datetime

import pytest
from sqlalchemy.exc import IntegrityError

from logmon.model import db, LogEvent, SnsNotification, AccessEvent, DiskSnapshot, AlertSuppression


# ----------------------------------------------------------------------
# to_dict()
# ----------------------------------------------------------------------

def test_logevent_to_dict_formats_occurred_at_iso():
    ev = LogEvent(id=1, app_name='myapp', occurred_at=datetime(2026, 3, 6, 11, 20, 52),
                  level='ERROR', exception_type='ValueError: boom')
    d = ev.to_dict()
    assert d['occurred_at'] == '2026-03-06T11:20:52'
    assert d['app_name'] == 'myapp'
    assert d['exception_type'] == 'ValueError: boom'


def test_logevent_to_dict_none_occurred_at():
    ev = LogEvent(id=1, app_name='myapp', occurred_at=None, level='ERROR')
    assert ev.to_dict()['occurred_at'] is None


def test_snsnotification_to_dict():
    n = SnsNotification(id=1, received_at=datetime(2026, 1, 1), notification_type='Notification',
                         topic_arn='arn:aws:sns:x', subject='hi', message='body', message_id='mid-1')
    d = n.to_dict()
    assert d['received_at'] == '2026-01-01T00:00:00'
    assert d['message_id'] == 'mid-1'


def test_accessevent_to_dict():
    ae = AccessEvent(id=1, app_name='myapp', occurred_at=datetime(2026, 3, 12, 15, 26, 46),
                      client_ip='97.238.20.183', path='/foo', status_code=200)
    d = ae.to_dict()
    assert d['occurred_at'] == '2026-03-12T15:26:46'
    assert d['client_ip'] == '97.238.20.183'
    assert d['path'] == '/foo'


def test_disksnapshot_to_dict_real_filesystem_row_has_no_docker_block():
    snap = DiskSnapshot(id=1, collected_at=datetime(2026, 1, 1), mount='/', device='/dev/sda1',
                         total_kb=1000, used_kb=500, avail_kb=500, use_pct=50)
    d = snap.to_dict()
    assert d['mount'] == '/'
    assert d['use_pct'] == 50
    assert d['docker'] is None


def test_disksnapshot_to_dict_docker_sentinel_row_has_docker_block():
    snap = DiskSnapshot(id=1, collected_at=datetime(2026, 1, 1), mount='__docker__',
                         docker_images_size_bytes=1000, docker_volumes_count=3)
    d = snap.to_dict()
    assert d['docker'] is not None
    assert d['docker']['images_size_bytes'] == 1000
    assert d['docker']['volumes_count'] == 3
    # real-filesystem-only fields are meaningless on the sentinel row
    assert d['total_kb'] is None


# ----------------------------------------------------------------------
# AlertSuppression uniqueness — shared by log/disk/memory alert suppression
# ----------------------------------------------------------------------

def test_alertsuppression_enforces_unique_app_and_exception_type(bare_dbapp):
    now = datetime.now()
    db.session.add(AlertSuppression(app_name='myapp', exception_type='ValueError', last_alerted_at=now))
    db.session.commit()

    db.session.add(AlertSuppression(app_name='myapp', exception_type='ValueError', last_alerted_at=now))
    with pytest.raises(IntegrityError):
        db.session.commit()
    db.session.rollback()


def test_alertsuppression_allows_same_exception_type_for_different_app(bare_dbapp):
    now = datetime.now()
    db.session.add(AlertSuppression(app_name='app1', exception_type='ValueError', last_alerted_at=now))
    db.session.add(AlertSuppression(app_name='app2', exception_type='ValueError', last_alerted_at=now))
    db.session.commit()   # must not raise

    assert AlertSuppression.query.count() == 2

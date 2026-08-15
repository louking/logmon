'''
test_alerter - test logmon.alerter

alerter.py calls `from loutilities.flask_helpers.mailer import sendmail` inside
each function body (not at module scope), so patching the attribute on
loutilities.flask_helpers.mailer directly -- rather than on logmon.alerter --
is what actually takes effect, since the import re-resolves that attribute on
every call.
'''

import re
from datetime import datetime

import pytest
from flask import Flask

from logmon.alerter import send_alert, send_disk_alert, send_mem_alert
from logmon.model import LogEvent


@pytest.fixture
def flask_app():
    app = Flask('logmon-test')
    app.config['ALERT_RECIPIENTS'] = ['ops@example.com']
    app.config['MAIL_DEFAULT_SENDER'] = 'logmon@example.com'
    return app


@pytest.fixture
def sent(monkeypatch):
    """Records every call to loutilities.flask_helpers.mailer.sendmail."""
    calls = []

    def fake_sendmail(subject, fromaddr, toaddr, html, text='', **kwargs):
        calls.append(dict(subject=subject, fromaddr=fromaddr, toaddr=toaddr,
                           html=html, text=text))

    monkeypatch.setattr('loutilities.flask_helpers.mailer.sendmail', fake_sendmail)
    return calls


# ----------------------------------------------------------------------
# send_alert
# ----------------------------------------------------------------------

def _make_event(**overrides):
    defaults = dict(
        app_name='myapp',
        occurred_at=datetime(2026, 3, 6, 11, 20, 52),
        level='ERROR',
        user='lking@pobox.com',
        method='GET',
        url='/admin/x',
        exception_type='ValueError: bad thing happened',
        traceback='Traceback (most recent call last):\nValueError: bad thing happened',
    )
    defaults.update(overrides)
    return LogEvent(**defaults)


def test_send_alert_skips_when_no_recipients(flask_app, sent):
    flask_app.config['ALERT_RECIPIENTS'] = []
    send_alert(flask_app, _make_event())
    assert sent == []


def test_send_alert_skips_when_recipients_are_blank_strings(flask_app, sent):
    flask_app.config['ALERT_RECIPIENTS'] = ['', '  ']
    send_alert(flask_app, _make_event())
    assert sent == []


def test_send_alert_sends_with_expected_subject_and_body(flask_app, sent):
    send_alert(flask_app, _make_event())
    assert len(sent) == 1
    call = sent[0]
    assert call['toaddr'] == ['ops@example.com']
    assert call['subject'] == '[logmon] myapp: ValueError: bad thing happened'
    assert call['fromaddr'] == 'logmon@example.com'
    assert 'App:' in call['text'] and 'myapp' in call['text']
    assert 'User:' in call['text'] and 'lking@pobox.com' in call['text']
    assert 'GET /admin/x' in call['text']
    assert '--- Traceback ---' in call['text']
    assert 'ValueError: bad thing happened' in call['text']


def test_send_alert_truncates_long_exception_type_in_subject(flask_app, sent):
    long_exc = 'ValueError: ' + ('x' * 200)
    send_alert(flask_app, _make_event(exception_type=long_exc))
    subject = sent[0]['subject']
    # "[logmon] myapp: " prefix + first 80 chars of the exception type
    assert subject == '[logmon] myapp: ' + long_exc[:80]


def test_send_alert_missing_exception_type_uses_placeholder(flask_app, sent):
    send_alert(flask_app, _make_event(exception_type=None, traceback=None))
    assert sent[0]['subject'] == '[logmon] myapp: Unknown exception'
    assert '--- Traceback ---' not in sent[0]['text']


def test_send_alert_alert_from_overrides_mail_default_sender(flask_app, sent):
    flask_app.config['ALERT_FROM'] = 'alerts@example.com'
    send_alert(flask_app, _make_event())
    assert sent[0]['fromaddr'] == 'alerts@example.com'


def test_send_alert_swallows_sendmail_exception(flask_app, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError('smtp down')

    monkeypatch.setattr('loutilities.flask_helpers.mailer.sendmail', boom)
    # must not raise
    send_alert(flask_app, _make_event())


# ----------------------------------------------------------------------
# send_disk_alert
# ----------------------------------------------------------------------

def test_send_disk_alert_skips_when_no_recipients(flask_app, sent):
    flask_app.config['ALERT_RECIPIENTS'] = []
    send_disk_alert(flask_app, {'mount': '/', 'use_pct': 90}, threshold=85)
    assert sent == []


def test_send_disk_alert_formats_sizes_by_magnitude(flask_app, sent):
    fs = {
        'device': '/dev/sda1',
        'mount': '/',
        'use_pct': 90,
        'total_kb': 2 * 1_048_576,   # 2 GB
        'used_kb': 500 * 1_024,      # 500 MB
        'avail_kb': 512,             # 512 KB
    }
    send_disk_alert(flask_app, fs, threshold=85)
    text = sent[0]['text']
    assert sent[0]['subject'] == '[logmon] disk alert: / is 90% full (threshold 85%)'
    assert re.search(r'Total:\s+2\.0 GB', text)
    assert re.search(r'Used:\s+500\.0 MB', text)
    assert re.search(r'Available:\s+512 KB', text)


def test_send_disk_alert_defaults_missing_size_fields_to_zero(flask_app, sent):
    send_disk_alert(flask_app, {'mount': '/data', 'use_pct': 99}, threshold=85)
    text = sent[0]['text']
    assert re.search(r'Total:\s+0 KB', text)
    assert re.search(r'Device:\s+–', text)


# ----------------------------------------------------------------------
# send_mem_alert
# ----------------------------------------------------------------------

def test_send_mem_alert_skips_when_no_recipients(flask_app, sent):
    flask_app.config['ALERT_RECIPIENTS'] = []
    send_mem_alert(flask_app, {'pct': 95}, threshold=90)
    assert sent == []


def test_send_mem_alert_formats_and_sends(flask_app, sent):
    swap = {'total_kb': 2 * 1_048_576, 'used_kb': 1_887_436, 'free_kb': 262_144}
    send_mem_alert(flask_app, {**swap, 'pct': 92}, threshold=90)
    call = sent[0]
    assert call['subject'] == '[logmon] swap alert: 92% used (threshold 90%)'
    assert 'Swap used: 92%  (threshold: 90%)' in call['text']
    assert re.search(r'Total:\s+2\.0 GB', call['text'])

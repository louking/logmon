'''
test_settings - test logmon.settings
=========================================================
'''

import os

import pytest

from logmon import settings
from logmon.settings import AppEntry, _read_secret, _inject_password, _load_logapps


# ----------------------------------------------------------------------
# _read_secret
# ----------------------------------------------------------------------

def test_read_secret_reads_and_strips_file_contents(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, 'SECRETS_DIR', str(tmp_path))
    (tmp_path / 'mail-password').write_text('s3kret\n')
    assert _read_secret('mail-password') == 's3kret'


def test_read_secret_missing_required_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, 'SECRETS_DIR', str(tmp_path))
    with pytest.raises(RuntimeError, match='not found'):
        _read_secret('does-not-exist')


def test_read_secret_missing_optional_returns_default(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, 'SECRETS_DIR', str(tmp_path))
    assert _read_secret('does-not-exist', default='') == ''
    assert _read_secret('does-not-exist', default='fallback') == 'fallback'


# ----------------------------------------------------------------------
# _inject_password
# ----------------------------------------------------------------------

def test_inject_password_inserts_before_at():
    url = 'mysql://dbuser@dbserver/dbname'
    assert _inject_password(url, 'secret') == 'mysql://dbuser:secret@dbserver/dbname'


def test_inject_password_no_at_sign_returns_url_unchanged():
    assert _inject_password('not-a-url', 'secret') == 'not-a-url'


def test_inject_password_empty_url_or_password_returns_url_unchanged():
    assert _inject_password('', 'secret') == ''
    assert _inject_password('mysql://u@h/d', '') == 'mysql://u@h/d'


# ----------------------------------------------------------------------
# AppEntry
# ----------------------------------------------------------------------

def test_appentry_app_log_none_uses_default_filename():
    entry = AppEntry(name='myapp', log_dir='/logs/myapp')
    assert entry.app_log_enabled is True
    assert entry.app_log_path == os.path.join('/logs/myapp', 'myapp.log')


def test_appentry_app_log_explicit_relative_filename():
    entry = AppEntry(name='myapp', log_dir='/logs/myapp', app_log='custom.log')
    assert entry.app_log_path == os.path.join('/logs/myapp', 'custom.log')


def test_appentry_app_log_absolute_path_used_as_is():
    entry = AppEntry(name='myapp', log_dir='/logs/myapp', app_log='/var/log/other.log')
    assert entry.app_log_path == '/var/log/other.log'


def test_appentry_app_log_false_disables():
    entry = AppEntry(name='myapp', log_dir='/logs/myapp', app_log=False)
    assert entry.app_log_enabled is False
    assert entry.app_log_path == ''


@pytest.mark.parametrize('raw', ['false', 'False', 'FALSE'])
def test_appentry_app_log_string_false_normalises_to_bool(raw):
    entry = AppEntry(name='myapp', log_dir='/logs/myapp', app_log=raw)
    assert entry.app_log is False
    assert entry.app_log_enabled is False


def test_appentry_app_log_string_that_is_not_false_kept_as_filename():
    # a filename that happens to differ only in case from "false" (e.g. a
    # deliberately-named "False.log") must NOT be treated as the disable sentinel
    entry = AppEntry(name='myapp', log_dir='/logs/myapp', app_log='False.log')
    assert entry.app_log == 'False.log'
    assert entry.app_log_enabled is True


def test_appentry_access_log_default_filename():
    entry = AppEntry(name='myapp', log_dir='/logs/myapp')
    assert entry.access_log_path == os.path.join('/logs/myapp', 'access.log')


def test_appentry_access_log_explicit():
    entry = AppEntry(name='myapp', log_dir='/logs/myapp', access_log='nginx-access.log')
    assert entry.access_log_path == os.path.join('/logs/myapp', 'nginx-access.log')


# ----------------------------------------------------------------------
# _load_logapps
# ----------------------------------------------------------------------

def test_load_logapps_missing_file_returns_empty_list(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, 'LOGAPPS_PATH', str(tmp_path / 'nope.yml'))
    assert _load_logapps() == []


def test_load_logapps_parses_apps(tmp_path, monkeypatch):
    yml = tmp_path / 'logapps.yml'
    yml.write_text(
        'apps:\n'
        '  myapp:\n'
        '    log_dir: /logs/myapp\n'
        '    access_log: nginx-access.log\n'
        '    alert_suppress_seconds: 120\n'
        '  wpapp:\n'
        '    log_dir: /logs/wpapp\n'
        '    app_log: false\n'
    )
    monkeypatch.setattr(settings, 'LOGAPPS_PATH', str(yml))

    apps = _load_logapps()
    by_name = {a.name: a for a in apps}

    assert set(by_name) == {'myapp', 'wpapp'}
    assert by_name['myapp'].log_dir == '/logs/myapp'
    assert by_name['myapp'].access_log_path == os.path.join('/logs/myapp', 'nginx-access.log')
    assert by_name['myapp'].alert_suppress_seconds == 120
    assert by_name['myapp'].app_log_enabled is True

    assert by_name['wpapp'].app_log_enabled is False
    assert by_name['wpapp'].app_log_path == ''


def test_load_logapps_empty_file_returns_empty_list(tmp_path, monkeypatch):
    yml = tmp_path / 'logapps.yml'
    yml.write_text('')
    monkeypatch.setattr(settings, 'LOGAPPS_PATH', str(yml))
    assert _load_logapps() == []

'''
test_diskmon - test logmon.diskmon
=========================================================
'''

from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from flask import Flask

from logmon import diskmon
from logmon.diskmon import _parse_size, _parse_docker_df_verbose, _collect_df, DiskMonitor
from logmon.model import db, AlertSuppression, DiskSnapshot


# ----------------------------------------------------------------------
# _parse_size
# ----------------------------------------------------------------------

@pytest.mark.parametrize('raw,expected', [
    ('0B', 0),
    ('512B', 512),
    ('1.5kB', 1500),
    ('200MB', 200_000_000),
    ('1.5GB', 1_500_000_000),
    ('1KiB', 1024),
    ('1MiB', 1_048_576),
    ('1GiB', 1_073_741_824),
    ('1TiB', 1_099_511_627_776),
    ('2TB', 2_000_000_000_000),
])
def test_parse_size_suffixes(raw, expected):
    assert _parse_size(raw) == expected


def test_parse_size_strips_parenthetical_suffix():
    # docker sometimes reports "10MB (5%)" for reclaimable percentages
    assert _parse_size('10MB (5%)') == 10_000_000


def test_parse_size_empty_or_garbage_returns_zero():
    assert _parse_size('') == 0
    assert _parse_size('not-a-size') == 0


def test_parse_size_bare_number_no_suffix():
    assert _parse_size('42') == 42


# ----------------------------------------------------------------------
# _parse_docker_df_verbose
# ----------------------------------------------------------------------

_DOCKER_DF_V = """\
Images space usage:

REPOSITORY   TAG       IMAGE ID       CREATED         SIZE      SHARED SIZE   UNIQUE SIZE   CONTAINERS
myapp        latest    abc123def456   3 weeks ago     150MB     100MB         50MB          1

Containers space usage:

CONTAINER ID   IMAGE     COMMAND   LOCAL VOLUMES   SIZE      CREATED         STATUS    NAMES
abc123         myapp     "..."     1               10MB      3 weeks ago     Up        myapp-1

Local Volumes space usage:

VOLUME NAME   LINKS     SIZE
small_vol     1         1MB
big_vol       2         500MB

Build cache usage: 0B

CACHE ID       CACHE TYPE   SIZE      CREATED   LAST USED   USAGE     SHARED
"""


def test_parse_docker_df_verbose_parses_images_and_volumes():
    result = _parse_docker_df_verbose(_DOCKER_DF_V)
    assert result['images'] == [{
        'repository': 'myapp', 'tag': 'latest', 'image_id': 'abc123def456',
        'size': '150MB', 'shared_size': '100MB', 'unique_size': '50MB',
    }]
    # volumes.sort() ranks by parsed byte size descending
    assert [v['name'] for v in result['volumes']] == ['big_vol', 'small_vol']


def test_parse_docker_df_verbose_empty_text():
    assert _parse_docker_df_verbose('') == {'images': [], 'volumes': []}


# ----------------------------------------------------------------------
# _collect_df — fallback mode (no /host/ bind mount present)
# ----------------------------------------------------------------------

_DF_HEADER = 'Filesystem     1024-blocks      Used Available Capacity Mounted on'


def _fake_run(stdout):
    return SimpleNamespace(stdout=stdout, returncode=0)


def test_collect_df_fallback_mode_parses_real_filesystem(monkeypatch):
    monkeypatch.setattr(diskmon.os.path, 'isdir', lambda p: False)
    monkeypatch.setattr(diskmon, '_get_fstype', lambda mount: None)
    stdout = '\n'.join([
        _DF_HEADER,
        '/dev/sda1       10485760   5242880   5242880      50% /',
    ])
    monkeypatch.setattr(diskmon.subprocess, 'run', lambda *a, **k: _fake_run(stdout))

    rows = _collect_df()
    assert rows == [{
        'device': '/dev/sda1', 'mount': '/',
        'total_kb': 10485760, 'used_kb': 5242880, 'avail_kb': 5242880, 'use_pct': 50,
    }]


def test_collect_df_fallback_mode_excludes_pseudo_devices(monkeypatch):
    monkeypatch.setattr(diskmon.os.path, 'isdir', lambda p: False)
    monkeypatch.setattr(diskmon, '_get_fstype', lambda mount: None)
    stdout = '\n'.join([
        _DF_HEADER,
        'tmpfs           1024000          0   1024000       0% /dev/shm',
        '/dev/sda1       10485760   5242880   5242880      50% /',
    ])
    monkeypatch.setattr(diskmon.subprocess, 'run', lambda *a, **k: _fake_run(stdout))

    rows = _collect_df()
    assert [r['device'] for r in rows] == ['/dev/sda1']


def test_collect_df_fallback_mode_excludes_docker_overlay_paths(monkeypatch):
    monkeypatch.setattr(diskmon.os.path, 'isdir', lambda p: False)
    monkeypatch.setattr(diskmon, '_get_fstype', lambda mount: None)
    stdout = '\n'.join([
        _DF_HEADER,
        '/dev/mapper/vg  2000000   1000000   1000000      50% /var/lib/docker/overlay2/abc/merged',
        '/dev/sda1       10485760   5242880   5242880      50% /',
    ])
    monkeypatch.setattr(diskmon.subprocess, 'run', lambda *a, **k: _fake_run(stdout))

    rows = _collect_df()
    assert [r['mount'] for r in rows] == ['/']


def test_collect_df_respects_exclude_mounts_config(monkeypatch):
    monkeypatch.setattr(diskmon.os.path, 'isdir', lambda p: False)
    monkeypatch.setattr(diskmon, '_get_fstype', lambda mount: None)
    stdout = '\n'.join([
        _DF_HEADER,
        '/dev/sda1       10485760   5242880   5242880      50% /',
        '/dev/sda2         512000      1000    511000       1% /boot',
    ])
    monkeypatch.setattr(diskmon.subprocess, 'run', lambda *a, **k: _fake_run(stdout))

    rows = _collect_df(exclude_mounts=['/boot'])
    assert [r['mount'] for r in rows] == ['/']


def test_collect_df_dedups_same_device_keeping_shortest_mount(monkeypatch):
    monkeypatch.setattr(diskmon.os.path, 'isdir', lambda p: False)
    monkeypatch.setattr(diskmon, '_get_fstype', lambda mount: None)
    stdout = '\n'.join([
        _DF_HEADER,
        '/dev/sdb1       10485760   5242880   5242880      50% /mnt/very/long/bind/path',
        '/dev/sdb1       10485760   5242880   5242880      50% /data',
    ])
    monkeypatch.setattr(diskmon.subprocess, 'run', lambda *a, **k: _fake_run(stdout))

    rows = _collect_df()
    assert len(rows) == 1
    assert rows[0]['mount'] == '/data'


def test_collect_df_command_unavailable_returns_empty(monkeypatch):
    monkeypatch.setattr(diskmon.os.path, 'isdir', lambda p: False)

    def raise_not_found(*a, **k):
        raise FileNotFoundError()

    monkeypatch.setattr(diskmon.subprocess, 'run', raise_not_found)
    assert _collect_df() == []


# ----------------------------------------------------------------------
# _collect_df — host_mode (a /host/ bind mount is present)
# ----------------------------------------------------------------------

def test_collect_df_host_mode_normalises_root_and_boot(monkeypatch):
    monkeypatch.setattr(diskmon.os.path, 'isdir', lambda p: p == diskmon.HOST_PREFIX)
    monkeypatch.setattr(diskmon, '_get_fstype', lambda mount: None)
    stdout = '\n'.join([
        _DF_HEADER,
        '/dev/sda2       10485760   5242880   5242880      50% /host/root',
        '/dev/sda3         512000      1000    511000       1% /host/root/boot',
        '/dev/sdb1       20000000  10000000  10000000      50% /host/mnt/data',
        # not under /host/ at all — ignored entirely in host_mode
        '/dev/sdc1        1000000    500000    500000      50% /var/lib/other',
    ])
    monkeypatch.setattr(diskmon.subprocess, 'run', lambda *a, **k: _fake_run(stdout))

    rows = {r['mount']: r for r in _collect_df()}
    assert set(rows) == {'/', '/boot', '/mnt/data'}
    assert rows['/']['device'] == '/dev/sda2'


def test_collect_df_host_mode_skips_loop_devices_and_overlay2(monkeypatch):
    monkeypatch.setattr(diskmon.os.path, 'isdir', lambda p: p == diskmon.HOST_PREFIX)
    monkeypatch.setattr(diskmon, '_get_fstype', lambda mount: None)
    stdout = '\n'.join([
        _DF_HEADER,
        '/dev/loop0        100000     50000     50000      50% /host/snap/core/1234',
        '/dev/sda1       10485760   5242880   5242880      50% /host/var/lib/docker/overlay2/abc/merged',
        '/dev/sda2       10485760   5242880   5242880      50% /host/root',
    ])
    monkeypatch.setattr(diskmon.subprocess, 'run', lambda *a, **k: _fake_run(stdout))

    rows = _collect_df()
    assert [r['mount'] for r in rows] == ['/']


# ----------------------------------------------------------------------
# DiskMonitor alert suppression
# ----------------------------------------------------------------------

@pytest.fixture
def flask_app_for_disk(bare_dbapp):
    bare_dbapp.config['ALERT_SUPPRESS_SECONDS'] = 3600
    bare_dbapp.config['DISK_ALERT_SUPPRESS_SECONDS'] = 14400
    return bare_dbapp


def test_maybe_alert_sends_once_and_suppresses_repeat(flask_app_for_disk, monkeypatch):
    calls = []
    monkeypatch.setattr('logmon.alerter.send_disk_alert', lambda *a, **k: calls.append(a))

    dm = DiskMonitor(flask_app_for_disk)
    fs = {'mount': '/', 'use_pct': 90}

    dm._maybe_alert(fs, threshold=85)
    assert len(calls) == 1
    row = AlertSuppression.query.filter_by(app_name='diskmon', exception_type='/').one()
    assert row is not None

    # second alert inside the suppression window is swallowed
    dm._maybe_alert(fs, threshold=85)
    assert len(calls) == 1


def test_maybe_alert_resends_after_suppression_window_elapses(flask_app_for_disk, monkeypatch):
    calls = []
    monkeypatch.setattr('logmon.alerter.send_disk_alert', lambda *a, **k: calls.append(a))

    dm = DiskMonitor(flask_app_for_disk)
    fs = {'mount': '/', 'use_pct': 90}
    dm._maybe_alert(fs, threshold=85)
    assert len(calls) == 1

    row = AlertSuppression.query.filter_by(app_name='diskmon', exception_type='/').one()
    row.last_alerted_at = datetime.now() - timedelta(seconds=20000)
    db.session.commit()

    dm._maybe_alert(fs, threshold=85)
    assert len(calls) == 2


def test_check_alerts_only_fires_for_filesystems_over_threshold(flask_app_for_disk, monkeypatch):
    flask_app_for_disk.config['DISK_ALERT_THRESHOLD_PCT'] = 85
    alerted_mounts = []
    monkeypatch.setattr(DiskMonitor, '_maybe_alert', lambda self, fs, threshold: alerted_mounts.append(fs['mount']))

    dm = DiskMonitor(flask_app_for_disk)
    snapshot = {'filesystems': [
        {'mount': '/', 'use_pct': 50},
        {'mount': '/data', 'use_pct': 90},
    ]}
    dm._check_alerts(snapshot)
    assert alerted_mounts == ['/data']


# ----------------------------------------------------------------------
# DiskMonitor._store_db
# ----------------------------------------------------------------------

def test_store_db_persists_filesystem_and_docker_rows(flask_app_for_disk):
    dm = DiskMonitor(flask_app_for_disk)
    snapshot = {
        'collected_at': '2026-01-01T00:00:00',
        'filesystems': [
            {'device': '/dev/sda1', 'mount': '/', 'total_kb': 100, 'used_kb': 50, 'avail_kb': 50, 'use_pct': 50},
        ],
        'docker': {'images_size_bytes': 1000, 'volumes_count': 2},
    }
    dm._store_db(snapshot)

    fs_row = DiskSnapshot.query.filter_by(mount='/').one()
    assert fs_row.use_pct == 50

    docker_row = DiskSnapshot.query.filter_by(mount='__docker__').one()
    assert docker_row.docker_images_size_bytes == 1000
    assert docker_row.docker_volumes_count == 2


def test_store_db_no_docker_key_persists_only_filesystem_rows(flask_app_for_disk):
    dm = DiskMonitor(flask_app_for_disk)
    snapshot = {
        'collected_at': '2026-01-01T00:00:00',
        'filesystems': [
            {'device': '/dev/sda1', 'mount': '/', 'total_kb': 100, 'used_kb': 50, 'avail_kb': 50, 'use_pct': 50},
        ],
        'docker': None,
    }
    dm._store_db(snapshot)
    assert DiskSnapshot.query.count() == 1

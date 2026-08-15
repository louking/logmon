'''
test_memmon - test logmon.memmon
=========================================================
'''

import io
from datetime import datetime, timedelta

import pytest

from logmon import memmon
from logmon.memmon import _read_proc_meminfo, _build_mem, _build_swap, MemMonitor
from logmon.model import db, AlertSuppression, MemSnapshot


def _fake_open(content=None, raises=False):
    """memmon.py calls the builtin `open("/proc/meminfo")` directly (no
    indirection), so we shadow `open` in memmon's own module namespace --
    Python resolves an unqualified name there before falling back to
    builtins, same trick applied to `subprocess`/`os.path` in diskmon's
    tests."""
    def fake(path, *a, **k):
        if raises:
            raise OSError(f'{path} unavailable')
        return io.StringIO(content)
    return fake


# ----------------------------------------------------------------------
# _read_proc_meminfo
# ----------------------------------------------------------------------

def test_read_proc_meminfo_parses_known_keys(monkeypatch):
    content = (
        'MemTotal:       16384000 kB\n'
        'MemFree:         2048000 kB\n'
        'MemAvailable:    8192000 kB\n'
        'SwapTotal:        2097152 kB\n'
        'SwapFree:         1048576 kB\n'
    )
    monkeypatch.setattr(memmon, 'open', _fake_open(content), raising=False)
    info = _read_proc_meminfo()
    assert info['MemTotal'] == 16384000
    assert info['MemAvailable'] == 8192000
    assert info['SwapFree'] == 1048576


def test_read_proc_meminfo_skips_unparsable_values(monkeypatch):
    content = 'MemTotal:       16384000 kB\nHugePages_Total:       \n'
    monkeypatch.setattr(memmon, 'open', _fake_open(content), raising=False)
    info = _read_proc_meminfo()
    assert info == {'MemTotal': 16384000}


def test_read_proc_meminfo_missing_file_returns_empty_dict(monkeypatch):
    monkeypatch.setattr(memmon, 'open', _fake_open(raises=True), raising=False)
    assert _read_proc_meminfo() == {}


# ----------------------------------------------------------------------
# _build_mem / _build_swap
# ----------------------------------------------------------------------

def test_build_mem_computes_used_and_pct():
    info = {'MemTotal': 16384000, 'MemAvailable': 8192000}
    mem = _build_mem(info)
    assert mem == {'total_kb': 16384000, 'available_kb': 8192000, 'used_kb': 8192000, 'pct': 50}


def test_build_mem_falls_back_to_memfree_when_memavailable_absent():
    info = {'MemTotal': 1000, 'MemFree': 250}
    mem = _build_mem(info)
    assert mem['available_kb'] == 250
    assert mem['used_kb'] == 750
    assert mem['pct'] == 75


def test_build_mem_zero_total_avoids_division_by_zero():
    assert _build_mem({}) == {'total_kb': 0, 'available_kb': 0, 'used_kb': 0, 'pct': 0}


def test_build_swap_computes_used_and_pct():
    info = {'SwapTotal': 2000, 'SwapFree': 500}
    swap = _build_swap(info)
    assert swap == {'total_kb': 2000, 'free_kb': 500, 'used_kb': 1500, 'pct': 75}


def test_build_swap_zero_total_avoids_division_by_zero():
    assert _build_swap({}) == {'total_kb': 0, 'free_kb': 0, 'used_kb': 0, 'pct': 0}


# ----------------------------------------------------------------------
# MemMonitor alert suppression
# ----------------------------------------------------------------------

@pytest.fixture
def flask_app_for_mem(bare_dbapp):
    bare_dbapp.config['ALERT_SUPPRESS_SECONDS'] = 3600
    bare_dbapp.config['MEM_ALERT_SUPPRESS_SECONDS'] = 14400
    return bare_dbapp


def test_maybe_alert_sends_once_and_suppresses_repeat(flask_app_for_mem, monkeypatch):
    calls = []
    monkeypatch.setattr('logmon.alerter.send_mem_alert', lambda *a, **k: calls.append(a))

    mm = MemMonitor(flask_app_for_mem)
    swap = {'total_kb': 2000, 'used_kb': 1900, 'free_kb': 100, 'pct': 95}

    mm._maybe_alert(swap, threshold=90)
    assert len(calls) == 1
    row = AlertSuppression.query.filter_by(app_name='memmon', exception_type='swap').one()
    assert row is not None

    mm._maybe_alert(swap, threshold=90)
    assert len(calls) == 1


def test_maybe_alert_resends_after_suppression_window_elapses(flask_app_for_mem, monkeypatch):
    calls = []
    monkeypatch.setattr('logmon.alerter.send_mem_alert', lambda *a, **k: calls.append(a))

    mm = MemMonitor(flask_app_for_mem)
    swap = {'total_kb': 2000, 'used_kb': 1900, 'free_kb': 100, 'pct': 95}
    mm._maybe_alert(swap, threshold=90)

    row = AlertSuppression.query.filter_by(app_name='memmon', exception_type='swap').one()
    row.last_alerted_at = datetime.now() - timedelta(seconds=20000)
    db.session.commit()

    mm._maybe_alert(swap, threshold=90)
    assert len(calls) == 2


@pytest.mark.parametrize('swap,threshold,should_alert', [
    ({'total_kb': 2000, 'pct': 95}, 90, True),
    ({'total_kb': 2000, 'pct': 50}, 90, False),
    # no swap configured at all — 0%/0 total must never alert, regardless of
    # threshold (guards against a threshold of 0 misfiring on swapless hosts)
    ({'total_kb': 0, 'pct': 0}, 0, False),
])
def test_check_alerts_only_fires_when_swap_configured_and_over_threshold(
        flask_app_for_mem, monkeypatch, swap, threshold, should_alert):
    flask_app_for_mem.config['SWAP_ALERT_THRESHOLD_PCT'] = threshold
    calls = []
    monkeypatch.setattr(MemMonitor, '_maybe_alert', lambda self, s, t: calls.append((s, t)))

    mm = MemMonitor(flask_app_for_mem)
    mm._check_alerts({'swap': swap})
    assert bool(calls) is should_alert


# ----------------------------------------------------------------------
# MemMonitor._store_db
# ----------------------------------------------------------------------

def test_store_db_persists_mem_and_swap_fields(flask_app_for_mem):
    mm = MemMonitor(flask_app_for_mem)
    snapshot = {
        'collected_at': '2026-01-01T00:00:00',
        'mem': {'total_kb': 16384000, 'available_kb': 8192000, 'used_kb': 8192000, 'pct': 50},
        'swap': {'total_kb': 2000, 'free_kb': 500, 'used_kb': 1500, 'pct': 75},
    }
    mm._store_db(snapshot)

    row = MemSnapshot.query.one()
    assert row.mem_total_kb == 16384000
    assert row.swap_pct == 75


def test_store_db_bad_collected_at_falls_back_to_now(flask_app_for_mem):
    mm = MemMonitor(flask_app_for_mem)
    snapshot = {'collected_at': 'not-a-timestamp', 'mem': {}, 'swap': {}}
    mm._store_db(snapshot)   # must not raise
    assert MemSnapshot.query.count() == 1

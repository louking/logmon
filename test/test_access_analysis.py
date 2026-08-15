'''
test_access_analysis - test logmon.access_analysis
=========================================================
'''

from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Network

import pytest

from logmon import access_analysis
from logmon.access_analysis import (
    CountryCidrMapper, _NullMapper, _exclude_private_ips, _get_excluded_ips,
    get_bad_actors, get_bad_actors_summary, get_cpu_metrics,
)
from logmon.model import db, AccessEvent


# ----------------------------------------------------------------------
# CountryCidrMapper / _NullMapper
# ----------------------------------------------------------------------

def _mapper_with(entries):
    """Build a CountryCidrMapper with a fixed NETWORK_MAP, bypassing
    __init__'s real network download (see CountryCidrMapper._load)."""
    m = object.__new__(CountryCidrMapper)
    m.NETWORK_MAP = sorted(
        ((int(net.network_address), net, code) for net, code in entries),
        key=lambda x: x[0],
    )
    return m


def test_get_country_from_ip_matches_containing_network():
    mapper = _mapper_with([
        (IPv4Network('8.8.8.0/24'), 'US'),
        (IPv4Network('1.1.1.0/24'), 'AU'),
    ])
    assert mapper.get_country_from_ip('8.8.8.8') == 'US'
    assert mapper.get_country_from_ip('1.1.1.1') == 'AU'


def test_get_country_from_ip_unknown_when_no_network_matches():
    mapper = _mapper_with([(IPv4Network('8.8.8.0/24'), 'US')])
    assert mapper.get_country_from_ip('203.0.113.5') == 'UNKNOWN'


def test_get_country_from_ip_empty_map_is_unknown():
    mapper = _mapper_with([])
    assert mapper.get_country_from_ip('8.8.8.8') == 'UNKNOWN'


def test_get_country_from_ip_ipv6_returns_sentinel():
    mapper = _mapper_with([])
    assert mapper.get_country_from_ip('2001:db8::1') == 'IPV6'


def test_get_country_from_ip_invalid_string_returns_sentinel():
    mapper = _mapper_with([])
    assert mapper.get_country_from_ip('not-an-ip') == 'INVALID'


def test_null_mapper_always_unknown():
    assert _NullMapper().get_country_from_ip('8.8.8.8') == 'UNKNOWN'


# ----------------------------------------------------------------------
# _get_iso_country_codes
# ----------------------------------------------------------------------

class _FakeResponse:
    def __init__(self, text):
        self.text = text

    def raise_for_status(self):
        pass


def test_get_iso_country_codes_parses_csv(monkeypatch):
    csv_text = 'Name,Code\nUnited States,US\nCanada,CA\n'
    monkeypatch.setattr(access_analysis, 'http_get', lambda *a, **k: _FakeResponse(csv_text))
    assert access_analysis._get_iso_country_codes() == ['us', 'ca']


def test_get_iso_country_codes_retries_then_succeeds(monkeypatch):
    attempts = {'n': 0}

    def flaky_get(*a, **k):
        attempts['n'] += 1
        if attempts['n'] < 3:
            raise ConnectionError('boom')
        return _FakeResponse('Name,Code\nCanada,CA\n')

    monkeypatch.setattr(access_analysis, 'http_get', flaky_get)
    assert access_analysis._get_iso_country_codes() == ['ca']
    assert attempts['n'] == 3


def test_get_iso_country_codes_raises_after_exhausting_retries(monkeypatch):
    def always_fails(*a, **k):
        raise ConnectionError('boom')

    monkeypatch.setattr(access_analysis, 'http_get', always_fails)
    with pytest.raises(ConnectionError):
        access_analysis._get_iso_country_codes()


# ----------------------------------------------------------------------
# _get_excluded_ips
# ----------------------------------------------------------------------

def test_get_excluded_ips_parses_comma_separated_config(bareapp):
    bareapp.config['EXCLUDED_IPS'] = ' 203.0.113.42 , 198.51.100.0/24 ,'
    assert _get_excluded_ips(bareapp) == ['203.0.113.42', '198.51.100.0/24']


def test_get_excluded_ips_empty_config_returns_empty_list(bareapp):
    bareapp.config['EXCLUDED_IPS'] = ''
    assert _get_excluded_ips(bareapp) == []


# ----------------------------------------------------------------------
# _exclude_private_ips — clause construction
# ----------------------------------------------------------------------
# The CIDR-network branch (extra_ips entries wider than /32) builds a clause
# using func.inet_aton(), a MySQL/MariaDB-only function -- not available on
# sqlite, so it's checked structurally here (compiled SQL text) rather than
# executed. The single-host branch uses plain equality and IS exercised
# end-to-end below, against a real sqlite AccessEvent table.

def test_exclude_private_ips_cidr_extra_uses_inet_aton(bareapp):
    clauses = _exclude_private_ips(AccessEvent.client_ip, ['198.51.100.0/24'])
    compiled = str(clauses[-1])
    assert 'inet_aton' in compiled


def test_exclude_private_ips_invalid_extra_entry_is_ignored(bareapp, caplog):
    before = _exclude_private_ips(AccessEvent.client_ip, [])
    after = _exclude_private_ips(AccessEvent.client_ip, ['not-an-ip'])
    assert len(after) == len(before)   # invalid entry contributes no clause


# ----------------------------------------------------------------------
# get_bad_actors / get_bad_actors_summary — full integration against sqlite
# ----------------------------------------------------------------------

class _FakeMapper:
    def get_country_from_ip(self, ip):
        return {'8.8.8.8': 'US', '1.1.1.1': 'AU'}.get(ip, 'XX')


@pytest.fixture
def fake_mapper(monkeypatch):
    mapper = _FakeMapper()
    monkeypatch.setattr(access_analysis, 'get_mapper', lambda: mapper)
    return mapper


def _add_access_event(app_name, client_ip, occurred_at, path='/x', status_code=200):
    db.session.add(AccessEvent(
        app_name=app_name, client_ip=client_ip, occurred_at=occurred_at,
        method='GET', path=path, status_code=status_code,
    ))


def test_get_bad_actors_excludes_private_ranges_and_ranks_by_count(bare_dbapp, fake_mapper):
    now = datetime(2026, 1, 1, 12, 0, 0)
    with bare_dbapp.app_context():
        for _ in range(5):
            _add_access_event('myapp', '8.8.8.8', now)
        for _ in range(2):
            _add_access_event('myapp', '1.1.1.1', now)
        # private ranges must never appear in results
        _add_access_event('myapp', '10.0.0.5', now)
        _add_access_event('myapp', '192.168.1.1', now)
        _add_access_event('myapp', '172.20.5.5', now)   # inside 172.16-31 range
        _add_access_event('myapp', '127.0.0.1', now)
        db.session.commit()

        result = get_bad_actors(now - timedelta(hours=1), now + timedelta(hours=1))

    ips = [r['ip'] for r in result]
    assert ips == ['8.8.8.8', '1.1.1.1']   # ordered by count desc
    assert result[0]['count'] == 5
    assert result[0]['country'] == 'US'
    assert result[0]['paths'] == [{'app': 'myapp', 'path': '/x'}]


def test_get_bad_actors_172_range_boundary_not_excluded(bare_dbapp, fake_mapper):
    # 172.15.x and 172.32.x are outside the private 172.16-31 block and
    # must NOT be excluded -- only 172.16.0.0/12 is RFC-1918.
    now = datetime(2026, 1, 1, 12, 0, 0)
    with bare_dbapp.app_context():
        _add_access_event('myapp', '172.15.0.1', now)
        _add_access_event('myapp', '172.32.0.1', now)
        db.session.commit()

        result = get_bad_actors(now - timedelta(hours=1), now + timedelta(hours=1))

    assert {r['ip'] for r in result} == {'172.15.0.1', '172.32.0.1'}


def test_get_bad_actors_respects_threshold_and_limit(bare_dbapp, fake_mapper):
    now = datetime(2026, 1, 1, 12, 0, 0)
    with bare_dbapp.app_context():
        for _ in range(3):
            _add_access_event('myapp', '8.8.8.8', now)
        _add_access_event('myapp', '1.1.1.1', now)   # count 1, below threshold
        db.session.commit()

        result = get_bad_actors(now - timedelta(hours=1), now + timedelta(hours=1), threshold=2)

    assert [r['ip'] for r in result] == ['8.8.8.8']


def test_get_bad_actors_error_count_only_counts_4xx_5xx(bare_dbapp, fake_mapper):
    now = datetime(2026, 1, 1, 12, 0, 0)
    with bare_dbapp.app_context():
        _add_access_event('myapp', '8.8.8.8', now, status_code=200)
        _add_access_event('myapp', '8.8.8.8', now, status_code=404)
        _add_access_event('myapp', '8.8.8.8', now, status_code=500)
        db.session.commit()

        result = get_bad_actors(now - timedelta(hours=1), now + timedelta(hours=1))

    assert result[0]['count'] == 3
    assert result[0]['error_count'] == 2


def test_get_bad_actors_excludes_extra_configured_single_ip(bare_dbapp, fake_mapper):
    bare_dbapp.config['EXCLUDED_IPS'] = '203.0.113.42'
    now = datetime(2026, 1, 1, 12, 0, 0)
    with bare_dbapp.app_context():
        _add_access_event('myapp', '203.0.113.42', now)
        _add_access_event('myapp', '8.8.8.8', now)
        db.session.commit()

        result = get_bad_actors(now - timedelta(hours=1), now + timedelta(hours=1), flask_app=bare_dbapp)

    assert [r['ip'] for r in result] == ['8.8.8.8']


def test_get_bad_actors_outside_window_excluded(bare_dbapp, fake_mapper):
    now = datetime(2026, 1, 1, 12, 0, 0)
    with bare_dbapp.app_context():
        _add_access_event('myapp', '8.8.8.8', now - timedelta(days=1))
        db.session.commit()

        result = get_bad_actors(now - timedelta(hours=1), now + timedelta(hours=1))

    assert result == []


def test_get_bad_actors_summary_uses_trailing_window_and_threshold(bare_dbapp, fake_mapper):
    recent = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=1)
    stale = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=48)
    with bare_dbapp.app_context():
        for _ in range(3):
            _add_access_event('myapp', '8.8.8.8', recent)
        _add_access_event('myapp', '1.1.1.1', stale)   # outside the 24h window
        db.session.commit()

        result = get_bad_actors_summary(threshold=2, hours=24)

    assert [r['ip'] for r in result] == ['8.8.8.8']
    assert result[0]['country'] == 'US'


# ----------------------------------------------------------------------
# get_cpu_metrics
# ----------------------------------------------------------------------

def test_get_cpu_metrics_returns_empty_without_credentials(bareapp):
    result = get_cpu_metrics(bareapp, datetime.now(), datetime.now())
    assert result == []


def test_get_cpu_metrics_parses_csv_skipping_first_row(bareapp, monkeypatch):
    # get_cpu_metrics does `from .dometrics import get_droplet_cpu_metrics, metrics2csv`
    # inside the function body, so the patch target is logmon.dometrics, not
    # logmon.access_analysis (same re-import-per-call pattern as alerter.sendmail).
    bareapp.config['DO_API_TOKEN'] = 'tok'
    bareapp.config['DO_HOST_ID'] = '123'

    monkeypatch.setattr('logmon.dometrics.get_droplet_cpu_metrics', lambda *a, **k: {})
    csv_text = (
        'Time,%CPU,Used (cum msec),Total (cum msec)\n'
        '2026-01-01T00:00:00,,1000,2000\n'
        '2026-01-01T00:01:00,12.5,1500,2500\n'
    )
    monkeypatch.setattr('logmon.dometrics.metrics2csv', lambda metrics: csv_text)

    result = get_cpu_metrics(bareapp, datetime.now(timezone.utc), datetime.now(timezone.utc))
    assert result == [{'timestamp': '2026-01-01T00:01:00', 'cpu_pct': 12.5}]


def test_get_cpu_metrics_swallows_api_failure(bareapp, monkeypatch):
    bareapp.config['DO_API_TOKEN'] = 'tok'
    bareapp.config['DO_HOST_ID'] = '123'

    def boom(*a, **k):
        raise RuntimeError('DO API down')

    monkeypatch.setattr('logmon.dometrics.get_droplet_cpu_metrics', boom)
    result = get_cpu_metrics(bareapp, datetime.now(timezone.utc), datetime.now(timezone.utc))
    assert result == []

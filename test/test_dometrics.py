'''
test_dometrics - test logmon.dometrics.metrics2csv

get_droplet_cpu_metrics() itself is a thin requests.get() wrapper against the
DigitalOcean API and isn't covered here -- access_analysis.get_cpu_metrics()
(test_access_analysis.py) exercises the calling code with it mocked out.
'''

from csv import DictReader
from io import StringIO

import pytest

from logmon.dometrics import metrics2csv


def _metrics(idle, user, system, base_ts=1_700_000_000, step=60):
    """Build a DigitalOcean-shaped metrics response for N samples per mode.
    CPU time values are cumulative milliseconds, as the real API returns."""
    n = len(idle)
    timestamps = [base_ts + i * step for i in range(n)]

    def series(mode, values):
        return {'metric': {'mode': mode}, 'values': [[t, str(v)] for t, v in zip(timestamps, values)]}

    return {'data': {'result': [
        series('idle', idle),
        series('user', user),
        series('system', system),
    ]}}


def test_metrics2csv_first_row_has_no_cpu_pct():
    metrics = _metrics(idle=[1000, 1900], user=[500, 600], system=[0, 0])
    rows = list(DictReader(StringIO(metrics2csv(metrics))))
    assert rows[0]['%CPU'] == ''
    assert rows[0]['Used (cum msec)'] == '500'
    assert rows[0]['Total (cum msec)'] == '1500'


def test_metrics2csv_computes_pct_from_cumulative_diff():
    # total goes 1500 -> 2500 (delta 1000); used (=total-idle) goes 500 -> 600
    # (delta 100) -> 100/1000 = 10.0%
    metrics = _metrics(idle=[1000, 1900], user=[500, 600], system=[0, 0])
    rows = list(DictReader(StringIO(metrics2csv(metrics))))
    assert rows[1]['%CPU'] == '10.0'
    assert rows[1]['Used (cum msec)'] == '600'
    assert rows[1]['Total (cum msec)'] == '2500'


def test_metrics2csv_sums_all_non_idle_modes_into_used():
    # used = total - idle, and total sums every mode present (idle, user, system, ...)
    metrics = _metrics(idle=[1000, 1000], user=[200, 400], system=[100, 300])
    rows = list(DictReader(StringIO(metrics2csv(metrics))))
    # total: 1300 -> 1700 (delta 400); idle unchanged -> used delta 400 -> 100%
    assert rows[1]['%CPU'] == '100.0'


def test_metrics2csv_mismatched_timestamps_raises():
    metrics = _metrics(idle=[1000, 1900], user=[500, 600], system=[0, 0])
    # shift the 'system' series' own timestamp array out of alignment
    metrics['data']['result'][2]['values'] = [[1_700_000_001, '0'], [1_700_000_061, '0']]
    with pytest.raises(ValueError, match='mismatched timestamps'):
        metrics2csv(metrics)


def test_metrics2csv_skips_nan_row_when_no_time_elapsed(caplog):
    # two samples with the identical cumulative totals (duplicate collection)
    # -> total[i] - last_total == 0 -> division produces NaN -> row is skipped
    # rather than writing a nonsensical %CPU value.
    metrics = _metrics(idle=[1000, 1000], user=[500, 500], system=[0, 0])
    rows = list(DictReader(StringIO(metrics2csv(metrics))))
    assert len(rows) == 1   # only the first (no-diff-available) row survives

'''
test_logparser - test logmon.logparser
=========================================================
'''

from datetime import datetime

from logmon.logparser import (
    parse_app_line, is_new_app_record, extract_exception_type, parse_access_line,
)


# ----------------------------------------------------------------------
# parse_app_line
# ----------------------------------------------------------------------

def test_parse_app_line_http():
    line = '2026-03-07 06:42:30,097 INFO: anonymous 16.58.56.214: GET http://x/foo 404 [in /app/views.py:10]'
    parsed = parse_app_line(line)
    assert parsed['type'] == 'http'
    assert parsed['occurred_at'] == datetime(2026, 3, 7, 6, 42, 30, 97000)
    assert parsed['level'] == 'INFO'
    assert parsed['user'] == 'anonymous'
    assert parsed['ip'] == '16.58.56.214'
    assert parsed['method'] == 'GET'
    assert parsed['url'] == 'http://x/foo'
    assert parsed['status_code'] == 404
    assert parsed['location'] == '/app/views.py:10'
    assert parsed['message'] == 'GET http://x/foo 404'


def test_parse_app_line_http_ipv6():
    line = '2026-03-07 06:42:30,097 INFO: lking@pobox.com 2001:db8::1: GET /x 200 [in /app/views.py:10]'
    parsed = parse_app_line(line)
    assert parsed['type'] == 'http'
    assert parsed['ip'] == '2001:db8::1'


def test_parse_app_line_exception_start():
    line = '2026-03-06 11:20:52,360 ERROR: lking@pobox.com Exception on /admin/x [GET] [in /app/errors.py:5]'
    parsed = parse_app_line(line)
    assert parsed['type'] == 'exception_start'
    assert parsed['level'] == 'ERROR'
    assert parsed['user'] == 'lking@pobox.com'
    assert parsed['url'] == '/admin/x'
    assert parsed['method'] == 'GET'
    assert parsed['ip'] is None
    assert parsed['status_code'] is None
    assert parsed['location'] == '/app/errors.py:5'
    assert parsed['message'] == 'Exception on /admin/x [GET]'


def test_parse_app_line_traceback_start():
    line = '2026-03-29 15:26:58,058 ERROR: harriet@example.com Traceback (most recent call last):'
    parsed = parse_app_line(line)
    assert parsed['type'] == 'traceback_start'
    assert parsed['user'] == 'harriet@example.com'
    assert parsed['message'] == 'Traceback (most recent call last):'
    assert parsed['ip'] is None
    assert parsed['url'] is None


def test_parse_app_line_generic():
    line = '2026-03-29 15:26:58,058 DEBUG: some diagnostic message'
    parsed = parse_app_line(line)
    assert parsed['type'] == 'generic'
    assert parsed['level'] == 'DEBUG'
    assert parsed['user'] is None
    assert parsed['message'] == 'some diagnostic message'


def test_parse_app_line_unrecognised_returns_none():
    assert parse_app_line('not a log line at all') is None
    assert parse_app_line('') is None


# a traceback continuation line has no leading timestamp, so it must fall
# all the way through every RE_APP_* pattern to None -- this guards that
# _run_app's "not is_new_app_record(line)" continuation-collection logic
# (follower.py) keeps working even if a new RE_APP_* pattern is added above
# the generic fallback and starts accidentally matching indented lines.
def test_parse_app_line_traceback_continuation_returns_none():
    assert parse_app_line('  File "app.py", line 10, in foo') is None


# ----------------------------------------------------------------------
# is_new_app_record
# ----------------------------------------------------------------------

def test_is_new_app_record_true_for_timestamped_line():
    assert is_new_app_record('2026-03-29 15:26:58,058 ERROR: boom\n') is True


def test_is_new_app_record_false_for_traceback_continuation():
    assert is_new_app_record('  File "app.py", line 10, in foo') is False
    assert is_new_app_record('ValueError: bad value') is False


# ----------------------------------------------------------------------
# extract_exception_type
# ----------------------------------------------------------------------

def test_extract_exception_type_prefers_last_exception_line():
    tb = (
        'Traceback (most recent call last):\n'
        '  File "app.py", line 10, in foo\n'
        '    raise ValueError("bad")\n'
        'ValueError: bad\n'
    )
    assert extract_exception_type(tb) == 'ValueError: bad'


def test_extract_exception_type_skips_trailing_loutilities_suffix():
    # a "[in file:line]" suffix line (added by loutilities/Flask logging) can
    # follow the real exception line; it must not be picked over the real one
    tb = (
        'Traceback (most recent call last):\n'
        '  File "app.py", line 10, in foo\n'
        'sqlalchemy.exc.DataError: (pymysql.err.DataError) bad\n'
        '[in /app/views.py:42]\n'
    )
    assert extract_exception_type(tb) == 'sqlalchemy.exc.DataError: (pymysql.err.DataError) bad'


def test_extract_exception_type_falls_back_to_last_nonblank_line():
    tb = 'Traceback (most recent call last):\nsome non-exception-shaped final line\n'
    assert extract_exception_type(tb) == 'some non-exception-shaped final line'


def test_extract_exception_type_empty_text_returns_none():
    assert extract_exception_type('') is None
    assert extract_exception_type('   \n  \n') is None


# ----------------------------------------------------------------------
# parse_access_line
# ----------------------------------------------------------------------

def test_parse_access_line_basic():
    line = ('97.238.20.183, 172.28.0.1 - - [12/Mar/2026:15:26:46 -0400] '
            '"GET /path HTTP/1.0" 200 83 "https://referer" "Mozilla/5.0"')
    parsed = parse_access_line(line)
    assert parsed['type'] == 'access'
    # first IP in the X-Forwarded-For chain is the real client, not the docker peer
    assert parsed['client_ip'] == '97.238.20.183'
    assert parsed['ip_chain'] == '97.238.20.183, 172.28.0.1'
    assert parsed['method'] == 'GET'
    assert parsed['path'] == '/path'
    assert parsed['status_code'] == 200
    assert parsed['bytes_sent'] == 83
    assert parsed['referer'] == 'https://referer'
    assert parsed['user_agent'] == 'Mozilla/5.0'
    assert parsed['occurred_at'] == datetime(2026, 3, 12, 15, 26, 46,
                                              tzinfo=parsed['occurred_at'].tzinfo)


def test_parse_access_line_single_ip_no_chain():
    line = '203.0.113.5 - - [01/Jan/2026:00:00:00 +0000] "POST /login HTTP/1.1" 401 0 "-" "-"'
    parsed = parse_access_line(line)
    assert parsed['client_ip'] == '203.0.113.5'
    assert parsed['ip_chain'] == '203.0.113.5'
    # "-" is nginx's placeholder for "absent"; both fields normalise to None
    assert parsed['referer'] is None
    assert parsed['user_agent'] is None
    assert parsed['bytes_sent'] == 0


def test_parse_access_line_ipv6_client():
    line = ('2001:db8::1, 172.28.0.1 - - [01/Jan/2026:00:00:00 +0000] '
            '"GET / HTTP/1.1" 200 10 "-" "-"')
    parsed = parse_access_line(line)
    assert parsed['client_ip'] == '2001:db8::1'


def test_parse_access_line_unrecognised_returns_none():
    assert parse_access_line('not an access log line') is None
    assert parse_access_line('') is None

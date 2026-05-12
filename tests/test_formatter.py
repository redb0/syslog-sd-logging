"""Tests for the functionality of formatting a message in the RFC 5424 format."""

from __future__ import annotations

import logging
from codecs import BOM_UTF8
from unittest.mock import patch

import pytest
import pytz

from syslog_sd_logging.formatter import REGISTERED_SD_IDs, Rfc5424Formatter
from syslog_sd_logging.handler import LOG_USER

_FIXED_OFFSET_7 = pytz.FixedOffset(420)


def _log_record(
    *,
    msg: object = 'hello',
    level: int = logging.INFO,
    levelname: str = 'INFO',
    **attrs: object,
) -> logging.LogRecord:
    record = logging.LogRecord(
        name='root',
        level=level,
        pathname='',
        lineno=0,
        msg=msg,
        args=(),
        exc_info=None,
    )
    record.levelname = levelname
    record.created = 946725071.111111
    for key, value in attrs.items():
        setattr(record, key, value)
    return record


def _formatter(**kwargs: object) -> Rfc5424Formatter:
    defaults: dict[str, object] = {
        'facility': LOG_USER,
        'hostname': 'test-hostname',
        'app_name': 'myapp',
        'procid': 111,
        'structured_data': {},
        'enterprise_id': None,
        'msg_as_utf8': True,
        'utc_timestamp': False,
    }
    defaults.update(kwargs)
    return Rfc5424Formatter(**defaults)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ('levelname', 'expected_severity'),
    [
        ('DEBUG', Rfc5424Formatter.LOG_DEBUG),
        ('INFO', Rfc5424Formatter.LOG_INFO),
        ('NOTICE', Rfc5424Formatter.LOG_NOTICE),
        ('WARNING', Rfc5424Formatter.LOG_WARNING),
        ('ERROR', Rfc5424Formatter.LOG_ERR),
        ('CRITICAL', Rfc5424Formatter.LOG_CRIT),
        ('ALERT', Rfc5424Formatter.LOG_ALERT),
        ('EMERGENCY', Rfc5424Formatter.LOG_EMERG),
        ('EMERG', Rfc5424Formatter.LOG_EMERG),
    ],
)
def test_encode_priority_maps_level_names(levelname: str, expected_severity: int) -> None:
    """Known ``levelname`` values map to RFC severities."""
    fmt = _formatter()
    assert fmt.encode_priority(LOG_USER, levelname) == (LOG_USER << 3) | expected_severity


def test_encode_priority_unknown_level_defaults_to_warning() -> None:
    """Unknown ``record.levelname`` falls back to WARNING severity."""
    fmt = _formatter()
    expected = (LOG_USER << 3) | Rfc5424Formatter.LOG_WARNING
    assert fmt.encode_priority(LOG_USER, 'UNKNOWN_LEVEL') == expected


def test_extract_hostname_prefers_record_attribute() -> None:
    """``record.hostname`` overrides formatter default."""
    fmt = _formatter(hostname='default-host')
    record = _log_record(hostname='from-record')
    assert fmt.extract_hostname(record) == 'from-record'


def test_extract_hostname_filters_non_printable_ascii() -> None:
    """Non-printable characters are stripped from hostname."""
    fmt = _formatter(hostname='h')
    record = _log_record(hostname='ab\x01cd')
    assert fmt.extract_hostname(record) == 'abcd'


def test_extract_app_name_uses_appname_extra() -> None:
    """Application name prefers ``appname`` on the record."""
    fmt = _formatter(app_name=None)
    record = _log_record(appname='from-appname')
    assert fmt.extract_app_name(record) == 'from-appname'


def test_extract_app_name_falls_back_to_record_name() -> None:
    """Without ``appname``, ``record.name`` is used."""
    fmt = _formatter(app_name=None)
    record = _log_record()
    record.name = 'logger-name'
    assert fmt.extract_app_name(record) == 'logger-name'


def test_extract_proc_id_prefers_record_procid() -> None:
    """Process ID uses ``procid`` extra when present."""
    fmt = _formatter(procid=1)
    record = _log_record(procid='999')
    assert fmt.extract_proc_id(record) == '999'


def test_extract_proc_id_falls_back_to_record_process() -> None:
    """Without ``procid``, ``record.process`` is used."""
    fmt = _formatter(procid=None)
    record = _log_record()
    record.process = 4242
    assert fmt.extract_proc_id(record) == '4242'


def test_extract_msgid_nil_when_missing() -> None:
    """Missing ``msgid`` yields NILVALUE ``-``."""
    fmt = _formatter()
    record = _log_record()
    assert fmt.extract_msgid(record) == '-'


def test_extract_enterprise_id_none_when_unset() -> None:
    """Unset enterprise id returns ``None`` for structured-data builder."""
    fmt = _formatter(enterprise_id=None)
    record = _log_record()
    assert fmt.extract_enterprise_id(record) is None


def test_extract_structured_data_merges_record_dict() -> None:
    """Handler SD is merged with per-record ``structured_data``."""
    fmt = _formatter(structured_data={'a@1': {'x': '1'}})
    record = _log_record(structured_data={'b@2': {'y': '2'}})
    assert fmt.extract_structured_data(record) == {'a@1': {'x': '1'}, 'b@2': {'y': '2'}}


def test_extract_structured_data_ignores_non_dict_record_sd() -> None:
    """Non-dict ``record.structured_data`` keeps only handler SD."""
    fmt = _formatter(structured_data={'a@1': {'x': '1'}})
    record = _log_record(structured_data='not-a-dict')
    assert fmt.extract_structured_data(record) == {'a@1': {'x': '1'}}


@pytest.mark.parametrize('registered_id', REGISTERED_SD_IDs)
def test_build_msg_registered_sd_keeps_short_id_with_enterprise(
    registered_id: str,
) -> None:
    """Registered SD-IDs stay unprefixed by PEN even when ``enterprise_id`` is set."""
    fmt = _formatter(structured_data={registered_id: {'k': 'v'}}, enterprise_id='32473')
    record = _log_record(msg='m')
    with patch('syslog_sd_logging.formatter.get_localzone', return_value=_FIXED_OFFSET_7):
        out = fmt.build_msg(record, lambda r: r.getMessage())
    assert f'[{registered_id} k="v"]'.encode() in out


def test_build_msg_full_payload_matches_header_and_utf8_msg() -> None:
    """Golden-path syslog bytes: header, NILVALUE SD, BOM-prefixed UTF-8 MSG."""
    fmt = _formatter()
    record = _log_record(msg='hello')
    with patch('syslog_sd_logging.formatter.get_localzone', return_value=_FIXED_OFFSET_7):
        out = fmt.build_msg(record, lambda r: r.getMessage())
    expected = (
        b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname myapp 111 - - ' + BOM_UTF8 + b'hello'
    )
    assert out == expected


def test_build_msg_utc_timestamp_switches_to_utc_iso() -> None:
    """``utc_timestamp=True`` converts timestamp to UTC."""
    fmt = _formatter(utc_timestamp=True)
    record = _log_record(msg='x')
    with patch('syslog_sd_logging.formatter.get_localzone', return_value=_FIXED_OFFSET_7):
        out = fmt.build_msg(record, lambda r: r.getMessage())
    assert b'2000-01-01T11:11:11.111111+00:00' in out


def test_build_msg_without_utf8_bom() -> None:
    """``msg_as_utf8=False`` emits MSG without BOM."""
    fmt = _formatter(msg_as_utf8=False)
    record = _log_record(msg='plain')
    with patch('syslog_sd_logging.formatter.get_localzone', return_value=_FIXED_OFFSET_7):
        out = fmt.build_msg(record, lambda r: r.getMessage())
    assert not out.startswith(BOM_UTF8)
    assert out.endswith(b'plain')


@pytest.mark.parametrize('empty_msg', [None, ''])
def test_build_msg_omits_msg_part_when_empty(empty_msg: str | None) -> None:
    """Falsy ``record.msg`` yields HEADER + SD only (no trailing MSG section)."""
    fmt = _formatter()
    record = _log_record(msg=empty_msg)
    with patch('syslog_sd_logging.formatter.get_localzone', return_value=_FIXED_OFFSET_7):
        out = fmt.build_msg(record, lambda r: r.getMessage())
    assert out == b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname myapp 111 - -'


def test_build_sd_id_raises_when_custom_id_without_enterprise() -> None:
    """Custom SD-ID needs ``@enterprise`` or handler ``enterprise_id``."""
    fmt = _formatter(structured_data={'custom_sd': {}}, enterprise_id=None)
    record = _log_record(msg='x')
    with (
        patch('syslog_sd_logging.formatter.get_localzone', return_value=_FIXED_OFFSET_7),
        pytest.raises(ValueError, match='Enterprise ID has not been set'),
    ):
        fmt.build_msg(record, lambda r: r.getMessage())


def test_build_sd_id_raises_when_enterprise_suffix_empty() -> None:
    """``sd_id@`` with empty enterprise part raises."""
    fmt = _formatter(structured_data={'myid@': {}}, enterprise_id=None)
    record = _log_record(msg='x')
    with (
        patch('syslog_sd_logging.formatter.get_localzone', return_value=_FIXED_OFFSET_7),
        pytest.raises(ValueError, match='Enterprise ID is not set'),
    ):
        fmt.build_msg(record, lambda r: r.getMessage())


def test_build_sd_id_raises_when_enterprise_too_long() -> None:
    """Enterprise id longer than 30 printable ASCII chars is rejected."""
    long_pen = 'x' * 31
    fmt = _formatter(structured_data={f'foo@{long_pen}': {}}, enterprise_id=None)
    record = _log_record(msg='x')
    with (
        patch('syslog_sd_logging.formatter.get_localzone', return_value=_FIXED_OFFSET_7),
        pytest.raises(ValueError, match='too long'),
    ):
        fmt.build_msg(record, lambda r: r.getMessage())


def test_sd_params_non_dict_emits_id_only() -> None:
    """Non-dict SD params yield ``[sd-id]`` with no PARAM blocks."""
    fmt = _formatter(structured_data={'sd@1': 'notdict'}, enterprise_id=None)
    record = _log_record(msg='m')
    with patch('syslog_sd_logging.formatter.get_localzone', return_value=_FIXED_OFFSET_7):
        out = fmt.build_msg(record, lambda r: r.getMessage())
    assert b'[sd@1]' in out


def test_sd_param_name_truncated_to_32_chars() -> None:
    """Parameter names are truncated to 32 bytes."""
    long_key = 'a' * 40
    fmt = _formatter(structured_data={'id@9': {long_key: 'v'}}, enterprise_id=None)
    record = _log_record(msg='m')
    with patch('syslog_sd_logging.formatter.get_localzone', return_value=_FIXED_OFFSET_7):
        out = fmt.build_msg(record, lambda r: r.getMessage())
    assert b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa="' in out


def test_build_sd_id_truncates_long_name_before_pen_suffix() -> None:
    """SD-NAME longer than allowed with enterprise suffix is truncated (non-registered)."""
    pen = '32473'
    long_local = 'x' * 35
    sd_key = f'{long_local}@{pen}'
    fmt = _formatter(structured_data={sd_key: {'a': 'b'}}, enterprise_id=None)
    record = _log_record(msg='m')
    with patch('syslog_sd_logging.formatter.get_localzone', return_value=_FIXED_OFFSET_7):
        out = fmt.build_msg(record, lambda r: r.getMessage())
    # 31 - len(pen) = 26 chars from local name + @ + pen in SD-ID
    truncated_local = long_local[: 31 - len(pen)]
    expected_id = f'{truncated_local}@{pen}'.encode()
    assert expected_id in out

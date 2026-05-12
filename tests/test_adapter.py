"""Tests for the ``Rfc5424SysLogAdapter`` class."""

import logging
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from syslog_sd_logging import NILVALUE, NOTICE, Rfc5424SysLogAdapter, Rfc5424SysLogHandler
from tests.test_data import address, message, sd1, sd2


@pytest.mark.parametrize(
    ('handler_kwargs', 'adapter_kwargs', 'logger_kwargs', 'expected'),
    [
        pytest.param(
            {
                'address': address,
                'structured_data': sd1,
                'app_name': 'my_appname',
                'hostname': 'my-hostname',
                'procid': '1234',
            },
            {},
            {'extra': {'structured_data': sd2, 'msgid': 'my_msgid'}},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 my-hostname my_appname 1234'
                b' my_msgid [my_sd_id1@32473 my_key1="my_value1"]'
                b'[my_sd_id2@32473 my_key2="my_value2"] '
                b'\xef\xbb\xbfThis is an interesting message'
            ),
            id='sd_and_msgid_from_logger_extra',
        ),
        pytest.param(
            {
                'address': address,
                'structured_data': sd1,
                'app_name': 'my_appname',
                'hostname': 'my-hostname',
                'procid': '1234',
            },
            {'enable_extra_levels': True},
            {'extra': {'structured_data': sd2, 'msgid': 'my_msgid'}},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 my-hostname my_appname 1234'
                b' my_msgid [my_sd_id1@32473 my_key1="my_value1"]'
                b'[my_sd_id2@32473 my_key2="my_value2"] '
                b'\xef\xbb\xbfThis is an interesting message'
            ),
            id='sd_and_msgid_from_logger_extra_enable_extra_levels',
        ),
        pytest.param(
            {
                'address': address,
                'structured_data': sd1,
                'app_name': 'my_appname',
                'hostname': 'my-hostname',
                'procid': '1234',
            },
            {'extra': {'structured_data': sd2, 'msgid': 'my_msgid'}},
            {},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 my-hostname my_appname 1234'
                b' my_msgid [my_sd_id1@32473 my_key1="my_value1"]'
                b'[my_sd_id2@32473 my_key2="my_value2"] '
                b'\xef\xbb\xbfThis is an interesting message'
            ),
            id='sd_and_msgid_from_adapter_extra',
        ),
        pytest.param(
            {
                'address': address,
                'structured_data': sd1,
                'app_name': 'my_appname',
                'hostname': 'my-hostname',
                'procid': '1234',
            },
            {'extra': {'structured_data': sd2, 'msgid': 'my_msgid'}, 'enable_extra_levels': True},
            {},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 my-hostname my_appname 1234'
                b' my_msgid [my_sd_id1@32473 my_key1="my_value1"]'
                b'[my_sd_id2@32473 my_key2="my_value2"] '
                b'\xef\xbb\xbfThis is an interesting message'
            ),
            id='sd_and_msgid_from_adapter_extra_enable_extra_levels',
        ),
        pytest.param(  # 4
            {
                'address': address,
                'structured_data': sd1,
                'app_name': 'my_appname',
                'hostname': 'my-hostname',
                'procid': '1234',
            },
            {'enable_extra_levels': True},
            {'structured_data': sd2, 'msgid': 'my_msgid'},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 my-hostname my_appname 1234'
                b' my_msgid [my_sd_id1@32473 my_key1="my_value1"]'
                b'[my_sd_id2@32473 my_key2="my_value2"] '
                b'\xef\xbb\xbfThis is an interesting message'
            ),
            id='sd_and_msgid_from_adapter_kwargs_enable_extra_levels_procid',
        ),
        pytest.param(  # 5
            {
                'address': address,
                'structured_data': sd1,
                'app_name': 'my_appname',
                'hostname': 'my-hostname',
                'procid': '1234',
            },
            {'enable_extra_levels': True},
            {'procid': 'some_procid'},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 my-hostname my_appname some_procid'
                b' - [my_sd_id1@32473 my_key1="my_value1"] '
                b'\xef\xbb\xbfThis is an interesting message'
            ),
            id='procid_from_adapter_kwargs_enable_extra_levels',
        ),
        pytest.param(
            {
                'address': address,
                'structured_data': sd1,
                'app_name': 'my_appname',
                'hostname': 'my-hostname',
                'procid': '1234',
            },
            {'enable_extra_levels': True},
            {'appname': 'some_appname'},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 my-hostname some_appname 1234'
                b' - [my_sd_id1@32473 my_key1="my_value1"] '
                b'\xef\xbb\xbfThis is an interesting message'
            ),
            id='appname_from_logger_extra_enable_extra_levels',
        ),
        pytest.param(
            {
                'address': address,
                'structured_data': sd1,
                'app_name': 'my_appname',
                'hostname': 'my-hostname',
                'procid': '1234',
            },
            {'enable_extra_levels': True},
            {'hostname': 'some-hostname'},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 some-hostname my_appname 1234'
                b' - [my_sd_id1@32473 my_key1="my_value1"] '
                b'\xef\xbb\xbfThis is an interesting message'
            ),
            id='hostname_from_logger_extra_enable_extra_levels',
        ),
        pytest.param(
            {'address': address},
            {'enable_extra_levels': True},
            {'hostname': NILVALUE, 'appname': NILVALUE, 'procid': NILVALUE},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 - - - - - '
                b'\xef\xbb\xbfThis is an interesting message'
            ),
            id='hostname_app_name_procid_nilvalue',
        ),
    ],
)
def test_adapter(
    logger: logging.Logger,
    handler_kwargs: dict[str, Any],
    adapter_kwargs: dict[str, Any],
    logger_kwargs: dict[str, Any],
    expected: bytes,
) -> None:
    """Test that the adapter is emitted correctly."""
    sh = Rfc5424SysLogHandler(**handler_kwargs)
    logger.addHandler(sh)
    adapter = Rfc5424SysLogAdapter(logger, **adapter_kwargs)
    with patch.object(sh.transport, 'transmit') as transmit_mock:
        adapter.info(message, **logger_kwargs)
        transmit_mock.assert_called_once_with(expected)
        transmit_mock.reset_mock()

        adapter.log(logging.INFO, message, **logger_kwargs)
        transmit_mock.assert_called_once_with(expected)
        transmit_mock.reset_mock()
    logger.removeHandler(sh)


def test_log(logger_with_udp_handler: tuple[logging.Logger, MagicMock]) -> None:
    """Test that the log method is emitted correctly."""
    expected_msg = (
        b'<13>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
        b' - - \xef\xbb\xbfThis is an interesting message'
    )
    logger, transmit_mock = logger_with_udp_handler
    adapter = Rfc5424SysLogAdapter(logger, enable_extra_levels=True)
    adapter.log(NOTICE, message)
    transmit_mock.assert_called_once_with(expected_msg)


def test_log_not_enabled(adapter_with_udp_handler: tuple[Rfc5424SysLogAdapter, MagicMock]) -> None:
    """Test that the log method is emitted correctly when extra levels are not enabled."""
    expected_msg = (
        b'<12>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
        b' - - \xef\xbb\xbfThis is an interesting message'
    )
    adapter, transmit_mock = adapter_with_udp_handler
    adapter.log(NOTICE, message)
    transmit_mock.assert_called_once_with(expected_msg)


def test_emergency(logger_with_udp_handler: tuple[logging.Logger, MagicMock]) -> None:
    """Test that the emergency method is emitted correctly."""
    expected_msg = (
        b'<8>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
        b' - - \xef\xbb\xbfThis is an interesting message'
    )
    logger, transmit_mock = logger_with_udp_handler
    adapter = Rfc5424SysLogAdapter(logger, enable_extra_levels=True)
    adapter.emerg(message)
    transmit_mock.assert_called_once_with(expected_msg)


def test_emergency_not_enabled(
    adapter_with_udp_handler: tuple[Rfc5424SysLogAdapter, MagicMock],
) -> None:
    """Test that the emergency method is emitted correctly when extra levels are not enabled."""
    expected_msg = (
        b'<10>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
        b' - - \xef\xbb\xbfThis is an interesting message'
    )
    adapter, transmit_mock = adapter_with_udp_handler
    adapter.emergency(message)
    transmit_mock.assert_called_once_with(expected_msg)


def test_alert(logger_with_udp_handler: tuple[logging.Logger, MagicMock]) -> None:
    """Test that the alert method is emitted correctly."""
    expected_msg = (
        b'<9>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
        b' - - \xef\xbb\xbfThis is an interesting message'
    )
    logger, transmit_mock = logger_with_udp_handler
    adapter = Rfc5424SysLogAdapter(logger, enable_extra_levels=True)
    adapter.alert(message)
    transmit_mock.assert_called_once_with(expected_msg)


def test_alert_not_enabled(
    adapter_with_udp_handler: tuple[Rfc5424SysLogAdapter, MagicMock],
) -> None:
    """Test that the alert method is emitted correctly when extra levels are not enabled."""
    expected_msg = (
        b'<10>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
        b' - - \xef\xbb\xbfThis is an interesting message'
    )
    adapter, transmit_mock = adapter_with_udp_handler
    adapter.alert(message)
    transmit_mock.assert_called_once_with(expected_msg)


def test_notice(logger_with_udp_handler: tuple[logging.Logger, MagicMock]) -> None:
    """Test that the notice method is emitted correctly."""
    expected_msg = (
        b'<13>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
        b' - - \xef\xbb\xbfThis is an interesting message'
    )
    logger, transmit_mock = logger_with_udp_handler
    adapter = Rfc5424SysLogAdapter(logger, enable_extra_levels=True)
    adapter.notice(message)
    transmit_mock.assert_called_once_with(expected_msg)


def test_notice_not_enabled(
    adapter_with_udp_handler: tuple[Rfc5424SysLogAdapter, MagicMock],
) -> None:
    """Test that the notice method is emitted correctly when extra levels are not enabled."""
    expected_msg = (
        b'<12>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
        b' - - \xef\xbb\xbfThis is an interesting message'
    )
    adapter, transmit_mock = adapter_with_udp_handler
    adapter.notice(message)
    transmit_mock.assert_called_once_with(expected_msg)


@pytest.mark.parametrize(
    ('method', 'expected_prival'),
    [
        ('debug', 15),
        ('info', 14),
        ('notice', 13),
        ('warning', 12),
        ('error', 11),
        ('critical', 10),
        ('alert', 9),
        ('emergency', 8),
    ],
)
def test_empty_msg(
    method: str,
    expected_prival: int,
    logger_with_udp_handler: tuple[logging.Logger, MagicMock],
) -> None:
    """Test that the empty message is emitted correctly."""
    logger, transmit_mock = logger_with_udp_handler
    adapter = Rfc5424SysLogAdapter(logger, enable_extra_levels=True)

    expected_msg = (
        f'<{expected_prival}>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111 - -'
    )
    getattr(adapter, method)(None)
    transmit_mock.assert_called_once_with(expected_msg.encode())
    transmit_mock.reset_mock()

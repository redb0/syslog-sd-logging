"""Tests for the RFC 5424 PROCID field emitted by ``Rfc5424SysLogHandler``."""

import logging
import socket
from typing import Any
from unittest.mock import patch

import pytest

from syslog_sd_logging import NILVALUE, Rfc5424SysLogHandler
from tests.test_data import SomeClass, address, message


@pytest.mark.parametrize(
    ('handler_kwargs', 'expected'),
    [
        pytest.param(
            {'address': address},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='default',
        ),
        pytest.param(
            {'address': address, 'procid': ''},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='empty',
        ),
        pytest.param(
            {'address': address, 'procid': None},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='none',
        ),
        pytest.param(
            {'address': address, 'procid': NILVALUE},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root -'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='nilvalue',
        ),
        pytest.param(
            {'address': address, 'procid': '1234'},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 1234'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='int_in_str',
        ),
        pytest.param(
            {
                'address': address,
                'procid': (
                    '1234123412341234123412341234123412341234123412341234123412341234123412341234'
                    '1234123412341234123412341234123412341234123412341234aaa'
                ),
            },
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 1234123412341234123412'
                b'34123412341234123412341234123412341234123412341234123412341234123412341234123412'
                b'34123412341234123412341234'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='long_str_truncated',
        ),
        pytest.param(
            {'address': address, 'procid': 1234},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 1234'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='int_coerced',
        ),
        pytest.param(
            {'address': address, 'procid': '12 \nΔ34'},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 1234'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='sanitized_non_printable',
        ),
        pytest.param(
            {'address': address, 'procid': SomeClass()},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root MyClassObject'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='object_str',
        ),
    ],
)
def test_procid(
    logger: logging.Logger,
    handler_kwargs: dict[str, Any],
    expected: bytes,
) -> None:
    """Check PROCID when ``procid`` is set on the handler."""
    sh = Rfc5424SysLogHandler(**handler_kwargs)
    logger.addHandler(sh)
    with patch.object(sh.transport, 'transmit') as transmit_mock:
        logger.info(message)
        transmit_mock.assert_called_once_with(expected)
        transmit_mock.reset_mock()

        logger.log(logging.INFO, message)
        transmit_mock.assert_called_once_with(expected)
        transmit_mock.reset_mock()

        logging.info(message)  # noqa: LOG015
        transmit_mock.assert_called_once_with(expected)
        transmit_mock.reset_mock()
    logger.removeHandler(sh)


@pytest.mark.parametrize(
    ('handler_kwargs', 'expected'),
    [
        pytest.param(
            {'address': address, 'socket_type': socket.SOCK_STREAM},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='default',
        ),
        pytest.param(
            {'address': address, 'procid': '1234', 'socket_type': socket.SOCK_STREAM},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 1234'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='int_in_str',
        ),
        pytest.param(
            {'address': address, 'procid': 1234, 'socket_type': socket.SOCK_STREAM},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 1234'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='int_coerced',
        ),
        pytest.param(
            {'address': address, 'procid': '12 \nΔ34', 'socket_type': socket.SOCK_STREAM},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 1234'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='sanitized_non_printable',
        ),
        pytest.param(
            {'address': address, 'procid': SomeClass(), 'socket_type': socket.SOCK_STREAM},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root MyClassObject'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='object_str',
        ),
    ],
)
def test_procid_tcp(
    logger: logging.Logger,
    handler_kwargs: dict[str, Any],
    expected: bytes,
) -> None:
    """Check PROCID when ``procid`` is set on the handler over TCP."""
    sh = Rfc5424SysLogHandler(**handler_kwargs)
    logger.addHandler(sh)
    with patch.object(sh.transport, 'transmit') as transmit_mock:
        logger.info(message)
        transmit_mock.assert_called_once_with(expected)
        transmit_mock.reset_mock()

        logger.log(logging.INFO, message)
        transmit_mock.assert_called_once_with(expected)
        transmit_mock.reset_mock()

        logging.info(message)  # noqa: LOG015
        transmit_mock.assert_called_once_with(expected)
        transmit_mock.reset_mock()
    logger.removeHandler(sh)

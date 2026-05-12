"""Tests for the RFC 5424 APP-NAME field emitted by ``Rfc5424SysLogHandler``."""

import logging
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
            id='no_app_name',
        ),
        pytest.param(
            {'address': address, 'app_name': ''},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='app_name_empty_string',
        ),
        pytest.param(
            {'address': address, 'app_name': NILVALUE},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname - 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='app_name_nilvalue',
        ),
        pytest.param(
            {'address': address, 'app_name': None},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='app_name_none',
        ),
        pytest.param(
            {'address': address, 'app_name': 'my_appname'},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname my_appname 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='app_name_literal',
        ),
        pytest.param(
            {
                'address': address,
                'app_name': 'my_loooooooooooooooooooooooooooooooooooooooooong_appname',
            },
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname '
                b'my_loooooooooooooooooooooooooooooooooooooooooong 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='app_name_truncated_long',
        ),
        pytest.param(
            {'address': address, 'app_name': 1234},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname 1234 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='app_name_int_coerced',
        ),
        pytest.param(
            {'address': address, 'app_name': 'my_Δapp \nname'},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname my_appname 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='app_name_sanitized_non_printable',
        ),
        pytest.param(
            {'address': address, 'app_name': SomeClass()},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname MyClassObject 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='app_name_object_str',
        ),
    ],
)
def test_appname(
    logger: logging.Logger,
    handler_kwargs: dict[str, Any],
    expected: bytes,
) -> None:
    """Assert APP-NAME in the syslog payload when ``app_name`` is set on the handler.

    We check that the handler behaves the same way, regardless of whether the
    recording has passed through ``Logger.info``, via ``Logger.log``, or via a
    convenient shortcut ``logging.info`` on root.
    """
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
            {'address': address},
            b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
            b' - - \xef\xbb\xbfThis is an interesting message',
            id='extra_omit_appname',
        ),
        pytest.param(
            {'address': address, 'appname': ''},
            b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
            b' - - \xef\xbb\xbfThis is an interesting message',
            id='extra_empty_string',
        ),
        pytest.param(
            {'address': address, 'appname': NILVALUE},
            b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname - 111'
            b' - - \xef\xbb\xbfThis is an interesting message',
            id='extra_nilvalue',
        ),
        pytest.param(
            {'address': address, 'appname': None},
            b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
            b' - - \xef\xbb\xbfThis is an interesting message',
            id='extra_none',
        ),
        pytest.param(
            {'address': address, 'appname': 'my_appname'},
            b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname my_appname 111'
            b' - - \xef\xbb\xbfThis is an interesting message',
            id='extra_literal',
        ),
        pytest.param(
            {
                'address': address,
                'appname': 'my_loooooooooooooooooooooooooooooooooooooooooong_appname',
            },
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname '
                b'my_loooooooooooooooooooooooooooooooooooooooooong 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='extra_truncated_long',
        ),
        pytest.param(
            {'address': address, 'appname': 1234},
            b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname 1234 111'
            b' - - \xef\xbb\xbfThis is an interesting message',
            id='extra_int_coerced',
        ),
        pytest.param(
            {'address': address, 'appname': 'my_Δapp \nname'},
            b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname my_appname 111'
            b' - - \xef\xbb\xbfThis is an interesting message',
            id='extra_sanitized_non_printable',
        ),
        pytest.param(
            {'address': address, 'appname': SomeClass()},
            b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname MyClassObject 111'
            b' - - \xef\xbb\xbfThis is an interesting message',
            id='extra_object_str',
        ),
    ],
)
def test_appname_with_extra(
    logger: logging.Logger,
    handler_kwargs: dict[str, Any],
    expected: bytes,
) -> None:
    """Assert APP-NAME when passed in ``extra`` (``record.appname``), not on the handler."""
    sh = Rfc5424SysLogHandler(address=handler_kwargs['address'])
    logger.addHandler(sh)
    with patch.object(sh.transport, 'transmit') as transmit_mock:
        logger.info(message, extra=handler_kwargs)
        transmit_mock.assert_called_once_with(expected)
        transmit_mock.reset_mock()

        logger.log(logging.INFO, message, extra=handler_kwargs)
        transmit_mock.assert_called_once_with(expected)
        transmit_mock.reset_mock()

        logging.info(message, extra=handler_kwargs)  # noqa: LOG015
        transmit_mock.assert_called_once_with(expected)
        transmit_mock.reset_mock()
    logger.removeHandler(sh)

"""Tests for the RFC 5424 MSGID field emitted by ``Rfc5424SysLogHandler``."""

import logging
from typing import Any
from unittest.mock import patch

import pytest

from syslog_sd_logging import NILVALUE, Rfc5424SysLogHandler
from tests.test_data import SomeClass, address, message


@pytest.mark.parametrize(
    ('logger_kwargs', 'expected'),
    [
        pytest.param(
            {},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='no_msgid',
        ),
        pytest.param(
            {'extra': {'msgid': ''}},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='msgid_empty_string',
        ),
        pytest.param(
            {'extra': {'msgid': None}},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='msgid_none',
        ),
        pytest.param(
            {'extra': {'msgid': NILVALUE}},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='msgid_nilvalue',
        ),
        pytest.param(
            {'extra': {'msgid': 'my_msgid'}},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' my_msgid - \xef\xbb\xbfThis is an interesting message'
            ),
            id='msgid_literal',
        ),
        pytest.param(
            {'extra': {'msgid': 'my_loooooooooooooooooooooooooong_msgid'}},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' my_loooooooooooooooooooooooooong - \xef\xbb\xbfThis is an interesting message'
            ),
            id='msgid_truncated_long',
        ),
        pytest.param(
            {'extra': {'msgid': 1234}},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' 1234 - \xef\xbb\xbfThis is an interesting message'
            ),
            id='msgid_int_coerced',
        ),
        pytest.param(
            {'extra': {'msgid': 'my_Δmsg \nid'}},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' my_msgid - \xef\xbb\xbfThis is an interesting message'
            ),
            id='msgid_sanitized_non_printable',
        ),
        pytest.param(
            {'extra': {'msgid': SomeClass()}},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' MyClassObject - \xef\xbb\xbfThis is an interesting message'
            ),
            id='msgid_object_str',
        ),
    ],
)
def test_msgid(
    logger: logging.Logger,
    logger_kwargs: dict[str, Any],
    expected: bytes,
) -> None:
    """Check MSGID when ``msgid`` is set on the handler."""
    sh = Rfc5424SysLogHandler(address=address)
    logger.addHandler(sh)
    with patch.object(sh.transport, 'transmit') as transmit_mock:
        logger.info(message, **logger_kwargs)
        transmit_mock.assert_called_once_with(expected)
        transmit_mock.reset_mock()

        logger.log(logging.INFO, message, **logger_kwargs)
        transmit_mock.assert_called_once_with(expected)
        transmit_mock.reset_mock()

        logging.info(message, **logger_kwargs)  # noqa: LOG015
        transmit_mock.assert_called_once_with(expected)
        transmit_mock.reset_mock()
    logger.removeHandler(sh)

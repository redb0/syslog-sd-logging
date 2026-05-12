"""Tests for the RFC 5424 MSG field emitted by ``Rfc5424SysLogHandler``."""

import logging
from unittest.mock import patch

from syslog_sd_logging import Rfc5424SysLogHandler
from tests.test_data import address, message


def test_unicode_msg(logger: logging.Logger) -> None:
    """Check that a Unicode message is emitted correctly."""
    sh = Rfc5424SysLogHandler(address=address)
    logger.addHandler(sh)
    message = 'This is a ℛℯα∂α♭ℓℯ message'  # noqa: RUF001
    with patch.object(sh.transport, 'transmit') as transmit_mock:
        logger.info(message)
        expected = (
            b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
            b' - - \xef\xbb\xbfThis is a \xe2\x84\x9b\xe2\x84\xaf\xce\xb1\xe2\x88\x82'
            b'\xce\xb1\xe2\x99\xad\xe2\x84\x93\xe2\x84\xaf message'
        )
        transmit_mock.assert_called_once_with(expected)
        transmit_mock.reset_mock()
    logger.removeHandler(sh)


def test_msg_any(logger: logging.Logger) -> None:
    """Check that a non-Unicode message is emitted correctly."""
    sh = Rfc5424SysLogHandler(address=address, msg_as_utf8=False)
    logger.addHandler(sh)
    with patch.object(sh.transport, 'transmit') as transmit_mock:
        logger.info(message)
        expected = (
            b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
            b' - - This is an interesting message'
        )
        transmit_mock.assert_called_once_with(expected)
        transmit_mock.reset_mock()
    logger.removeHandler(sh)


def test_empty_msg(logger: logging.Logger) -> None:
    """Check that an empty message is emitted correctly."""
    sh = Rfc5424SysLogHandler(address=address, msg_as_utf8=False)
    logger.addHandler(sh)
    with patch.object(sh.transport, 'transmit') as transmit_mock:
        logger.info(None)
        expected = b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111 - -'
        transmit_mock.assert_called_once_with(expected)
        transmit_mock.reset_mock()
    logger.removeHandler(sh)

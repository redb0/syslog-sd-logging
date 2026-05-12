"""Tests for the RFC 5424 TIMESTAMP field emitted by ``Rfc5424SysLogHandler``."""

import logging
from typing import Any
from unittest.mock import patch

import pytest

from syslog_sd_logging import Rfc5424SysLogHandler
from tests.test_data import address, message


@pytest.mark.parametrize(
    ('handler_kwargs', 'expected'),
    [
        pytest.param(
            {'address': address, 'utc_timestamp': True},
            (
                b'<14>1 2000-01-01T11:11:11.111111+00:00 test-hostname root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='utc_timestamp',
        ),
        pytest.param(
            {
                'address': address,
            },
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='default',
        ),
    ],
)
def test_timestamp(
    logger: logging.Logger,
    handler_kwargs: dict[str, Any],
    expected: bytes,
) -> None:
    """Check TIMESTAMP when ``utc_timestamp`` is set on the handler."""
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

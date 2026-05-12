"""Tests for the RFC 5424 HOSTNAME field from ``Rfc5424SysLogHandler``.

Covers ``hostname`` on the handler vs overrides in ``extra``, plus ``NILVALUE``,
sanitisation, and truncation. Each case is emitted via ``Logger.info``,
``Logger.log``, and ``logging.info`` so all stdlib entry paths match.
"""

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
            id='no_hostname',
        ),
        pytest.param(
            {'address': address, 'hostname': ''},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='hostname_empty_string',
        ),
        pytest.param(
            {'address': address, 'hostname': NILVALUE},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 - root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='hostname_nilvalue',
        ),
        pytest.param(
            {'address': address, 'hostname': None},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='hostname_none',
        ),
        pytest.param(
            {'address': address, 'hostname': 'my-hostname'},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 my-hostname root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='hostname_literal',
        ),
        pytest.param(
            {
                'address': address,
                'hostname': (
                    'my-loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo'
                    'oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo'
                    'oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo'
                    'ooooooooooooooooooooooooong-hostname'
                ),
            },
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 my-loooooooooooooooooooooooooooooooooooo'
                b'ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo'
                b'ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo'
                b'ooooooooooooooooooooooooooooooooooooooooooooooooooooooong root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='hostname_truncated_long',
        ),
        pytest.param(
            {'address': address, 'hostname': 1234},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 1234 root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='hostname_int_coerced',
        ),
        pytest.param(
            {'address': address, 'hostname': 'my-Δhost \nname'},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 my-hostname root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='hostname_sanitized_non_printable',
        ),
        pytest.param(
            {'address': address, 'hostname': SomeClass()},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 MyClassObject root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='hostname_object_str',
        ),
    ],
)
def test_hostname_from_init(
    logger: logging.Logger,
    handler_kwargs: dict[str, Any],
    expected: bytes,
) -> None:
    """Check HOSTNAME when ``hostname`` is set on ``Rfc5424SysLogHandler``.

    Args:
        logger: Shared logger (time/zone/hostname patched in ``conftest``).
        handler_kwargs: Passed to the handler (``address`` and optional ``hostname``).
        expected: Full RFC 5424 syslog payload for that record.
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
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='extra_omit_hostname',
        ),
        pytest.param(
            {'address': address, 'hostname': ''},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='extra_empty_string',
        ),
        pytest.param(
            {'address': address, 'hostname': NILVALUE},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 - root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='extra_nilvalue',
        ),
        pytest.param(
            {'address': address, 'hostname': None},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='extra_none',
        ),
        pytest.param(
            {'address': address, 'hostname': 'my-hostname'},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 my-hostname root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='extra_literal',
        ),
        pytest.param(
            {
                'address': address,
                'hostname': (
                    'my-loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo'
                    'oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo'
                    'oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo'
                    'ooooooooooooooooooooooooong-hostname'
                ),
            },
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 my-loooooooooooooooooooooooooooooooooooo'
                b'ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo'
                b'ooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo'
                b'ooooooooooooooooooooooooooooooooooooooooooooooooooooooong root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='extra_truncated_long',
        ),
        pytest.param(
            {'address': address, 'hostname': 1234},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 1234 root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='extra_int_coerced',
        ),
        pytest.param(
            {'address': address, 'hostname': 'my-Δhost \nname'},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 my-hostname root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='extra_sanitized_non_printable',
        ),
        pytest.param(
            {'address': address, 'hostname': SomeClass()},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 MyClassObject root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='extra_object_str',
        ),
    ],
)
def test_hostname_extra(
    logger: logging.Logger,
    handler_kwargs: dict[str, Any],
    expected: bytes,
) -> None:
    """Check HOSTNAME when values come from ``extra`` (per-message), not handler init.

    Args:
        logger: Shared logger fixture.
        handler_kwargs: ``address`` plus optional ``hostname``; applied as ``extra`` on each emit.
        expected: Expected full RFC 5424 payload.
    """
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

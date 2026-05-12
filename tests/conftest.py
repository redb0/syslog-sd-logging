"""Conftest file for the tests."""

import logging
import socket
from collections.abc import Generator
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest
import pytz

from syslog_sd_logging import Rfc5424SysLogAdapter, Rfc5424SysLogHandler

if TYPE_CHECKING:
    from pytz.tzinfo import BaseTzInfo

# LogRecord time base used across tests expecting 2000-01-01T18:11:11.111111+07:00 (Vostok).
# Python 3.13+ sets record.created from time.time_ns() / 1e9, so time.time() alone is ignored.
_FIXED_LOG_CREATED_S = 946725071.111111
_FIXED_LOG_CREATED_NS = 946_725_071_111_111_000


@pytest.fixture
def timezone() -> 'BaseTzInfo':
    """Fixture to return the timezone for the tests."""
    return pytz.timezone('Antarctica/Vostok')


@pytest.fixture
def address() -> tuple[str, int]:
    """Fixture to return the address for the tests."""
    return ('127.0.0.1', 514)


def connect_mock(_: Any) -> None:  # noqa: ANN401
    """Mock function to return the connect for the tests."""
    return


@pytest.fixture
def logger(timezone: 'BaseTzInfo') -> Generator[logging.Logger, None, None]:
    """Fixture to return the logger for the tests."""
    with (
        patch('logging.os.getpid', return_value=111),
        patch('logging.time.time', return_value=_FIXED_LOG_CREATED_S),
        patch('logging.time.time_ns', return_value=_FIXED_LOG_CREATED_NS),
        patch('syslog_sd_logging.formatter.get_localzone', return_value=timezone),
        patch('syslog_sd_logging.handler.socket.gethostname', return_value='test-hostname'),
        patch('logging.handlers.socket.socket.connect', side_effect=connect_mock),
        patch('logging.handlers.socket.socket.sendall', side_effect=connect_mock),
        patch.dict(logging._levelToName),  # noqa: SLF001
        patch.dict(logging._nameToLevel),  # noqa: SLF001
    ):
        logging.raiseExceptions = True
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)
        yield logger

    Rfc5424SysLogAdapter._extra_levels_enabled = False  # noqa: SLF001


@pytest.fixture
def logger_with_udp_handler(
    logger: logging.Logger,
    address: tuple[str, int],
) -> Generator[tuple[logging.Logger, MagicMock], None, None]:
    """Fixture to return the logger with the UDP handler for the tests."""
    sh = Rfc5424SysLogHandler(address=address)
    logger.addHandler(sh)
    with patch.object(sh.transport, 'transmit') as transmit_mock:
        yield logger, transmit_mock
    logger.removeHandler(sh)


@pytest.fixture
def adapter_with_udp_handler(
    logger_with_udp_handler: tuple[logging.Logger, MagicMock],
) -> tuple[Rfc5424SysLogAdapter, MagicMock]:
    """Fixture to return the adapter with the UDP handler for the tests."""
    logger, transmit_mock = logger_with_udp_handler
    adapter = Rfc5424SysLogAdapter(logger)
    return adapter, transmit_mock


@pytest.fixture
def logger_with_tcp_handler(
    logger: logging.Logger,
    address: tuple[str, int],
) -> Generator[tuple[logging.Logger, MagicMock], None, None]:
    """Fixture to return the logger with the TCP handler for the tests."""
    sh = Rfc5424SysLogHandler(address=address, socket_type=socket.SOCK_STREAM)
    logger.addHandler(sh)
    with patch.object(sh.transport, 'transmit') as transmit_mock:
        yield logger, transmit_mock
    logger.removeHandler(sh)

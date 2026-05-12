"""Tests for the RFC 5424 STRUCTURED-DATA field emitted by ``Rfc5424SysLogHandler``."""

import logging
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from syslog_sd_logging import Rfc5424SysLogAdapter, Rfc5424SysLogHandler
from tests.test_data import (
    address,
    message,
    sd1,
    sd1_no_pen,
    sd1_param_none_key,
    sd1_param_none_value,
    sd1_param_object_value,
    sd2,
    sd_multi_id,
    sd_multi_param,
)


@pytest.mark.parametrize(
    ('handler_kwargs', 'logger_kwargs', 'expected'),
    [
        pytest.param(  # 0
            {'address': address},
            {'extra': {'structured_data': sd1}},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - [my_sd_id1@32473 my_key1="my_value1"] \xef\xbb\xbf'
                b'This is an interesting message'
            ),
            id='structured_data_in_extra',
        ),
        pytest.param(  # 1
            {'address': address, 'structured_data': sd1},
            {},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - [my_sd_id1@32473 my_key1="my_value1"] \xef\xbb\xbf'
                b'This is an interesting message'
            ),
            id='structured_data_in_handler',
        ),
        pytest.param(  # 2
            {'address': address, 'structured_data': sd1},
            {'extra': {'structured_data': sd2}},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - [my_sd_id1@32473 my_key1="my_value1"][my_sd_id2@32473 my_key2="my_value2"]'
                b' \xef\xbb\xbfThis is an interesting message'
            ),
            id='structured_data_in_extra_and_handler_different',
        ),
        pytest.param(  # 3
            {'address': address, 'structured_data': sd1},
            {'extra': {'structured_data': sd1}},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - [my_sd_id1@32473 my_key1="my_value1"] \xef\xbb\xbf'
                b'This is an interesting message'
            ),
            id='structured_data_in_extra_and_handler_same',
        ),
        pytest.param(  # 4
            {'address': address},
            {'extra': {'structured_data': sd_multi_id}},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - [my_sd_id1@32473 my_key1="my_value1"][my_sd_id2@32473 my_key2="my_value2"]'
                b' \xef\xbb\xbfThis is an interesting message'
            ),
            id='structured_data_in_extra_multi_id',
        ),
        pytest.param(  # 5
            {'address': address},
            {'extra': {'structured_data': sd_multi_param}},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - [my_sd_id1@32473 my_key1="my_value1" my_key2="my_value2"]'
                b' \xef\xbb\xbfThis is an interesting message'
            ),
            id='structured_data_multi_param',
        ),
        pytest.param(  # 6
            {'address': address, 'enterprise_id': 32473},
            {'extra': {'structured_data': sd1_no_pen}},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - [my_sd_id1@32473 my_key1="my_value1"] \xef\xbb\xbf'
                b'This is an interesting message'
            ),
            id='enterprise_id_in_handler',
        ),
        pytest.param(  # 7
            {'address': address},
            {'extra': {'structured_data': None}},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='structured_data_none_in_extra',
        ),
        pytest.param(  # 8
            {'address': address, 'structured_data': None},
            {},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='structured_data_none_in_handler',
        ),
        pytest.param(  # 9
            {'address': address},
            {'extra': {'structured_data': 'just a string'}},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - - \xef\xbb\xbfThis is an interesting message'
            ),
            id='structured_data_string_in_extra',
        ),
        pytest.param(  # 10
            {'address': address},
            {'extra': {'structured_data': sd1_param_none_value}},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - [my_sd_id1@32473 my_key1=""] \xef\xbb\xbfThis is an interesting message'
            ),
            id='structured_data_none_value_in_extra',
        ),
        pytest.param(  # 11
            {'address': address},
            {'extra': {'structured_data': sd1_param_object_value}},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - [my_sd_id1@32473 my_key1="MyClass Object"] \xef\xbb\xbf'
                b'This is an interesting message'
            ),
            id='structured_data_object_value_in_extra',
        ),
        pytest.param(  # 12
            {'address': address},
            {'extra': {'structured_data': sd1_param_none_key}},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - [my_sd_id1@32473 None="my_value1"] \xef\xbb\xbfThis is an interesting message'
            ),
            id='structured_data_none_key_in_extra',
        ),
        pytest.param(  # 13
            {'address': address},
            {'extra': {'structured_data': {'my_sd_id1@32473': {'my_= ]"Δkey1': 'my_value1'}}}},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - [my_sd_id1@32473 my_key1="my_value1"] \xef\xbb\xbf'
                b'This is an interesting message'
            ),
            id='structured_data_invalid_key_in_extra',
        ),
        pytest.param(  # 14
            {'address': address},
            {'extra': {'structured_data': {'my_sd_id1@32473': {'my_key1': 'my]_\\value"\n1'}}}},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - [my_sd_id1@32473 my_key1="my\\]_\\\\value\\"\n1"] \xef\xbb\xbf'
                b'This is an interesting message'
            ),
            id='structured_data_invalid_value_in_extra',
        ),
        pytest.param(  # 15
            {'address': address},
            {'extra': {'structured_data': {'my_sd_id1@32473': None}}},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - [my_sd_id1@32473] \xef\xbb\xbfThis is an interesting message'
            ),
            id='structured_data_not_values',
        ),
        pytest.param(  # 16
            {'address': address},
            {'extra': {'structured_data': {'my_=sd _id ]\n\r"Δ1@32473': {'my_key1': 'my_value1'}}}},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - [my_sd_id1@32473 my_key1="my_value1"] \xef\xbb\xbf'
                b'This is an interesting message'
            ),
            id='structured_data_invalid_id',
        ),
        pytest.param(  # 17
            {'address': address},
            {'extra': {'structured_data': {'my_@sd_id1@32473': {'my_key1': 'my_value1'}}}},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - [my_sd_id1@32473 my_key1="my_value1"] \xef\xbb\xbf'
                b'This is an interesting message'
            ),
            id='structured_data_multiple_@',
        ),
        pytest.param(  # 18
            {'address': address},
            {'extra': {'structured_data': {'my_sd_id1@32473': {'my_key1': 'my_Δ_value1'}}}},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - [my_sd_id1@32473 my_key1="my_\xce\x94_value1"] \xef\xbb\xbf'
                b'This is an interesting message'
            ),
            id='non_printable_value',
        ),
        pytest.param(  # 19
            {'address': address},
            {
                'extra': {
                    'structured_data': {
                        'my_sddddddddddddddddddddddddddddddddd_ID@32473': {'my_key1': 'my_value1'},
                    },
                },
            },
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - [my_sdddddddddddddddddddddd@32473 my_key1="my_value1"] '
                b'\xef\xbb\xbfThis is an interesting message'
            ),
            id='too_long_id_with_enterprise_id',
        ),
        pytest.param(  # 20
            {'address': address, 'enterprise_id': 32473},
            {
                'extra': {
                    'structured_data': {
                        'my_sddddddddddddddddddddddddddddddddd_ID': {'my_key1': 'my_value1'},
                    },
                },
            },
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - [my_sdddddddddddddddddddddd@32473 my_key1="my_value1"]'
                b' \xef\xbb\xbfThis is an interesting message'
            ),
            id='too_long_id_with_enterprise_id_in_handler',
        ),
        pytest.param(  # 21
            {'address': address, 'enterprise_id': 32473},
            {'extra': {'structured_data': {'timeQuality': {'isSynced': '1'}}}},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - [timeQuality isSynced="1"]'
                b' \xef\xbb\xbfThis is an interesting message'
            ),
            id='time_quality',
        ),
        pytest.param(  # 22
            {'address': address, 'enterprise_id': '32473.1.2'},
            {'extra': {'structured_data': sd1_no_pen}},
            (
                b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
                b' - [my_sd_id1@32473.1.2 my_key1="my_value1"] \xef\xbb\xbf'
                b'This is an interesting message'
            ),
            id='sub_identifier',
        ),
    ],
)
def test_sd(
    logger: logging.Logger,
    handler_kwargs: dict[str, Any],
    logger_kwargs: dict[str, Any],
    expected: bytes,
) -> None:
    """Test that structured data."""
    sh = Rfc5424SysLogHandler(**handler_kwargs)
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


@pytest.mark.parametrize(
    ('handler_kwargs', 'logger_kwargs'),
    [
        pytest.param(
            {'address': address},
            {
                'extra': {
                    'structured_data': {
                        'my_sd_id1': {('my_key1', 'my_value1'), ('my_key2', 'my_value2')},
                    },
                },
            },
            id='without_enterprise_id',
        ),
        pytest.param(
            {'address': address},
            {
                'extra': {
                    'structured_data': {
                        'my_sd_id@3247332473324733247332473324735': {'my_key1': 'my_value1'},
                    },
                },
            },
            id='too_long_enterprise_id',
        ),
    ],
)
def test_sd_not_sent(
    logger: logging.Logger,
    handler_kwargs: dict[str, Any],
    logger_kwargs: dict[str, Any],
) -> None:
    """Test that structured data is not sent when the enterprise ID is not set."""
    sh = Rfc5424SysLogHandler(**handler_kwargs)
    logger.addHandler(sh)
    with patch.object(sh.transport, 'transmit') as transmit_mock:
        logger.info(message, **logger_kwargs)
        transmit_mock.assert_not_called()
    logger.removeHandler(sh)


def test_sd_in_message_with_adapter(
    adapter_with_udp_handler: tuple[Rfc5424SysLogAdapter, MagicMock],
) -> None:
    """Test that structured data is sent when the enterprise ID is set."""
    expected_msg = (
        b'<14>1 2000-01-01T18:11:11.111111+07:00 test-hostname root 111'
        b' - [my_sd_id1@32473 my_key1="my_value1"] \xef\xbb\xbfThis is an interesting message'
    )
    adapter, transmit_mock = adapter_with_udp_handler
    adapter.info(message, structured_data=sd1)
    transmit_mock.assert_called_once_with(expected_msg)

"""RFC 5424 syslog message formatting."""

import types
from codecs import BOM_UTF8
from collections.abc import Callable
from datetime import datetime
from logging import LogRecord
from typing import Any

from pytz import utc
from typing_extensions import LiteralString
from tzlocal import get_localzone

NILVALUE = '-'

SP = b' '
# As defined in RFC5424 Section 7
REGISTERED_SD_IDs = ('timeQuality', 'origin', 'meta')
SYSLOG_VERSION = '1'

_MIN_ASCII_CHAR = 33
_MAX_ASCII_CHAR = 126

_MAX_ENTERPRISE_ID_LENGTH = 30
_MAX_SD_ID_LENGTH = 32


def _filter_ascii(str_to_filter: str) -> LiteralString:
    """Filter ASCII characters from a string."""
    return ''.join([x for x in str_to_filter if _MIN_ASCII_CHAR <= ord(x) <= _MAX_ASCII_CHAR])


class Rfc5424Formatter:
    """Build RFC 5424 syslog payloads from :class:`logging.LogRecord` instances."""

    # priorities (these are ordered; RFC 5424 / BSD syslog severity)
    LOG_EMERG = 0
    LOG_ALERT = 1
    LOG_CRIT = 2
    LOG_ERR = 3
    LOG_WARNING = 4
    LOG_NOTICE = 5
    LOG_INFO = 6
    LOG_DEBUG = 7

    priority_map: types.MappingProxyType[str, int] = types.MappingProxyType(
        {
            'DEBUG': LOG_DEBUG,
            'INFO': LOG_INFO,
            'NOTICE': LOG_NOTICE,
            'WARNING': LOG_WARNING,
            'ERROR': LOG_ERR,
            'CRITICAL': LOG_CRIT,
            'ALERT': LOG_ALERT,
            'EMERGENCY': LOG_EMERG,
            'EMERG': LOG_EMERG,
        },
    )

    def __init__(  # noqa: PLR0913
        self,
        *,
        facility: int,
        hostname: str,
        app_name: str | None,
        procid: int | str | None,
        structured_data: dict[str, Any],
        enterprise_id: str | None,
        msg_as_utf8: bool,
        utc_timestamp: bool,
    ) -> None:
        self.facility = facility
        self.hostname = hostname
        self.app_name = app_name
        self.procid = procid
        self.structured_data = structured_data
        self.enterprise_id = enterprise_id
        self.msg_as_utf8 = msg_as_utf8
        self.utc_timestamp = utc_timestamp

    def encode_priority(self, facility: int, priority: str) -> int:
        """Combine syslog facility and severity into a single PRIVAL (RFC 5424 pri component).

        ``facility`` must already be a numeric syslog facility (e.g. ``LOG_USER``).
        ``priority`` is the logging level name (``record.levelname``), looked up in
        ``priority_map``; if the name is unknown, ``LOG_WARNING`` severity is used.

        Returns ``(facility << 3) | severity`` in the range expected for the PRI field.
        """
        return (facility << 3) | self.priority_map.get(priority, self.LOG_WARNING)

    def extract_hostname(self, record: LogRecord) -> LiteralString:
        """Extract the hostname from the record."""
        hostname = getattr(record, 'hostname', self.hostname)
        hostname = hostname or self.hostname or NILVALUE
        return _filter_ascii(str(hostname))

    def extract_app_name(self, record: LogRecord) -> LiteralString:
        """Extract the application name from the record."""
        app_name = getattr(record, 'appname', self.app_name) or getattr(record, 'name', NILVALUE)
        return _filter_ascii(str(app_name))

    def extract_proc_id(self, record: LogRecord) -> LiteralString:
        """Extract the process ID from the record."""
        procid = getattr(record, 'procid', self.procid) or getattr(record, 'process', NILVALUE)
        return _filter_ascii(str(procid))

    def extract_msgid(self, record: LogRecord) -> LiteralString:
        """Extract the message ID from the record."""
        msgid = getattr(record, 'msgid', NILVALUE) or NILVALUE
        return _filter_ascii(str(msgid))

    def extract_enterprise_id(self, record: LogRecord) -> LiteralString | None:
        """Extract the enterprise ID from the record."""
        enterprise_id = getattr(record, 'enterprise_id', self.enterprise_id)
        return None if enterprise_id is None else _filter_ascii(str(enterprise_id))

    def extract_structured_data(self, record: LogRecord) -> dict[str, Any]:
        """Extract the structured data from the record."""
        structured_data = self.structured_data
        record_sd = getattr(record, 'structured_data', {})
        return structured_data | record_sd if isinstance(record_sd, dict) else structured_data

    def build_msg(self, record: LogRecord, format_line: Callable[[LogRecord], str]) -> bytes:
        r"""The syslog message has the following ABNF [RFC5234] definition.

        SYSLOG-MSG      = HEADER SP STRUCTURED-DATA [SP MSG]

        HEADER          = PRI VERSION SP TIMESTAMP SP HOSTNAME
                        SP APP-NAME SP PROCID SP MSGID
        PRI             = "<" PRIVAL ">"
        PRIVAL          = 1*3DIGIT ; range 0 .. 191
        VERSION         = NONZERO-DIGIT 0*2DIGIT
        HOSTNAME        = NILVALUE / 1*255PRINTUSASCII

        APP-NAME        = NILVALUE / 1*48PRINTUSASCII
        PROCID          = NILVALUE / 1*128PRINTUSASCII
        MSGID           = NILVALUE / 1*32PRINTUSASCII

        TIMESTAMP       = NILVALUE / FULL-DATE "T" FULL-TIME
        FULL-DATE       = DATE-FULLYEAR "-" DATE-MONTH "-" DATE-MDAY
        DATE-FULLYEAR   = 4DIGIT
        DATE-MONTH      = 2DIGIT  ; 01-12
        DATE-MDAY       = 2DIGIT  ; 01-28, 01-29, 01-30, 01-31 based on
                                ; month/year
        FULL-TIME       = PARTIAL-TIME TIME-OFFSET
        PARTIAL-TIME    = TIME-HOUR ":" TIME-MINUTE ":" TIME-SECOND
                        [TIME-SECFRAC]
        TIME-HOUR       = 2DIGIT  ; 00-23
        TIME-MINUTE     = 2DIGIT  ; 00-59
        TIME-SECOND     = 2DIGIT  ; 00-59
        TIME-SECFRAC    = "." 1*6DIGIT
        TIME-OFFSET     = "Z" / TIME-NUMOFFSET
        TIME-NUMOFFSET  = ("+" / "-") TIME-HOUR ":" TIME-MINUTE


        STRUCTURED-DATA = NILVALUE / 1*SD-ELEMENT
        SD-ELEMENT      = "[" SD-ID *(SP SD-PARAM) "]"
        SD-PARAM        = PARAM-NAME "=" %d34 PARAM-VALUE %d34
        SD-ID           = SD-NAME
        PARAM-NAME      = SD-NAME
        PARAM-VALUE     = UTF-8-STRING ; characters '"', '\' and
                                     ; ']' MUST be escaped.
        SD-NAME         = 1*32PRINTUSASCII
                        ; except '=', SP, ']', %d34 (")

        MSG             = MSG-ANY / MSG-UTF8
        MSG-ANY         = *OCTET ; not starting with BOM
        MSG-UTF8        = BOM UTF-8-STRING
        BOM             = %xEF.BB.BF

        UTF - 8 - STRING = *OCTET ; UTF - 8 string as specified
                                  ; in RFC 3629

        OCTET = % d00 - 255
        SP = % d32
        PRINTUSASCII = % d33 - 126
        NONZERO - DIGIT = % d49 - 57
        DIGIT = % d48 / NONZERO - DIGIT
        NILVALUE = "-"
        """
        header = self._build_header(record)
        structured_data = self._build_structured_data(record)
        msg = self._build_msg(record, format_line)
        return self._combine(header, structured_data, msg)

    def _build_header(self, record: LogRecord) -> bytes:
        """Build the header of the syslog message.

        HEADER          = PRI VERSION SP TIMESTAMP SP HOSTNAME
                        SP APP-NAME SP PROCID SP MSGID
        PRI             = "<" PRIVAL ">"
        PRIVAL          = 1*3DIGIT ; range 0 .. 191
        VERSION         = NONZERO-DIGIT 0*2DIGIT
        HOSTNAME        = NILVALUE / 1*255PRINTUSASCII

        APP-NAME        = NILVALUE / 1*48PRINTUSASCII
        PROCID          = NILVALUE / 1*128PRINTUSASCII
        MSGID           = NILVALUE / 1*32PRINTUSASCII
        """
        pri = f'<{self.encode_priority(self.facility, record.levelname)}>'
        version = SYSLOG_VERSION
        timestamp = datetime.fromtimestamp(record.created, get_localzone())
        if self.utc_timestamp:
            timestamp = timestamp.astimezone(utc)
        str_timestamp = timestamp.isoformat()
        hostname = self.extract_hostname(record)
        app_name = self.extract_app_name(record)
        proc_id = self.extract_proc_id(record)
        msg_id = self.extract_msgid(record)

        return b''.join(
            (
                pri.encode('ascii'),
                version.encode('ascii'),
                SP,
                str_timestamp.encode('ascii'),
                SP,
                hostname.encode('ascii', 'replace')[:255],
                SP,
                app_name.encode('ascii', 'replace')[:48],
                SP,
                proc_id.encode('ascii', 'replace')[:128],
                SP,
                msg_id.encode('ascii', 'replace')[:32],
            ),
        )

    def _build_structured_data(self, record: LogRecord) -> bytes:
        enterprise_id = self.extract_enterprise_id(record)
        structured_data = self.extract_structured_data(record)
        cleaned_structured_data = []
        for sd_id, sd_params in list(structured_data.items()):
            bytes_sd_id = self._build_sd_id(sd_id, enterprise_id)
            bytes_sd_params = self._build_sd_params(sd_params)

            spacer = SP if bytes_sd_params else b''
            sd_element = b''.join((b'[', bytes_sd_id, spacer, bytes_sd_params, b']'))
            cleaned_structured_data.append(sd_element)

        if not cleaned_structured_data:
            return NILVALUE.encode('ascii')

        return b''.join(cleaned_structured_data)

    def _build_sd_id(self, sd_id: str, enterprise_id: str | None) -> bytes:
        sd_id = _filter_ascii(sd_id)
        sd_id = sd_id.replace('=', '').replace(' ', '').replace(']', '').replace('"', '')

        if '@' not in sd_id and sd_id not in REGISTERED_SD_IDs and enterprise_id is None:
            msg = (
                'Enterprise ID has not been set. Cannot build structured data ID. '
                'Please set a enterprise ID when initializing the syslog handler '
                'or include one in the structured data ID.'
            )
            raise ValueError(msg)

        if '@' in sd_id:
            sd_id, enterprise_id = sd_id.rsplit('@', 1)

        if not enterprise_id:
            msg = 'Enterprise ID is not set. Cannot build structured data ID.'
            raise ValueError(msg)

        if len(enterprise_id) > _MAX_ENTERPRISE_ID_LENGTH:
            msg = 'Enterprise ID is too long. Impossible to build structured data ID.'
            raise ValueError(msg)

        sd_id = sd_id.replace('@', '')
        if len(sd_id) + len(enterprise_id) > _MAX_SD_ID_LENGTH:
            sd_id = sd_id[: 31 - len(enterprise_id)]
        if sd_id not in REGISTERED_SD_IDs:
            sd_id = f'{sd_id}@{enterprise_id}'
        return sd_id.encode('ascii', 'replace')

    def _build_sd_params(self, sd_params: dict[str, Any]) -> bytes:
        cleaned_sd_params = []
        sd_params_pairs = sd_params.items() if isinstance(sd_params, dict) else []

        for raw_param_name, raw_param_value in sd_params_pairs:
            param_name = _filter_ascii(str(raw_param_name))
            param_name = (
                param_name.replace('=', '').replace(' ', '').replace(']', '').replace('"', '')
            )
            param_value = '' if raw_param_value is None else str(raw_param_value)

            param_value = param_value.replace('\\', '\\\\').replace('"', '\\"').replace(']', '\\]')

            bytes_param_name = param_name.encode('ascii', 'replace')[:32]
            bytes_param_value = param_value.encode('utf-8', 'replace')

            sd_param = b''.join((bytes_param_name, b'="', bytes_param_value, b'"'))
            cleaned_sd_params.append(sd_param)

        return SP.join(cleaned_sd_params)

    def _build_msg(
        self,
        record: LogRecord,
        format_line: Callable[[LogRecord], str],
    ) -> bytes | None:
        if not record.msg:
            return None
        msg = format_line(record)
        if self.msg_as_utf8:
            bytes_msg = b''.join((BOM_UTF8, msg.encode('utf-8')))
        else:
            bytes_msg = msg.encode('utf-8')
        return bytes_msg

    def _combine(self, header: bytes, structured_data: bytes, msg: bytes | None) -> bytes:
        if msg is None:
            return SP.join((header, structured_data))

        return SP.join((header, structured_data, msg))

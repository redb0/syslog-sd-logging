"""Handler for RFC 5424 syslog messages."""

import socket
from logging import Handler, LogRecord
from typing import TYPE_CHECKING, Any, overload

from syslog_sd_logging import transport
from syslog_sd_logging._types import AddressType, FramingType, StreamType
from syslog_sd_logging.formatter import Rfc5424Formatter

if TYPE_CHECKING:
    from _typeshed import StrOrBytesPath

EMERGENCY = 70
EMERG = EMERGENCY
ALERT = 60
NOTICE = 25


#  facility codes
LOG_KERN = 0  # kernel messages
LOG_USER = 1  # random user-level messages
LOG_MAIL = 2  # mail system
LOG_DAEMON = 3  # system daemons
LOG_AUTH = 4  # security/authorization messages
LOG_SYSLOG = 5  # messages generated internally by syslogd
LOG_LPR = 6  # line printer subsystem
LOG_NEWS = 7  # network news subsystem
LOG_UUCP = 8  # UUCP subsystem
LOG_CRON = 9  # clock daemon
LOG_AUTHPRIV = 10  # security/authorization messages (private)
LOG_FTP = 11  # FTP daemon
#  other codes through 15 reserved for system use
LOG_LOCAL0 = 16  # reserved for local use
LOG_LOCAL1 = 17  # reserved for local use
LOG_LOCAL2 = 18  # reserved for local use
LOG_LOCAL3 = 19  # reserved for local use
LOG_LOCAL4 = 20  # reserved for local use
LOG_LOCAL5 = 21  # reserved for local use
LOG_LOCAL6 = 22  # reserved for local use
LOG_LOCAL7 = 23  # reserved for local use


class Rfc5424SysLogHandler(Handler):
    """A handler class which sends RFC 5424 formatted logging records to a syslog server.

    Based on the python built-in SyslogHandler class, but simplified in some parts.
    """

    @overload
    def __init__(
        self,
        *,
        address: AddressType | str = ('localhost', transport.SYSLOG_PORT),
        facility: int = LOG_USER,
        socket_type: socket.SocketKind | int = socket.SOCK_DGRAM,
        framing: FramingType = 'non_transparent',
        msg_as_utf8: bool = True,
        hostname: str | None = None,
        app_name: str | None = None,
        procid: int | str | None = None,
        structured_data: dict[str, Any] | None = None,
        enterprise_id: str | None = None,
        utc_timestamp: bool = False,
        timeout: float = 5,
        tls_enable: bool = False,
        tls_ca_bundle: None = None,
        tls_verify: bool = True,
        tls_client_cert: None = None,
        tls_client_key: None = None,
        tls_key_password: None = None,
        stream: StreamType | None = None,
    ) -> None: ...

    @overload
    def __init__(
        self,
        *,
        address: AddressType | str = ('localhost', transport.SYSLOG_PORT),
        facility: int = LOG_USER,
        socket_type: socket.SocketKind | int = socket.SOCK_DGRAM,
        framing: FramingType = 'non_transparent',
        msg_as_utf8: bool = True,
        hostname: str | None = None,
        app_name: str | None = None,
        procid: int | str | None = None,
        structured_data: dict[str, Any] | None = None,
        enterprise_id: str | None = None,
        utc_timestamp: bool = False,
        timeout: float = 5,
        tls_enable: bool = True,
        tls_ca_bundle: 'StrOrBytesPath',
        tls_verify: bool = True,
        tls_client_cert: 'StrOrBytesPath',
        tls_client_key: 'StrOrBytesPath',
        tls_key_password: str | None = None,
        stream: StreamType | None = None,
    ) -> None: ...

    def __init__(  # noqa: PLR0913
        self,
        *,
        address: AddressType | str = ('localhost', transport.SYSLOG_PORT),
        facility: int = LOG_USER,
        socket_type: socket.SocketKind | int = socket.SOCK_DGRAM,
        framing: FramingType = 'non_transparent',
        msg_as_utf8: bool = True,
        hostname: str | None = None,
        app_name: str | None = None,
        procid: int | str | None = None,
        structured_data: dict[str, Any] | None = None,
        enterprise_id: str | None = None,
        utc_timestamp: bool = False,
        timeout: float = 5,
        tls_enable: bool = False,
        tls_ca_bundle: 'StrOrBytesPath | None' = None,
        tls_verify: bool = True,
        tls_client_cert: 'StrOrBytesPath | None' = None,
        tls_client_key: 'StrOrBytesPath | None' = None,
        tls_key_password: str | None = None,
        stream: StreamType | None = None,
    ) -> None:
        """Initialize the Rfc5424SysLogHandler.

        Returns a new instance of the Rfc5424SysLogHandler class intended to communicate with
        a remote machine whose address is given by address in the form of a (host, port) tuple.
        If address is not specified, ``('localhost', 514)`` is used. The address is used to open a
        socket.

        An alternative to providing a (host, port) tuple is providing an address as a
        string, for example `/dev/log`. In this case, a Unix domain socket is used to send the
        message to the syslog. If facility is not specified, LOG_USER is used. The type of
        socket opened depends on the socket_type argument, which defaults to socket.SOCK_DGRAM
        and thus opens a UDP socket. To open a TCP socket (for use with the newer syslog
        daemons such as rsyslog), specify a value of socket.SOCK_STREAM.

        Note that if your server is not listening on UDP port 514, SysLogHandler may appear
        not to work. In that case, check what address you should be using for a domain socket
        - it's system dependent. For example, on Linux it's usually ``/dev/log`` but on OS/X
        it's ``/var/run/syslog``. You'll need to check your platform and use the appropriate
        address (you may need to do this check at runtime if your application needs to run
        on several platforms). On Windows, you pretty much have to use the UDP option.

        As an alternative transport, you can also provide a stream

        Args:
            address (AddressType | str, optional): Address in the form of a (host, port).
                Defaults to ``('localhost', transport.SYSLOG_PORT)``.
            facility (int, optional): Facility of the syslog message.
                One of the ``syslog_sd_logging.LOG_*`` values. Defaults to ``LOG_USER``.
            socket_type (socket.SocketKind | int, optional): Socket type.
                One of the ``socket.SOCK_*`` values. Defaults to ``socket.SOCK_DGRAM``.
            framing (FramingType, optional): Framing type.
                One of the ``syslog_sd_logging.FRAMING_*`` values according to
                RFC6587 section 3.4. Only applies when sockettype is ``socket.SOCK_STREAM`` (TCP)
                and is used to give the syslog server an indication about the boundaries
                of the message. Defaults to ``FRAMING_NON_TRANSPARENT`` which will escape all
                newline characters in the message and end the message with a newline character.
                When set to ``FRAMING_OCTET_COUNTING``, it will prepend the message length to the
                begin of the message.
            msg_as_utf8 (bool, optional): Controls the way the message is sent.
                disabling this parameter sends the message as MSG-ANY (RFC2424 section 6), avoiding
                issues with receivers that don't support the UTF-8 Byte Order Mark (BOM) at
                the beginning of the message. Defaults to ``True``.
            hostname (str | None, optional): The hostname of the system where the message
                originated from. Defaults to the values returned by ``socket.gethostname()``.
            app_name (str | None, optional): The name of the application.
                Defaults to the name of the logger that sent the message.
            procid (int | str | None, optional): The process ID of the sending application.
                Defaults to the ``process`` attribute of the log record.
            structured_data (dict[str, Any] | None, optional): A dictionary with structured data
                that is added to every message. Per message your can add more structured data
                by adding it to the ``extra`` argument of the log function. Defaults to ``None``.
            enterprise_id (str | None, optional): The Private Enterprise Number.
                This is used to compose the structured data IDs when they do not include an
                Enterprise ID and are not one of the reserved structured data IDs. Can be a single
                PEN like ``32473`` or optionally contain sub-identifiers like ``32473.2.6``.
                Defaults to ``None``.
            utc_timestamp (bool, optional): Whether the timestamp should be converted to UTC time
                or kept in the local timezone. Defaults to ``False``.
            timeout (float, optional): Sets the timeout on the connection to the server.
                Defaults to ``5``.
            tls_enable (bool, optional): If set to ``True``, it sets up a TLS/SSL connection
                to the address specified in ``address`` over which the syslog messages will be sent.
                Default to ``False``.
            tls_ca_bundle (StrOrBytesPath | None, optional): The path to a bundle of CA certificates
                used for validating the remote server's identity. If set to ``None``, it will try
                to load the default CA as described in
                https://docs.python.org/3/library/ssl.html#ssl.SSLContext.load_verify_locations.
                Defaults to ``None``.
            tls_verify (bool, optional): Whether to verify the certificate of the server.
                Defaults to ``True``.
            tls_client_cert (StrOrBytesPath | None, optional): Path to a file containing a client
                certificate. Defaults to ``None``.
            tls_client_key (StrOrBytesPath | None, optional): Path to a file containing the client
                private key. Defaults to ``None``.
            tls_key_password (str | None, optional): Optionally the password for decrypting the
                specified private key. Defaults to ``None``.
            stream (StreamType | None, optional): Optionally a stream object to send the
                message to. See ``https://docs.python.org/3/library/io.html`` for details.
                Defaults to ``None``.

        Raises:
            ValueError: If the facility is not valid.
        """
        super().__init__()

        if not (LOG_KERN <= facility <= LOG_LOCAL7):
            msg = 'Facility is not valid'
            raise ValueError(msg)

        self.address = address
        self.facility = facility
        self.socket_type = socket_type
        self.hostname = hostname or socket.gethostname()
        self.app_name = app_name
        self.procid = procid
        self.structured_data = structured_data or {}
        self.enterprise_id = enterprise_id
        self.framing = framing
        self.msg_as_utf8 = msg_as_utf8
        self.utc_timestamp = utc_timestamp
        self.timeout = timeout
        self.tls_enable = tls_enable
        self.tls_ca_bundle = tls_ca_bundle
        self.tls_verify = tls_verify
        self.tls_client_cert = tls_client_cert
        self.tls_client_key = tls_client_key
        self.tls_key_password = tls_key_password
        self.stream = stream
        self._transport: transport.TransportProtocol | None = None

        self._formatter = Rfc5424Formatter(
            facility=facility,
            hostname=self.hostname,
            app_name=app_name,
            procid=procid,
            structured_data=self.structured_data,
            enterprise_id=enterprise_id,
            msg_as_utf8=msg_as_utf8,
            utc_timestamp=utc_timestamp,
        )

        self._setup_transport()

    @property
    def transport(self) -> transport.TransportProtocol:
        """Get the transport. Raise ValueError if the transport is not set."""
        if self._transport is None:
            msg = 'Transport is not set'
            raise ValueError(msg)
        return self._transport

    def _setup_transport(self) -> None:
        if self.stream is not None:
            self._transport = transport.StreamTransport(self.stream)
        elif isinstance(self.address, str):
            self._transport = transport.UnixSocketTransport(self.address, self.socket_type)
        elif isinstance(self.address, (tuple, list)):
            if self.socket_type == socket.SOCK_STREAM:
                if self.tls_enable:
                    if self.tls_client_cert is None:
                        msg = 'TLS client certificate is not set'
                        raise ValueError(msg)
                    self._transport = transport.TLSSocketTransport(
                        address=self.address,
                        timeout=self.timeout,
                        framing=self.framing,
                        tls_ca_bundle=self.tls_ca_bundle,
                        tls_verify=self.tls_verify,
                        tls_client_cert=self.tls_client_cert,
                        tls_client_key=self.tls_client_key,
                        tls_key_password=self.tls_key_password,
                    )
                else:
                    self._transport = transport.TCPSocketTransport(
                        self.address,
                        self.timeout,
                        self.framing,
                    )
            else:
                self._transport = transport.UDPSocketTransport(self.address, self.timeout)

    def build_msg(self, record: LogRecord) -> bytes:
        """Build the RFC 5424 syslog payload for *record*."""
        return self._formatter.build_msg(record, self.format)

    def emit(self, record: LogRecord) -> None:
        """Emit a record.

        The record is formatted, and then sent to the syslog server. If
        exception information is present, it is NOT sent to the server.
        """
        try:
            syslog_msg = self.build_msg(record)
            self.transport.transmit(syslog_msg)
        except Exception:  # noqa: BLE001
            self.handleError(record)

    def close(self) -> None:
        """Closes the socket."""
        self.acquire()
        try:
            if self._transport is not None:
                self._transport.close()
            super().close()
        finally:
            self.release()

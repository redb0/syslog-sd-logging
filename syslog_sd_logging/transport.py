"""Transport classes."""

import io
import socket as socket_module
import ssl
from typing import TYPE_CHECKING, Final, Protocol

from syslog_sd_logging._types import AddressType, FramingType, SocketAddressType, StreamType

if TYPE_CHECKING:
    from _typeshed import StrOrBytesPath

SYSLOG_PORT = 514

# RFC6587 framing
FRAMING_OCTET_COUNTING: Final[str] = 'octet_counting'
FRAMING_NON_TRANSPARENT: Final[str] = 'non_transparent'


class TransportProtocol(Protocol):
    """Transport protocol."""

    def transmit(self, syslog_msg: bytes) -> None:
        """Transmit the syslog message."""

    def close(self) -> None:
        """Close the transport."""


class TCPSocketTransport:
    """TCP socket transport."""

    def __init__(
        self,
        address: AddressType,
        timeout: float | None,
        framing: FramingType,
    ) -> None:
        self._socket: socket_module.socket | None = None
        self.address = address
        self.timeout = timeout
        self.framing = framing
        self.open()

    @property
    def socket(self) -> socket_module.socket:
        """Get the socket. Raise OSError if the socket is not open."""
        if self._socket is None:
            msg = 'Socket is not open'
            raise OSError(msg)
        return self._socket

    def open(self) -> None:
        """Open the socket."""
        error = None
        host, port = self.address
        addr_info = socket_module.getaddrinfo(host, port, 0, socket_module.SOCK_STREAM)
        if not addr_info:
            msg = 'getaddrinfo returns an empty list'
            raise OSError(msg)
        for entry in addr_info:
            family, socket_type, _, _, socket_address = entry
            try:
                self._socket = socket_module.socket(family, socket_type)
                self._socket.settimeout(self.timeout)
                self._socket.connect(socket_address)
                # Connected successfully. Erase any previous errors.
                error = None
                break
            except OSError as e:
                error = e
                sock = self._socket
                if sock is not None:
                    sock.close()
                    self._socket = None
        if error is not None:
            raise error

    def transmit(self, syslog_msg: bytes) -> None:
        """Transmit the syslog message."""
        # RFC6587 framing
        if self.framing == 'non_transparent':
            syslog_msg = syslog_msg.replace(b'\n', b'\\n')
            syslog_msg = b''.join((syslog_msg, b'\n'))
        else:
            syslog_msg = b' '.join((str(len(syslog_msg)).encode('ascii'), syslog_msg))

        try:
            self.socket.sendall(syslog_msg)
        except OSError:
            self.close()
            self.open()
            self.socket.sendall(syslog_msg)

    def close(self) -> None:
        """Close the socket."""
        sock = self._socket
        self._socket = None
        if sock is not None:
            sock.close()


class TLSSocketTransport(TCPSocketTransport):
    """TLS socket transport."""

    def __init__(  # noqa: PLR0913
        self,
        address: AddressType,
        timeout: float | None,
        framing: FramingType,
        *,
        tls_ca_bundle: 'StrOrBytesPath | None' = None,
        tls_verify: bool = False,
        tls_client_cert: 'StrOrBytesPath',
        tls_client_key: 'StrOrBytesPath | None' = None,
        tls_key_password: str | None = None,
    ) -> None:
        self.tls_ca_bundle = tls_ca_bundle
        self.tls_verify = tls_verify
        self.tls_client_cert = tls_client_cert
        self.tls_client_key = tls_client_key
        self.tls_key_password = tls_key_password
        super().__init__(address, timeout, framing=framing)

    def open(self) -> None:
        """Open the TLS socket.

        On failure loading certificates or during ``wrap_socket``, the plain TCP socket
        from ``super().open()`` is closed.
        """
        super().open()
        try:
            context = ssl.create_default_context(
                purpose=ssl.Purpose.SERVER_AUTH,
                cafile=self.tls_ca_bundle,
            )
            context.verify_mode = ssl.CERT_REQUIRED if self.tls_verify else ssl.CERT_NONE
            server_hostname, _ = self.address
            if self.tls_client_cert:
                context.load_cert_chain(
                    self.tls_client_cert,
                    self.tls_client_key,
                    self.tls_key_password,
                )
            self._socket = context.wrap_socket(self.socket, server_hostname=server_hostname)
        except (OSError, ValueError):
            self.close()
            raise


class UDPSocketTransport:
    """UDP socket transport."""

    def __init__(
        self,
        address: AddressType,
        timeout: float | None,
    ) -> None:
        self._socket: socket_module.socket | None = None
        self.address = address
        self.timeout = timeout
        self._resolved_address: SocketAddressType | None = None
        self.open()

    @property
    def socket(self) -> socket_module.socket:
        """Get the socket. Raise OSError if the socket is not open."""
        if self._socket is None:
            msg = 'Socket is not open'
            raise OSError(msg)
        return self._socket

    @property
    def resolved_address(self) -> SocketAddressType:
        """Get the socket address. Raise OSError if the socket is not open."""
        if self._resolved_address is None:
            msg = 'Socket address is not set'
            raise OSError(msg)
        return self._resolved_address

    def open(self) -> None:
        """Open the socket."""
        error = None
        host, port = self.address
        addr_info = socket_module.getaddrinfo(host, port, 0, socket_module.SOCK_DGRAM)
        if not addr_info:
            msg = 'getaddrinfo returns an empty list'
            raise OSError(msg)
        for entry in addr_info:
            family, socket_type, _, _, socket_address = entry
            try:
                self._socket = socket_module.socket(family, socket_type)
                self._socket.settimeout(self.timeout)
                self._resolved_address = socket_address
                break
            except OSError as e:
                error = e
                sock = self._socket
                if sock is not None:
                    sock.close()
                    self._socket = None
                    self._resolved_address = None
        if error is not None:
            raise error

    def transmit(self, syslog_msg: bytes) -> None:
        """Transmit the syslog message."""
        try:
            self.socket.sendto(syslog_msg, self.resolved_address)
        except OSError:
            self.close()
            self.open()
            self.socket.sendto(syslog_msg, self.resolved_address)

    def close(self) -> None:
        """Close the socket."""
        sock = self._socket
        self._socket = None
        self._resolved_address = None
        if sock is not None:
            sock.close()


class UnixSocketTransport:
    """Unix socket transport."""

    def __init__(
        self,
        address: str,
        socket_type: socket_module.SocketKind | int | None,
    ) -> None:
        self._socket: socket_module.socket | None = None
        self.address = address
        self.socket_type = socket_type
        self.open()

    @property
    def socket(self) -> socket_module.socket:
        """Get the socket. Raise OSError if the socket is not open."""
        if self._socket is None:
            msg = 'Socket is not open'
            raise OSError(msg)
        return self._socket

    def open(self) -> None:
        """Open the socket."""
        if self.socket_type is None:
            socket_types: list[socket_module.SocketKind | int] = [
                socket_module.SOCK_DGRAM,
                socket_module.SOCK_STREAM,
            ]
        else:
            socket_types = [self.socket_type]

        for socket_type in socket_types:
            # Syslog server may be unavailable during handler initialization.
            # So we ignore connection errors
            try:
                self._socket = socket_module.socket(socket_module.AF_UNIX, socket_type)
                self._socket.connect(self.address)
                self.socket_type = socket_type
                break
            except OSError:
                sock = self._socket
                if sock is not None:
                    sock.close()
                    self._socket = None

        if self._socket is None:
            msg = 'Failed to connect to the socket'
            raise OSError(msg)

    def transmit(self, syslog_msg: bytes) -> None:
        """Transmit the syslog message."""
        try:
            self.socket.send(syslog_msg)
        except OSError:
            self.close()
            self.open()
            self.socket.send(syslog_msg)

    def close(self) -> None:
        """Close the socket."""
        sock = self._socket
        self._socket = None
        if sock is not None:
            sock.close()


class StreamTransport:
    """Stream transport."""

    def __init__(self, stream: StreamType) -> None:
        if not stream.writable():
            msg = 'Stream is not a writeable stream'
            raise ValueError(msg)

        self.stream = stream

    def transmit(self, syslog_msg: bytes) -> None:
        """Transmit the syslog message."""
        syslog_msg = syslog_msg + b'\n'
        if isinstance(self.stream, io.TextIOBase):
            self.stream.write(syslog_msg.decode(self.stream.encoding, 'replace'))
        else:
            self.stream.write(syslog_msg)

    def close(self) -> None:
        """Closing the stream is left up to the user."""

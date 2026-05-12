"""Adapter for RFC 5424 SysLog."""

import logging
from collections.abc import Mapping, MutableMapping
from logging import CRITICAL, DEBUG, ERROR, INFO, WARNING
from typing import TYPE_CHECKING, Any

from syslog_sd_logging.handler import ALERT, EMERGENCY, NOTICE

if TYPE_CHECKING:
    _LoggerAdapter = logging.LoggerAdapter[logging.Logger]
else:
    _LoggerAdapter = logging.LoggerAdapter


class Rfc5424SysLogAdapter(_LoggerAdapter):
    """Adapter for RFC 5424 SysLog."""

    _extra_levels_enabled = False

    def __init__(
        self,
        logger: logging.Logger,
        extra: Mapping[str, object] | None = None,
        *,
        enable_extra_levels: bool = False,
    ) -> None:
        """Initializing the adapter.

        Initialize the adapter with a logger and a dict-like object which
        provides contextual information. This constructor signature allows
        easy stacking of LoggerAdapters, if so desired.

        The dictionary passed as the ``extra`` argument will be included in every
        message sent via the adapter.

        Example:
            >>> adapter = Rfc5424SysLogAdapter(some_logger, extra={'p1': 'v1', 'p2': 'v2'})

        Args:
            logger (logging.Logger): A Logger class instance
            extra (Mapping[str, object] | None, optional): A Dictionary with extra
                contextual information, sent with every message. Defaults to ``None``.
            enable_extra_levels (bool, optional): Add custom log levels to the
                logging framework. Use with caution because it can conflict with
                other packages defining custom levels. Defaults to ``False``.
        """
        if enable_extra_levels and not Rfc5424SysLogAdapter._extra_levels_enabled:
            logging.addLevelName(EMERGENCY, 'EMERGENCY')
            logging.addLevelName(ALERT, 'ALERT')
            logging.addLevelName(NOTICE, 'NOTICE')
            Rfc5424SysLogAdapter._extra_levels_enabled = True

        super().__init__(logger, extra or {})

    def process(
        self,
        msg: Any,  # noqa: ANN401
        kwargs: MutableMapping[str, Any],
    ) -> tuple[Any, MutableMapping[str, Any]]:
        """Process the logging message and keyword arguments to insert contextual information.

        Searches for ``msgid`` and ``sd`` or ``structured_data`` in the keyword arguments
        and puts them in the ``extra`` keyword argument

        We don't touch other keyword arguments so we don't interfere with possible
        other logger adapters
        """
        hostname = kwargs.pop('hostname', None)
        app_name = kwargs.pop('appname', None)
        procid = kwargs.pop('procid', None)
        msgid = kwargs.pop('msgid', None)
        structured_data = kwargs.pop('sd', None)

        if structured_data is None:
            structured_data = kwargs.pop('structured_data', None)

        extra = self.extra.copy() if isinstance(self.extra, dict) else {}
        extra.update(kwargs.get('extra', {}) or {})
        kwargs['extra'] = extra

        if hostname:
            kwargs['extra']['hostname'] = hostname
        if app_name:
            kwargs['extra']['appname'] = app_name
        if procid:
            kwargs['extra']['procid'] = procid
        if msgid:
            kwargs['extra']['msgid'] = msgid
        if structured_data:
            kwargs['extra']['structured_data'] = structured_data

        return msg, kwargs

    def log(  # noqa: PLR0913
        self,
        level: int,
        msg: object,
        *args: object,
        exc_info: 'logging._ExcInfoType | None' = None,
        stack_info: bool = False,
        stacklevel: int = 1,
        extra: Mapping[str, object] | None = None,
        **kwargs: object,
    ) -> None:
        """Log a message with the specified level."""
        # If custom levels are not enabled, we convert
        # the level to a standard one
        if not Rfc5424SysLogAdapter._extra_levels_enabled:
            if level in (EMERGENCY, ALERT):
                level = logging.CRITICAL
            elif level == NOTICE:
                level = logging.WARNING
        super().log(
            level,
            msg,
            *args,
            exc_info=exc_info,
            stack_info=stack_info,
            stacklevel=stacklevel,
            extra=extra,
            **kwargs,
        )

    def emergency(
        self,
        msg: object,
        *args: object,
        exc_info: 'logging._ExcInfoType | None' = None,
        stack_info: bool = False,
        stacklevel: int = 1,
        extra: Mapping[str, object] | None = None,
        **kwargs: object,
    ) -> None:
        """Log a message with the EMERGENCY level."""
        self.log(
            EMERGENCY,
            msg,
            *args,
            exc_info=exc_info,
            stack_info=stack_info,
            stacklevel=stacklevel,
            extra=extra,
            **kwargs,
        )

    emerg = emergency

    def alert(
        self,
        msg: object,
        *args: object,
        exc_info: 'logging._ExcInfoType | None' = None,
        stack_info: bool = False,
        stacklevel: int = 1,
        extra: Mapping[str, object] | None = None,
        **kwargs: object,
    ) -> None:
        """Log a message with the ALERT level."""
        self.log(
            ALERT,
            msg,
            *args,
            exc_info=exc_info,
            stack_info=stack_info,
            stacklevel=stacklevel,
            extra=extra,
            **kwargs,
        )

    def critical(
        self,
        msg: object,
        *args: object,
        exc_info: 'logging._ExcInfoType | None' = None,
        stack_info: bool = False,
        stacklevel: int = 1,
        extra: Mapping[str, object] | None = None,
        **kwargs: object,
    ) -> None:
        """Log a message with the CRITICAL level."""
        self.log(
            CRITICAL,
            msg,
            *args,
            exc_info=exc_info,
            stack_info=stack_info,
            stacklevel=stacklevel,
            extra=extra,
            **kwargs,
        )

    def error(
        self,
        msg: object,
        *args: object,
        exc_info: 'logging._ExcInfoType | None' = None,
        stack_info: bool = False,
        stacklevel: int = 1,
        extra: Mapping[str, object] | None = None,
        **kwargs: object,
    ) -> None:
        """Log a message with the ERROR level."""
        self.log(
            ERROR,
            msg,
            *args,
            exc_info=exc_info,
            stack_info=stack_info,
            stacklevel=stacklevel,
            extra=extra,
            **kwargs,
        )

    def warning(
        self,
        msg: object,
        *args: object,
        exc_info: 'logging._ExcInfoType | None' = None,
        stack_info: bool = False,
        stacklevel: int = 1,
        extra: Mapping[str, object] | None = None,
        **kwargs: object,
    ) -> None:
        """Log a message with the WARNING level."""
        self.log(
            WARNING,
            msg,
            *args,
            exc_info=exc_info,
            stack_info=stack_info,
            stacklevel=stacklevel,
            extra=extra,
            **kwargs,
        )

    warn = warning

    def notice(
        self,
        msg: object,
        *args: object,
        exc_info: 'logging._ExcInfoType | None' = None,
        stack_info: bool = False,
        stacklevel: int = 1,
        extra: Mapping[str, object] | None = None,
        **kwargs: object,
    ) -> None:
        """Log a message with the NOTICE level."""
        self.log(
            NOTICE,
            msg,
            *args,
            exc_info=exc_info,
            stack_info=stack_info,
            stacklevel=stacklevel,
            extra=extra,
            **kwargs,
        )

    def info(
        self,
        msg: object,
        *args: object,
        exc_info: 'logging._ExcInfoType | None' = None,
        stack_info: bool = False,
        stacklevel: int = 1,
        extra: Mapping[str, object] | None = None,
        **kwargs: object,
    ) -> None:
        """Log a message with the INFO level."""
        self.log(
            INFO,
            msg,
            *args,
            exc_info=exc_info,
            stack_info=stack_info,
            stacklevel=stacklevel,
            extra=extra,
            **kwargs,
        )

    def debug(
        self,
        msg: object,
        *args: object,
        exc_info: 'logging._ExcInfoType | None' = None,
        stack_info: bool = False,
        stacklevel: int = 1,
        extra: Mapping[str, object] | None = None,
        **kwargs: object,
    ) -> None:
        """Log a message with the DEBUG level."""
        self.log(
            DEBUG,
            msg,
            *args,
            exc_info=exc_info,
            stack_info=stack_info,
            stacklevel=stacklevel,
            extra=extra,
            **kwargs,
        )

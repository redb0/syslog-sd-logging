# Python rfc5424 syslog logging handler

[![codecov](https://codecov.io/gh/redb0/syslog-sd-logging/graph/badge.svg?token=19FZSE1P0A)](https://codecov.io/gh/redb0/syslog-sd-logging)

**This is a fork of a [package](https://github.com/jobec/rfc5424-logging-handler) with a logging handler with support for the RFC 5424 standard.**

[RFC 5424](https://tools.ietf.org/html/rfc5424) (syslog structured data) compliant syslog handler for the Python logging framework.

* Free software: BSD License
* [Homepage](https://github.com/redb0/syslog-sd-logging)
* [Original documentation](http://rfc5424-logging-handler.readthedocs.org/)

## Installation

```bash
pip install syslog-sd-logging
```

## Usage

After installing you can use this package like this:

```python
import logging
from syslog_sd_logging import Rfc5424SysLogHandler

logger = logging.getLogger('syslogtest')
logger.setLevel(logging.INFO)

sh = Rfc5424SysLogHandler(address=('10.0.0.1', 514))
logger.addHandler(sh)

logger.info('This is an interesting message', extra={'msgid': 'some_unique_msgid'})
```

This will send the following message to the syslog server::

```text
<14>1 2020-01-01T05:10:20.841485+01:00 myserver syslogtest 5252 some_unique_msgid - \xef\xbb\xbfThis is an interesting message
```

Note the UTF8 Byte order mark (BOM) preceding the message. While required by
[RFC 5424 section 6.4](https://tools.ietf.org/html/rfc5424#section-6.4) if the message is known to be UTF-8 encoded,
there are still syslog receivers that cannot handle it. To bypass this limitation, when initializing the handler Class,
set the `msg_as_utf8` parameter to `False` like this:

```python
sh = Rfc5424SysLogHandler(address=('10.0.0.1', 514), msg_as_utf8=False)
```

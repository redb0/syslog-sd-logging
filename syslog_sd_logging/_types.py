import io
from typing import Literal, TypeAlias

StreamType: TypeAlias = io.BufferedIOBase | io.TextIOBase
FramingType: TypeAlias = Literal['octet_counting', 'non_transparent']
AddressType: TypeAlias = tuple[str, int]

SocketAddressType: TypeAlias = tuple[str, int] | tuple[str, int, int, int] | tuple[int, bytes]

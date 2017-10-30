from random import choice
from string import printable
from ..agent.util import encode, decode

import pytest


#noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_codec():
    for plen in range(1, 1025):
        plain = ''.join(choice(printable) for _ in range(plen))
        enc = encode(plain)
        dec = decode(enc)
        assert plain == dec

    for plain in (None, -5, 0, 1024, 2**32 - 1, 2**32, 2**32 + 1):
        enc = encode(plain)
        dec = decode(enc)
        assert str(plain) == dec

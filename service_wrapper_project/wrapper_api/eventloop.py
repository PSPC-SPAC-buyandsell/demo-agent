import asyncio

_loop = None

def get_loop():
    global _loop
    if not _loop:
        _loop = asyncio.new_event_loop()
        asyncio.set_event_loop(_loop)
    return _loop


from ..agent.nodepool import NodePool

import pytest
import json


#noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_pool_open(
    pool_name,
    pool_genesis_txn_path,
    pool_genesis_txn_file):

    p = NodePool(pool_name, pool_genesis_txn_path)
    await p.open()
    assert p.handle is not None

    await p.close()


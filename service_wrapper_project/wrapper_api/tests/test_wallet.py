from ..agent.nodepool import NodePool
from ..agent.wallet import Wallet

import pytest


#noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_wallet(
    pool_name,
    pool_genesis_txn_path,
    pool_genesis_txn_file):

    p = NodePool(pool_name, pool_genesis_txn_path)
    await p.open()
    assert p.handle is not None

    seed = '00000000000000000000000000000000'
    base_name = 'my-wallet'
    w = Wallet(p.name, seed, base_name, 0)
    await w.open()

    num = w.num

    assert num != None
    assert w.did
    assert w.verkey
    assert w.pubkey

    (did, verkey, pubkey) = (w.did, w.verkey, w.pubkey)
    await w.close()

    num += 1
    x = Wallet(p.name, seed, base_name, num)
    await x.open()
    assert did == x.did
    assert verkey == x.verkey
    assert pubkey == x.pubkey

    await x.close()
    await p.close()

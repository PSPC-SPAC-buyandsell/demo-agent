from indy import agent, anoncreds, ledger, signus, pool, wallet, IndyError
from indy.error import ErrorCode
from wrapper_api.agent.nodepool import NewPool, LivePool
from wrapper_api.agent.demo_agents import TrustAnchorAgent, SRIAgent, OrgBookAgent, BCRegistrarAgent
from wrapper_api.agent.util import claim_value_pair, ppjson, plain_claims_for, prune_claims_json

import pytest
import json


#noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_pool_open(
        pool_name,
        pool_genesis_txn_path,
        pool_genesis_txn_file):

    p = NewPool(pool_name, pool_genesis_txn_path)
    await p.open()
    assert p.handle is not None

    q = LivePool(p.name, p.handle)
    await q.open()
    await q.close()
    await p.close()

from django.apps.config import AppConfig
from wrapper_api.config import get_config
from wrapper_api.agent.nodepool import NodePool
from wrapper_api.agent.demo_agents import TrustAnchorAgent, SRIAgent, BCRegistrarAgent, OrgBookAgent
from wrapper_api.eventloop import get_loop

import asyncio


class WrapperApiConfig(AppConfig):
    name = 'wrapper_api'

    def ready(self):
        loop = get_loop()
        cfg = get_config()

        pool = NodePool(cfg['Pool']['name'], cfg['Pool']['genesis.txn.path'])
        print('>>> POOL {}, {}, {}'.format(pool.name, pool.handle, pool.genesis_txn_path))
        loop.run_until_complete(pool.open())  # TODO: put this into eventloop, accept params
        print('>>> POOL HANDLE {}'.format(pool.handle))

        role = cfg['Agent']['role'] or ''
        if role.tolower().contains('bc'):
            pass
        elif role.tolower().contains('sri'):
            pass
        elif role.tolower().contains('trust'):
            pass
        elif role.tolower().contains('org'):
            pass
        else:
            loop.run_until_complete(asyncio.gather(pool.close()))
            raise ValueError('Unsupported agent role [{}]'.format(role))

        loop.run_until_complete(asyncio.gather(pool.close()))

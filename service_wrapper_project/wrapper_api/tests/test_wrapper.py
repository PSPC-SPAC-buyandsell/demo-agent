from configparser import ConfigParser
from indy import agent, anoncreds, ledger, signus, pool, wallet, IndyError
from indy.error import ErrorCode
from os.path import abspath, dirname, isfile, join as pjoin

import json
import pytest
import requests


#noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_wrapper(
        pool_name,
        pool_genesis_txn_path,
        seed_trustee1,
        pool_genesis_txn_file,
        path_home):
    """LD_LIBRARY_PATH=/home/sklump/indy/indy-sdk/libindy/target/debug TEST_POOL_IP=10.0.0.2 AGENT_PROFILE=the-org-book python manage.py runserver --settings=config.settings.local 0.0.0.0:9702 --noreload
    """

    # 1. check that all nodes are started
    agent_roles = ['bc-registrar',  'sri', 'the-org-book', 'trust-anchor']
    for agent_role in agent_roles:
        inis = [
            pjoin(dirname(dirname(abspath(__file__))), 'config', 'config.ini'),
            pjoin(
                dirname(dirname(abspath(__file__))),
                'config',
                'agent-profile',
                '{}.ini'.format(agent_role))
        ]

        parser = ConfigParser()
        for ini in inis:
            assert isfile(ini)
            parser.read(ini)
            # print('\n\n=== done file {}: {}'.format(ini, parser.sections()))

        cfg = {s: dict(parser[s].items()) for s in parser.sections()}
        assert 'Agent' in cfg

        url = 'http://{}:{}/{}/did'.format(
            cfg['Agent']['host'],
            cfg['Agent']['port'],
            cfg['Common']['base.api.url.path'])
        r = requests.get(url)
        assert r.status_code == 200

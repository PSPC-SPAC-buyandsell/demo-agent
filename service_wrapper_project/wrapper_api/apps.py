from django.apps.config import AppConfig
from os.path import abspath, dirname, join as pjoin
from wrapper_api.config import get_config
from wrapper_api.agent.nodepool import NodePool
from wrapper_api.agent.demo_agents import TrustAnchorAgent, SRIAgent, BCRegistrarAgent, OrgBookAgent
from wrapper_api.eventloop import get_loop

import asyncio
import json
import logging
import requests

logging.basicConfig(level=logging.DEBUG)

class WrapperApiConfig(AppConfig):
    name = 'wrapper_api'

    def ready(self):
        logger = logging.getLogger(__name__)
        loop = get_loop()
        cfg = get_config()

        logging.debug("\n== check 0")

        role = (cfg['Agent']['role'] or '').lower().replace(' ', '')  # as a pool name, will be a dir: spaces are evil
        p = None  # the node pool
        p = NodePool('pool.{}'.format(role), cfg['Pool']['genesis.txn.path'])
        loop.run_until_complete(p.open())  # TODO: put this into eventloop, accept params
        assert p

        ag = None
        if role == 'trust-anchor':
            logging.debug("\n== check tag 1")
            bootstrap_json = cfg['Agent']
            ag = TrustAnchorAgent(
                p,
                cfg['Agent']['seed'],
                'wallet-{}'.format(role),
                None,
                cfg['Agent']['host'],
                int(cfg['Agent']['port']),
                cfg['Common']['base.api.url.path'].strip('/'))
            loop.run_until_complete(ag.open())
            assert ag.did
            
            logging.debug("\n== check tag 2")
            # register trust anchor if need be
            if not json.loads(loop.run_until_complete(ag.get_nym(ag.did))):
                loop.run_until_complete(ag.send_nym(ag.did, ag.verkey))
            if not json.loads(loop.run_until_complete(ag.get_endpoint(ag.did))):
                loop.run_until_complete(ag.send_endpoint(ag.did))

            logging.debug("\n== check tag 3")
            # send schema if need be
            if not json.loads(loop.run_until_complete(ag.get_schema(
                    ag.did,
                    cfg['Schema']['name'],
                    cfg['Schema']['version']))):
                with open(pjoin(dirname(abspath(__file__)), 'protocol', 'schema-send.json'), 'r') as proto:
                    j = proto.read()
                schema = json.loads(loop.run_until_complete(ag.process_post(j % (
                    ag.did,
                    cfg['Schema']['name'],
                    cfg['Schema']['version']))))
                logging.debug("\n== check tag 4")
                assert schema

        elif role in ('sri', 'the-org-book', 'bc-registrar'):
            logging.debug("\n== check sag/obag/bcrag 1")
            # create agent via factory by role
            if role == 'sri':
                ag = SRIAgent(
                    p,
                    cfg['Agent']['seed'],
                    'wallet-{}'.format(role),
                    None,
                    cfg['Agent']['host'],
                    int(cfg['Agent']['port']),
                    cfg['Common']['base.api.url.path'].strip('/'))
            elif role == 'the-org-book':
                ag = OrgBookAgent(
                    p,
                    cfg['Agent']['seed'],
                    'wallet-{}'.format(role),
                    None,
                    cfg['Agent']['host'],
                    int(cfg['Agent']['port']),
                    cfg['Common']['base.api.url.path'].strip('/'))
            elif role == 'bc-registrar':
                ag = BCRegistrarAgent(
                    p,
                    cfg['Agent']['seed'],
                    'wallet-{}'.format(role),
                    None,
                    cfg['Agent']['host'],
                    int(cfg['Agent']['port']),
                    cfg['Common']['base.api.url.path'].strip('/'))

            loop.run_until_complete(ag.open())
            logging.debug("\n== check sag/obag/bcrag 3: ag class {}".format(ag.__class__.__name__))

            trust_anchor_host = cfg['Trust Anchor']['host']
            trust_anchor_port = cfg['Trust Anchor']['port']
            base_api_url_path = cfg['Common']['base.api.url.path']

            # trust anchor DID is necessary
            logging.debug("\n== check sag/obag/bcrag 4")
            r = requests.get('http://{}:{}/{}/did'.format(trust_anchor_host, trust_anchor_port, base_api_url_path))
            try:
                r.raise_for_status()
            except:
                loop.run_until_complete(ag.close())
                raise
            tag_did = r.json()

            logging.debug("\n== check sag/obag/bcrag 5")
            # get nym: if not registered; get trust-anchor host & port, post an agent-nym-send form
            if not json.loads(loop.run_until_complete(ag.get_nym(ag.did))):
                with open(pjoin(dirname(abspath(__file__)), 'protocol', 'agent-nym-send.json'), 'r') as proto:
                    j = proto.read()
                r = requests.post(
                    'http://{}:{}/{}'.format(trust_anchor_host, trust_anchor_port, base_api_url_path),
                    json=json.loads(j % (ag.did, ag.verkey)))
                try:
                    r.raise_for_status()
                except:
                    loop.run_until_complete(ag.close())
                    raise

            logging.debug("\n== check sag/obag/bcrag 6")
            # get endpoint: if not present, send it
            if not json.loads(loop.run_until_complete(ag.get_endpoint(ag.did))):
                loop.run_until_complete(ag.send_endpoint(ag.did))

            logging.debug("\n== check sag/obag/bcrag 7")
            # lookup schema
            with open(pjoin(dirname(abspath(__file__)), 'protocol', 'schema-lookup.json'), 'r') as proto:
                j = proto.read()
            schema_json = loop.run_until_complete(ag.get_schema(
                tag_did,
                cfg['Schema']['name'],
                cfg['Schema']['version']))
            schema = json.dumps(schema)
            assert schema

            logging.debug("\n== check sag/obag/bcrag 8")
            if role == 'the-org-book':
                # set master secret
                loop.run_until_complete(ag.create_master_secret(cfg['Agent']['master.secret']))
                logging.debug("\n== check sag/obag/bcrag 9")

            elif role in ('bc-registrar', 'sri'):
                # issuer send claim def
                loop.run_until_complete(ag.send_claim_def(schema_json))
                logging.debug("\n== check sag/obag/bcrag 10")
            logging.debug("\n== check sag/obag/bcrag 11")

        else:
            loop.run_until_complete(p.close())
            raise ValueError('Unsupported agent role [{}]'.format(role))

        loop.run_until_complete(p.close())

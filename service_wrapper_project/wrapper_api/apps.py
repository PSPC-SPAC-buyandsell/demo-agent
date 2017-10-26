from django.apps.config import AppConfig
from django.core.cache import cache
from os.path import abspath, dirname, join as pjoin
from wrapper_api.config import init_config
from wrapper_api.agent.nodepool import NodePool
from wrapper_api.agent.demo_agents import TrustAnchorAgent, SRIAgent, BCRegistrarAgent, OrgBookAgent
from wrapper_api.eventloop import do

import asyncio
import atexit
import json
import logging
import requests

logging.basicConfig(
    level=logging.DEBUG,
    format='%(levelname)-8s %(name)-12s %(message)s')


def _cleanup():
    ag = cache.get('agent')
    if ag is not None:
        do(ag.close())
    p = cache.get('pool')
    if p is not None:
        do(p.close())


class WrapperApiConfig(AppConfig):
    name = 'wrapper_api'

    def ready(self):
        logger = logging.getLogger(__name__)

        cfg = init_config()

        role = (cfg['Agent']['role'] or '').lower().replace(' ', '')  # as a pool name, will be a dir: spaces are evil
        p = None  # the node pool
        p = NodePool('pool.{}'.format(role), cfg['Pool']['genesis.txn.path'])
        do(p.open())
        assert p.handle
        cache.set('pool', p)

        ag = None
        if role == 'trust-anchor':
            bootstrap_json = cfg['Agent']
            ag = TrustAnchorAgent(
                p,
                cfg['Agent']['seed'],
                'wallet-{}'.format(role),
                None,
                cfg['Agent']['host'],
                int(cfg['Agent']['port']),
                cfg['Common']['base.api.url.path'].strip('/'))
            do(ag.open())
            assert ag.did
            
            # register trust anchor if need be
            if not json.loads(do(ag.get_nym(ag.did))):
                do(ag.send_nym(ag.did, ag.verkey))
            if not json.loads(do(ag.get_endpoint(ag.did))):
                do(ag.send_endpoint())

            # send schema if need be
            if not json.loads(do(ag.get_schema(
                    ag.did,
                    cfg['Schema']['name'],
                    cfg['Schema']['version']))):
                with open(pjoin(dirname(abspath(__file__)), 'protocol', 'schema-send.json'), 'r') as proto:
                    j = proto.read()
                schema = do(ag.process_post(json.loads(j % (
                    ag.did,
                    cfg['Schema']['name'],
                    cfg['Schema']['version']))))
                assert schema

        elif role in ('sri', 'the-org-book', 'bc-registrar'):
            logging.debug("check {} 1".format(role))
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

            do(ag.open())
            logging.debug("check {} 2: ag class {}".format(role, ag.__class__.__name__))

            trust_anchor_host = cfg['Trust Anchor']['host']
            trust_anchor_port = cfg['Trust Anchor']['port']
            base_api_url_path = cfg['Common']['base.api.url.path']

            # trust anchor DID is necessary
            logging.debug("check {} 3".format(role))
            r = requests.get('http://{}:{}/{}/did'.format(trust_anchor_host, trust_anchor_port, base_api_url_path))
            r.raise_for_status()
            tag_did = r.json()

            logging.debug("== check {} 4, tag_did {}".format(role, tag_did))
            # get nym: if not registered; get trust-anchor host & port, post an agent-nym-send form
            if not json.loads(do(ag.get_nym(ag.did))):
                with open(pjoin(dirname(abspath(__file__)), 'protocol', 'agent-nym-send.json'), 'r') as proto:
                    j = proto.read()
                logging.debug("== check {} 4.0 sending {}".format(role, j % (ag.did, ag.verkey)))
                r = requests.post(
                    'http://{}:{}/{}/agent-nym-send'.format(trust_anchor_host, trust_anchor_port, base_api_url_path),
                    json=json.loads(j % (ag.did, ag.verkey)))
                r.raise_for_status()

            logging.debug("\n== check {} 5".format(role))
            # get endpoint: if not present, send it
            if not json.loads(do(ag.get_endpoint(ag.did))):
                do(ag.send_endpoint())

            # lookup schema
            with open(pjoin(dirname(abspath(__file__)), 'protocol', 'schema-lookup.json'), 'r') as proto:
                j = proto.read()
            schema_json = do(ag.get_schema(
                tag_did,
                cfg['Schema']['name'],
                cfg['Schema']['version']))
            assert json.dumps(schema_json)

            logging.debug("\n== check {} 6".format(role))
            if role == 'the-org-book':
                # set master secret
                do(ag.create_master_secret(cfg['Agent']['master.secret']))
                logging.debug("\n== check {} 7".format(role))

            elif role in ('bc-registrar', 'sri'):
                # issuer send claim def
                do(ag.send_claim_def(schema_json))
                logging.debug("\n== check {} 8".format(role))
            logging.debug("\n== check {} 9".format(role))

        else:
            raise ValueError('Unsupported agent role [{}]'.format(role))

        assert ag is not None
        cache.set('agent', ag)
        atexit.register(_cleanup)

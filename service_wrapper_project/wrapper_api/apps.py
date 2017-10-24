from django.apps.config import AppConfig
from os.path import abspath, dirname, join as pjoin
from wrapper_api.config import get_config
from wrapper_api.agent.nodepool import NewPool, LivePool
from wrapper_api.agent.demo_agents import TrustAnchorAgent, SRIAgent, BCRegistrarAgent, OrgBookAgent
from wrapper_api.eventloop import get_loop

import asyncio
import json
import requests


class WrapperApiConfig(AppConfig):
    name = 'wrapper_api'

    def ready(self):
        loop = get_loop()
        cfg = get_config()

        p = None  # the node pool
        if int(cfg['Agent']['pool.new']):
            p = NewPool(cfg['Pool']['name'], cfg['Pool']['genesis.txn.path'])
            loop.run_until_complete(p.open())  # TODO: put this into eventloop, accept params

        ag = None
        role = (cfg['Agent']['role'] or '').lower()
        if role == 'trust-anchor':
            assert int(cfg['Agent']['pool.new'])
            bootstrap_json = cfg['Agent']
            ag = TrustAnchorAgent(
                p,
                cfg['Agent']['seed'],
                cfg['Agent']['wallet'],
                None,
                cfg['Agent']['host'],
                int(cfg['Agent']['port']),
                cfg['Common']['base.api.url.path'].strip('/'))
            
            # register trust anchor if need be
            if not json.loads(loop.run_until_complete(ag.get_nym(ag.did))):
                loop.run_until_complete(ag.send_nym(ag.did, ag.verkey))
            if not json.loads(loop.run_until_complete(ag.get_endpoint(ag.did))):
                loop.run_until_complete(ag.send_endpoint(ag.did))

            # send schema if need be
            if not json.loads(loop.run_until_complete(ag.get_schema(
                    ag.did,
                    cfg['Schema']['name'],
                    cfg['Schema']['version']))):
                with open(pjoin(dirname(abspath(__file__), 'protocol', 'schema-send.json'), 'r') as proto:
                    j = proto.read()
                schema = json.loads(loop.run_until_complete(ag.process_post(j % (
                    ag.did,
                    cfg['Schema']['name'],
                    cfg['Schema']['version'])))

        elif role in ('sri', 'the-org-book', 'bc-registrar'):
            # pool info is necessary
            if not p:
                r = requests.get('http://{}:{}/{}/pool'.format(trust_anchor_host, trust_anchor_port, base_api_url_path))
                try:
                    r.raise_for_status()
                except:
                    loop.run_until_complete(ag.close())
                    raise
                pool_info = r.json()
                p = LivePool(pool_info['name'], pool_info['handle'])

            # create agent via factory by role
            if role == 'sri':
                ag = SRIAgent(
                    p,
                    cfg['Agent']['seed'],
                    cfg['Agent']['wallet'],
                    None,
                    cfg['Agent']['host'],
                    int(cfg['Agent']['port']),
                    cfg['Common']['base.api.url.path'].strip('/'))
            elif role == 'the-org-book':
                ag = OrgBookAgent(
                    p,
                    cfg['Agent']['seed'],
                    cfg['Agent']['wallet'],
                    None,
                    cfg['Agent']['host'],
                    int(cfg['Agent']['port']),
                    cfg['Common']['base.api.url.path'].strip('/'))
            elif role == 'bc-registrar':
                ag = BCRegistrarAgent(
                    p,
                    cfg['Agent']['seed'],
                    cfg['Agent']['wallet'],
                    None,
                    cfg['Agent']['host'],
                    int(cfg['Agent']['port']),
                    cfg['Common']['base.api.url.path'].strip('/'))

            loop.run_until_complete(ag.open())

            trust_anchor_host = cfg['Trust Anchor']['host']
            trust_anchor_port = cfg['Trust Anchor']['port']
            base_api_url_path = cfg['Common']['base.api.url.path']

            # trust anchor DID is necessary
            r = requests.get('http://{}:{}/{}/did'.format(trust_anchor_host, trust_anchor_port, base_api_url_path))
            try:
                r.raise_for_status()
            except:
                loop.run_until_complete(ag.close())
                raise
            tag_did = r.json()

            # get nym: if not registered; get trust-anchor host & port, post an agent-nym-send form
            if not json.loads(loop.run_until_complete(ag.get_nym(ag.did))):
                with open(pjoin(dirname(abspath(__file__), 'protocol', 'agent-nym-send.json'), 'r') as proto:
                    j = proto.read()
                r = requests.post(
                    'http://{}:{}/{}'.format(trust_anchor_host, trust_anchor_port, base_api_url_path),
                    json=json.loads(j % (ag.did, ag.verkey)))
                try:
                    r.raise_for_status()
                except:
                    loop.run_until_complete(ag.close())
                    raise

            # get endpoint: if not present, send it
            if not json.loads(loop.run_until_complete(ag.get_endpoint(ag.did))):
                loop.run_until_complete(ag.send_endpoint(ag.did))

            # lookup schema
            with open(pjoin(dirname(abspath(__file__), 'protocol', 'schema-lookup.json'), 'r') as proto:
                j = proto.read()
            schema_json = loop.run_until_complete(ag.get_schema(
                tag_did,
                cfg['Schema']['name'],
                cfg['Schema']['version']))
            schema = json.dumps(schema)
            assert schema

            if role == 'the-org-book':
                # set master secret
                loop.run_until_complete(ag.create_master_secret(cfg['Agent']['master.secret']))

            elif role in ('bc-registrar', 'sri'):
                # issuer send claim def
                loop.run_until_complete(ag.send_claim_def(schema_json))

        else:
            loop.run_until_complete(p.close())
            raise ValueError('Unsupported agent role [{}]'.format(role))

        loop.run_until_complete(p.close())

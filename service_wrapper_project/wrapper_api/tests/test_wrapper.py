"""
Copyright 2017 Government of Canada – Public Services and Procurement Canada – buyandsell.gc.ca

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from configparser import ConfigParser
from os.path import abspath, dirname, isfile, join as pjoin
from ..agent.util import ppjson, plain_claims_for, prune_claims_json

import json
import pytest
import requests


def form_json(msg_type, args, proxy_did=None):
    assert all(isinstance(x, str) for x in args)
    # print("... form_json interpolands {}".format([a for a in args]))
    with open(pjoin(dirname(dirname(abspath(__file__))), 'protocol', '{}.json'.format(msg_type)), 'r') as proto:
        raw_json = proto.read()
    msg_json = raw_json % args
    rv = msg_json
    if proxy_did:
        assert msg_type in (
            'agent-nym-send',
            'agent-endpoint-send',
            'claim-hello',
            'claim-store',
            'claim-request',
            'proof-request',
            'verification-request')
        # print("... form_json json-loading {}".format(msg_json))
        msg = json.loads(msg_json)
        msg['data']['proxy-did'] = proxy_did
        rv = json.dumps(msg, indent=4)
    print('... composed {} form: {}'.format(msg_type, ppjson(rv)))
    return rv


def url_for(cfg_section, suffix=''):
    rv = 'http://{}:{}/api/v0/{}'.format(cfg_section['host'], cfg_section['port'], suffix).strip('/')
    print('... interpolated URL: {}'.format(rv))
    return rv


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

    agent_roles = ['trust-anchor', 'sri', 'the-org-book', 'bc-registrar']

    # 0. configure
    cfg = {}
    parser = ConfigParser()
    ini = pjoin(dirname(dirname(abspath(__file__))), 'config', 'config.ini')
    assert isfile(ini)
    parser.read(ini)
    cfg = {s: dict(parser[s].items()) for s in parser.sections()}

    for agent_role in agent_roles:
        ini = pjoin(dirname(dirname(abspath(__file__))), 'config', 'agent-profile', '{}.ini'.format(agent_role))
        assert isfile(ini)
        agent_parser = ConfigParser()
        agent_parser.read(ini)

        cfg[agent_role] = {s: dict(agent_parser[s].items()) for s in agent_parser.sections()}

    print("\n\n=== Test config: {}".format(ppjson(cfg)))

    did = {}
    # 1. ensure all demo agents are up
    for agent_role in agent_roles:
        url = url_for(cfg[agent_role]['Agent'], 'did')
        r = requests.get(url)
        assert r.status_code == 200
        did[agent_role] = r.json()

    print("\n\n=== DIDs: {}".format(ppjson(did)))
    # 2. get schema
    schema_lookup_json = form_json(
        'schema-lookup',
        (
            did['trust-anchor'],
            cfg['Schema']['name'],
            cfg['Schema']['version']
        ))
    url = url_for(cfg['Trust Anchor'], 'schema-lookup')
    r = requests.post(url, json=json.loads(schema_lookup_json))
    assert r.status_code == 200
    schema = r.json()

    """
    # 3X. claim-hello no proxy
    claim_hello_json = form_json(
        'claim-hello',
        (did['bc-registrar'],))
    url = url_for(cfg['the-org-book']['Agent'], 'claim-hello')
    r = requests.post(url, json=json.loads(claim_hello_json))
    assert r.status_code == 200
    claim_req = r.json()
    assert claim_req
    print('\n\n=== X.0 === claim-req from bc-rag->obag hello: {}'.format(ppjson(claim_req)))
    """

    # 3. Prover responds to claims-reset directive, to restore state to base line
    claims_reset_json = form_json(
        'claims-reset',
        ())
    url = url_for(cfg['the-org-book']['Agent'], 'claims-reset')
    r = requests.post(url, json=json.loads(claims_reset_json))
    assert r.status_code == 200
    reset_resp = r.json()
    assert not reset_resp

    # 4. issuer claim-hello; then create, store each claim
    claim_hello_json = form_json(
        'claim-hello',
        (did['bc-registrar'],),
        did['the-org-book'])
    url = url_for(cfg['bc-registrar']['Agent'], 'claim-hello')
    r = requests.post(url, json=json.loads(claim_hello_json))
    assert r.status_code == 200
    claim_req = r.json()
    assert claim_req
    # print('\n\n=== XX === claim-req through proxy bc-rag->obag hello: {}'.format(ppjson(claim_req)))

    claims = [
        {
            'id': 1,
            'busId': 11121398,
            'orgTypeId': 2,
            'jurisdictionId': 1,
            'LegalName': 'The Original House of Pies',
            'effectiveDate': '2010-10-10',
            'endDate': None,
            'sriRegDate': None
        },
        {
            'id': 2,
            'busId': 11133333,
            'orgTypeId': 1,
            'jurisdictionId': 1,
            'LegalName': 'Planet Cake',
            'effectiveDate': '2011-10-01',
            'endDate': None,
            'sriRegDate': None
        },
        {
            'id': 3,
            'busId': 11144444,
            'orgTypeId': 2,
            'jurisdictionId': 1,
            'LegalName': 'Tart City',
            'effectiveDate': '2012-12-01',
            'endDate': None,
            'sriRegDate': None
        }
    ]
    for c in claims:
        claim_create_json = form_json(
            'claim-create',
            (json.dumps(claim_req), json.dumps(c)))
        url = url_for(cfg['bc-registrar']['Agent'], 'claim-create')
        r = requests.post(url, json=json.loads(claim_create_json))
        assert r.status_code == 200
        claim = r.json()
        assert claim

        print("\n\n== 0 == claim: {}".format(ppjson(claim)))
        claim_store_json = form_json(
            'claim-store',
            (json.dumps(claim),),
            did['the-org-book'])
        url = url_for(cfg['bc-registrar']['Agent'], 'claim-store')
        r = requests.post(url, json=json.loads(claim_store_json))
        assert r.status_code == 200
        # response is empty

    # 5. Prover finds claims
    claim_req_all_json = form_json(
        'claim-request',
        (json.dumps({}),),
        did['the-org-book'])
    url = url_for(cfg['sri']['Agent'], 'claim-request')
    r = requests.post(url, json=json.loads(claim_req_all_json))
    assert r.status_code == 200
    claims_all = r.json()
    assert claims_all
    print("\n\n== 1 == claims by attr, no filter, api-post {}".format(ppjson(claims_all)))

    display_pruned_postfilt = plain_claims_for(claims_all['claims'], {'LegalName': claims[2]['LegalName']})
    print("\n\n== 2 == display claims filtered post-hoc matching {}: {}".format(
        claims[2]['LegalName'],
        ppjson(display_pruned_postfilt)))  # LegalName appears plain: we specified it to plain_claims_for()
    display_pruned = prune_claims_json({k for k in display_pruned_postfilt}, claims_all['claims'])
    print("\n\n== 3 == stripped down {}".format(ppjson(display_pruned)))

    claim_req_prefilt_json = form_json(
        'claim-request',
        (json.dumps({k: claims[2][k] for k in claims[2] if k in ('sriRegDate', 'busId')}),),
        did['the-org-book'])
    url = url_for(cfg['sri']['Agent'], 'claim-request')
    r = requests.post(url, json=json.loads(claim_req_prefilt_json))
    assert r.status_code == 200
    claims_prefilt = r.json()
    assert claims_prefilt

    print("\n== 4 == claims by attr, with filter a priori {}".format(ppjson(claims_prefilt)))
    display_pruned_prefilt = plain_claims_for(claims_prefilt['claims'])
    print("\n== 5 == display claims filtered a priori matching {}: {}".format(
        claims[2]['LegalName'],
        ppjson(display_pruned_prefilt)))  # LegalName appears encoded: we didn't specify it to plain_claims_for()
    assert set([*display_pruned_postfilt]) == set([*display_pruned_prefilt])
    assert len(display_pruned_postfilt) == 1

    # 6. Prover responds to request for proof
    claim_uuid = set([*display_pruned_prefilt]).pop()  # TODO: allow claim-req/proof-req by claim_uuid handle
    proof_req_json = form_json(
        'proof-request',
        (json.dumps({k: claims[2][k] for k in claims[2] if k in ('sriRegDate', 'busId')}),),
        did['the-org-book'])
    url = url_for(cfg['sri']['Agent'], 'proof-request')
    r = requests.post(url, json=json.loads(proof_req_json))
    assert r.status_code == 200
    proof_resp = r.json()
    assert proof_resp

    # 7. Verifier verify proof
    verification_req_json = form_json(
        'verification-request',
        (json.dumps(proof_resp['proof-req']),json.dumps(proof_resp['proof'])))
    url = url_for(cfg['sri']['Agent'], 'verification-request')
    r = requests.post(url, json=json.loads(verification_req_json))
    assert r.status_code == 200
    verification_resp = r.json()
    assert verification_resp

    print("\n== 6 == the proof verifies as {}".format(ppjson(verification_resp)))
    assert verification_resp

    # 8. Exercise helper GET TXN call
    url = url_for(cfg['sri']['Agent'], 'txn/{}'.format(schema['seqNo']))
    r = requests.get(url)
    assert r.status_code == 200
    assert r.json()
    print("\n== 7 == ledger transaction by seq no {}: {}".format(schema['seqNo'], ppjson(r.json())))
    
    # 9. txn# non-existence case
    url = url_for(cfg['sri']['Agent'], 'txn/99999')
    r = requests.get(url)  # ought not exist
    assert r.status_code == 200
    print("\n== 8 == txn #99999: {}".format(ppjson(r.json())))
    assert not r.json() 

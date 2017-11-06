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

from indy import agent, anoncreds, ledger, signus, pool, wallet, IndyError
from indy.error import ErrorCode
from ..agent.nodepool import NodePool
from ..agent.demo_agents import TrustAnchorAgent, SRIAgent, OrgBookAgent, BCRegistrarAgent
from ..agent.util import encode, ppjson, plain_claims_for, prune_claims_json

import pytest
import json


def claim_value_pair(plain):
    return [str(plain), encode(plain)]


#noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_agents_direct(
        pool_name,
        pool_genesis_txn_path,
        seed_trustee1,
        pool_genesis_txn_file,
        path_home):

    # 1. Open pool
    p = NodePool(pool_name, pool_genesis_txn_path)

    await p.open()
    assert p.handle

    # 2. Init agents
    tag = TrustAnchorAgent(
        p,
        seed_trustee1,
        'trustee_wallet',
        None,
        '127.0.0.1',
        9700,
        'api/v0')
    sag = SRIAgent(
        p,
        'SRI-Agent-0000000000000000000000',
        'sri-agent-wallet',
        None,
        '127.0.0.1',
        9701,
        'api/v0')
    obag = OrgBookAgent(
        p,
        'The-Org-Book-Agent-0000000000000',
        'the-org-book-agent-wallet',
        None,
        '127.0.0.1',
        9702,
        'api/v0')
    bcrag = BCRegistrarAgent(
        p,
        'BC-Registrar-Agent-0000000000000',
        'bc-registrar-agent-wallet',
        None,
        '127.0.0.1',
        9703,
        'api/v0')

    await tag.open()
    await sag.open()
    await obag.open()
    await bcrag.open()

    # 3. Publish agent particulars to ledger if not yet present
    for ag in (tag, sag, obag, bcrag):
        if not json.loads(await tag.get_nym(ag.did)):
            await tag.send_nym(ag.did, ag.verkey)
        if not json.loads(await tag.get_endpoint(ag.did)):
            await ag.send_endpoint()

    nyms = {
        'tag': await tag.get_nym(tag.did),
        'sag': await tag.get_nym(sag.did),
        'obag': await tag.get_nym(obag.did),
        'bcrag': await tag.get_nym(bcrag.did)
    }
    endpoints = {
        'tag': await tag.get_endpoint(tag.did),
        'sag': await tag.get_endpoint(sag.did),
        'obag': await tag.get_endpoint(obag.did),
        'bcrag': await tag.get_endpoint(bcrag.did)
    }

    print("\n\n=== 1 === nyms {}\nendpoints {}\n".format(nyms, endpoints))

    for k in nyms:
        assert 'dest' in nyms[k]
    for k in endpoints:
        assert 'ha' in endpoints[k]

    # 4. Publish schema to ledger if not yet present; get from ledger
    schema_data = {
        'name': 'supplier-registration',
        'version': '1.1',
        'attr_names': [
            'id',
            'busId',
            'orgTypeId',
            'jurisdictionId',
            'LegalName',
            'effectiveDate',
            'endDate',
            'sriRegDate'
        ]
    }

    try:
        schema_json = await tag.get_schema(tag.did, 'Xxxx', 'X.x')  # Bad version number
    except IndyError as e:
        assert ErrorCode.LedgerInvalidTransaction == e.error_code
    schema_json = await tag.get_schema(tag.did, schema_data['name'], schema_data['version'])  # may exist
    if not json.loads(schema_json):
        schema_json = await tag.send_schema(json.dumps(schema_data))
    schema_json = await tag.get_schema(tag.did, schema_data['name'], schema_data['version'])  # should exist now
    schema = json.loads(schema_json)
    assert schema
    print("\n\n=== 2 === SCHEMA {}".format(ppjson(schema)))

    # 5. Issuer create, store,  and publish claim def to ledger
    # print('TAG DID {}'.format(tag.did))      # V4SG...
    # print('SAG DID {}'.format(sag.did))      # FaBA...
    # print('OBAG DID {}'.format(obag.did))    # 34JS...
    # print('BCRAG DID {}'.format(bcrag.did))  # Q4zq...
    claim_def_json = await obag.get_claim_def(999999, bcrag.did)  # ought not exist
    assert not json.loads(claim_def_json)
    claim_def_json = await bcrag.send_claim_def(schema_json)

    claim_def_json = await obag.get_claim_def(schema['seqNo'], bcrag.did)  # ought to exist now
    assert json.loads(claim_def_json)['ref'] == schema['seqNo']
    print('\n\n\n\n=== 3 === claim def {}'.format(ppjson(json.loads(claim_def_json))))

    # 6. Setup master secrets, claim reqs at Prover agents
    await obag.create_master_secret('MasterSecret')

    wallet_num = obag.wallet.num
    assert (await obag.reset_wallet()) > wallet_num  # makes sure later ops are OK on reset wallet

    await obag.store_claim_offer(bcrag.did, schema['seqNo'])
    claim_req_json = await obag.store_claim_req(bcrag.did, claim_def_json)

    print('\n\n\n=== 4 === claim req {}'.format(claim_req_json))

    # 7. Issuer issue claims and store at prover: get claim req, create claim, store claim
    claims = [
        {
            'id': claim_value_pair('1'),
            'busId': claim_value_pair('11121398'),
            'orgTypeId': claim_value_pair('2'),
            'jurisdictionId': claim_value_pair('1'),
            'LegalName': claim_value_pair('The Original House of Pies'),
            'effectiveDate': claim_value_pair('2010-10-10'),
            'endDate': claim_value_pair(None),
            'sriRegDate': claim_value_pair(None)
        },
        {
            'id': claim_value_pair('2'),
            'busId': claim_value_pair('11133333'),
            'orgTypeId': claim_value_pair('1'),
            'jurisdictionId': claim_value_pair('1'),
            'LegalName': claim_value_pair('Planet Cake'),
            'effectiveDate': claim_value_pair('2011-10-01'),
            'endDate': claim_value_pair(None),
            'sriRegDate': claim_value_pair(None)
        },
        {
            'id': claim_value_pair('3'),
            'busId': claim_value_pair('11144444'),
            'orgTypeId': claim_value_pair('2'),
            'jurisdictionId': claim_value_pair('1'),
            'LegalName': claim_value_pair('Tart City'),
            'effectiveDate': claim_value_pair('2012-12-01'),
            'endDate': claim_value_pair(None),
            'sriRegDate': claim_value_pair(None)
        }
    ]
    for c in claims:
        (_, claim_json) = await bcrag.create_claim(claim_req_json, c)
        assert json.loads(claim_json)
        await obag.store_claim(claim_json)
    

    # 8. Prover finds claims
    by_attr = {
        'nonce': '1234',
        'name': 'proof_req_0',
        'version': '0',
        'requested_attrs': {
            '{}_uuid'.format(attr): {
                'schema_seq_no': schema['seqNo'],
                'name': attr
            } for attr in claims[0]
        },
        'requested_predicates': {
        },
    } 
    (claim_uuids_all, claims_found_json) = await obag.get_claims(json.dumps(by_attr))
    print("\n== 5 == claims by attr, no filter {}; {}".format(claim_uuids_all, ppjson(claims_found_json)))
    claims_found = json.loads(claims_found_json)
    display_pruned_postfilt = plain_claims_for(claims_found, {'LegalName': claims[2]['LegalName'][0]})
    print("\n== 6 == display claims filtered post-hoc matching {}: {}".format(
        claims[2]['LegalName'][0],
        ppjson(display_pruned_postfilt)))  # LegalName appears plain: we specified it to plain_claims_for()
    display_pruned = prune_claims_json({k for k in display_pruned_postfilt}, claims_found)
    print("\n== 7 == stripped down {}".format(ppjson(display_pruned)))

    filter_enc = {k: claims[2][k][1] for k in claims[2] if k in ('sriRegDate', 'busId')}
    (claim_uuids_filt, claims_found_json) = await obag.get_claims(json.dumps(by_attr), filter_enc)
    print("\n== 8 == claims by attr, filtered a priori {}; {}".format(claim_uuids_filt, ppjson(claims_found_json)))
    assert set([*display_pruned_postfilt]) == claim_uuids_filt
    assert len(display_pruned_postfilt) == 1

    # 9. Prover responds to request for proof
    claim_uuid = claim_uuids_filt.pop()
    claims_found = json.loads(claims_found_json)
    requested_claims = {
        'self_attested_attributes': {},
        'requested_attrs': {
            attr: [claim_uuid, True]
                for attr in by_attr['requested_attrs'] if attr in claims_found['attrs']
        },
        'requested_predicates': {
            pred: claim_uuid
                for pred in by_attr['requested_predicates']
        }
    }
    proof_json = await obag.create_proof(json.dumps(by_attr), schema, json.loads(claim_def_json), requested_claims)
    print("\n== 9 == proof {}".format(ppjson(proof_json)))

    # 10. Verifier verify proof
    rc_json = await sag.verify_proof(json.dumps(by_attr), json.loads(proof_json), schema, json.loads(claim_def_json))
    print("\n== 10 == the proof verifies as {}".format(ppjson(rc_json)))
    assert json.loads(rc_json)

    await bcrag.close()
    await obag.close()
    await sag.close()
    await tag.close()
    await p.close()


#noinspection PyUnusedLocal
@pytest.mark.asyncio
async def test_agents_process_forms_local(
        pool_name,
        pool_genesis_txn_path,
        seed_trustee1,
        pool_genesis_txn_file,
        path_home):

    # 1. Open pool, init agents
    async with NodePool(pool_name, pool_genesis_txn_path) as p, (
            TrustAnchorAgent(
                p,
                seed_trustee1,
                'trustee_wallet',
                None,
                '127.0.0.1',
                '9700',
                'api/v0')) as tag, (
            SRIAgent(
                p,
                'SRI-Agent-0000000000000000000000',
                'sri-agent-wallet',
                None,
                '127.0.0.1',
                9701,
                'api/v0')) as sag, (
            OrgBookAgent(
                p,
                'The-Org-Book-Agent-0000000000000',
                'org-book-agent-wallet',
                None,
                '127.0.0.1',
                9702,
                'api/v0')) as obag, (
            BCRegistrarAgent(
                p,
                'BC-Registrar-Agent-0000000000000',
                'bc-reg-agent-wallet',
                None,
                '127.0.0.1',
                9703,
                'api/v0')) as bcrag:

        assert p.handle is not None

        # 2. Publish agent particulars to ledger if not yet present
        for ag in (tag, sag, obag, bcrag):
            nym_lookup_form = {
                'type': 'agent-nym-lookup',
                'data': {
                    'agent-nym': {
                        'did': ag.did
                    }
                }
            }
            nym = json.loads(await ag.process_post(nym_lookup_form))
            if not nym:
                resp_json = await tag.process_post({
                    'type': 'agent-nym-send',
                    'data': {
                        'agent-nym': {
                            'did': ag.did,
                            'verkey': ag.verkey
                        }
                    }
                })

            nym = json.loads(await ag.process_post(nym_lookup_form))  # ought to exist now
            assert nym

            endpoint_lookup_form = {
                'type': 'agent-endpoint-lookup',
                'data': {
                    'agent-endpoint': {
                        'did': ag.did
                    }
                }
            }
            endpoint = json.loads(await tag.process_post(endpoint_lookup_form))
            if not endpoint:
                resp_json = await ag.process_post({
                    'type': 'agent-endpoint-send',
                    'data': {
                    }
                })
            endpoint = json.loads(await ag.process_post(endpoint_lookup_form))  # ought to exist now
            assert endpoint

        try:  # Make sure only a trust anchor can register an agent
            await sag.process_post({
                'type': 'agent-nym-send',
                'data': {
                    'agent-nym': {
                        'did': sag.did,
                        'verkey': sag.verkey
                    }
                }
            })
            assert False
        except NotImplementedError:
            pass

        # 3. Publish schema to ledger if not yet present; get from ledger
        schema_data = {
            'name': 'supplier-registration',
            'version': '1.1',
            'attr_names': [
                'id',
                'busId',
                'orgTypeId',
                'jurisdictionId',
                'LegalName',
                'effectiveDate',
                'endDate',
                'sriRegDate'
            ]
        }

        schema_lookup_form = {
            'type': 'schema-lookup',
            'data': {
                'schema': {
                    'issuer-did': tag.did,
                    'name': schema_data['name'],
                    'version': 'xxxx'
                },
            }
        }

        try:
            schema_json = await tag.process_post(schema_lookup_form)  # Bad version number
            assert False
        except IndyError:
            pass

        schema_lookup_form['data']['schema']['version'] = '999.999'
        assert not json.loads(await tag.process_post(schema_lookup_form))  # ought not exist
        schema_lookup_form['data']['schema']['version'] = '1.1'
        schema_json = await tag.process_post(schema_lookup_form)  # may exist
        if not json.loads(schema_json):
            schema_send = json.loads(await tag.process_post({
                'type': 'schema-send',
                'data': {
                    'schema': {
                        'issuer-did': tag.did,
                        'name': schema_data['name'],
                        'version': schema_data['version']
                    },
                    'attr-names': schema_data['attr_names']
                }
            }))
            assert schema_send
        schema_json = await sag.process_post(schema_lookup_form)
        schema = json.loads(schema_json)  # should exist now
        assert schema
        print("\n\n=== 2 === SCHEMA {}".format(ppjson(schema)))

        try:  # Make sure only an origin can send a schema
            await sag.process_post({
                'type': 'schema-send',
                'data': {
                    'schema': {
                        'issuer-did': tag.did,
                        'name': schema_data['name'],
                        'version': schema_data['version']
                    },
                    'attr-names': schema_data['attr_names']
                }
            })
            assert False
        except NotImplementedError:
            pass

        # 4. Issuer create, store,  and publish claim def to ledger
        # print('TAG DID {}'.format(tag.did))      # V4SG...
        # print('SAG DID {}'.format(sag.did))      # FaBA...
        # print('OBAG DID {}'.format(obag.did))    # 34JS...
        # print('BCRAG DID {}'.format(bcrag.did))  # Q4zq...

        claim_def_send_form = {
            'type': 'claim-def-send',
            'data': {
            }
        }

        try:  # schema unspecified, ought to fail
            await bcrag.process_post(claim_def_send_form)
        except ValueError:
            pass
        await bcrag.process_post(schema_lookup_form)  # bootstrap issuer with current schema
        await bcrag.process_post(claim_def_send_form)
        claim_def_json = await obag.get_claim_def(schema['seqNo'], bcrag.did)  # ought to exist now (short-circuit)
        assert json.loads(claim_def_json)['ref'] == schema['seqNo']

        # 5. Setup master secrets, claim reqs at Prover agents
        master_secret_set_form = {
            'type': 'master-secret-set',
            'data': {
                'label': 'maestro'
            }
        }
        claim_hello_form = {
            'type': 'claim-hello',
            'data': {
                'issuer-did': bcrag.did
            }
        }

        try:  # master secret unspecified, ought to fail
            await obag.process_post(claim_hello_form)
        except ValueError:
            pass

        await obag.process_post(master_secret_set_form)
        try:  # schema unspecified, ought to fail
            claim_req_json = await obag.process_post(claim_hello_form)
        except ValueError:
            pass

        claims_reset_resp = json.loads(await obag.process_post({  # make sure later ops are OK on reset wallet
            'type': 'claims-reset',
            'data': {
            }
        }))
        assert not claims_reset_resp

        await obag.process_post(schema_lookup_form)  # bootstrap prover with current schema
        claim_req_json = await obag.process_post(claim_hello_form)
        claim_req = json.loads(claim_req_json)
        assert claim_req
        print('\n\n=== XX === claim-req from bc-rag->obag hello: {}'.format(ppjson(claim_req)))

        # 6. Issuer issue claims and store at prover: get claim req, create claim, store claim
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
            claim_json = await bcrag.process_post({
                'type': 'claim-create',
                'data': {
                    'claim-req': claim_req,
                    'claim-attrs': c
                }
            })
            claim = json.loads(claim_json)
            await obag.process_post({
                'type': 'claim-store',
                'data': {
                    'claim': claim
                }
            })

        # 7. Prover finds claims
        by_attr = {
            'nonce': '1234',
            'name': 'proof_req_0',
            'version': '0',
            'requested_attrs': {
                '{}_uuid'.format(attr): {
                    'schema_seq_no': schema['seqNo'],
                    'name': attr
                } for attr in claims[0]
            },
            'requested_predicates': {
            },
        } 
        claims_all = json.loads(await obag.process_post({
            'type': 'claim-request',
            'data': {
                'claim-filter': {
                    'attr-match': {
                    },
                    'predicate-match': [
                    ]
                }
            }
        }))
        print("\n== 3 == claims by attr, no filter, process-post {}".format(ppjson(claims_all)))
        display_pruned_postfilt = plain_claims_for(claims_all['claims'], {'LegalName': claims[2]['LegalName']})
        print("\n== 4 == display claims filtered post-hoc matching {}: {}".format(
            claims[2]['LegalName'],
            ppjson(display_pruned_postfilt)))  # LegalName appears plain: we specified it to plain_claims_for()
        display_pruned = prune_claims_json({k for k in display_pruned_postfilt}, claims_all['claims'])
        print("\n== 5 == stripped down {}".format(ppjson(display_pruned)))

        claims_prefilt_json = await obag.process_post({
            'type': 'claim-request',
            'data': {
                'claim-filter': {
                    'attr-match': {
                        k: claims[2][k] for k in claims[2] if k in ('sriRegDate', 'busId')
                    },
                    'predicate-match': [
                    ]
                }
            }
        })
        claims_prefilt = json.loads(claims_prefilt_json)
        print("\n== 6 == claims by attr, with filter a priori, process-post {}".format(ppjson(claims_prefilt)))
        display_pruned_prefilt = plain_claims_for(claims_prefilt['claims'])
        print("\n== 7 == display claims filtered a priori matching {}: {}".format(
            claims[2]['LegalName'],
            ppjson(display_pruned_prefilt)))  # LegalName appears encoded: we didn't specify it to plain_claims_for()
        assert set([*display_pruned_postfilt]) == set([*display_pruned_prefilt])
        assert len(display_pruned_postfilt) == 1

        # 8. Prover responds to request for proof
        claim_uuid = set([*display_pruned_prefilt]).pop()  # TODO: allow claim-req/proof-req by claim_uuid handle
        proof_resp = json.loads(await obag.process_post({
            'type': 'proof-request',
            'data': {
                'claim-filter': {
                    'attr-match': {
                        k: claims[2][k] for k in claims[2] if k in ('sriRegDate', 'busId')
                    },
                    'predicate-match': [
                    ]
                }
            }
        }))
        print("\n== 8 == proof response {}".format(ppjson(proof_resp)))

        # 9. Verifier verify proof
        rc_json = await sag.process_post({
            'type': 'verification-request',
            'data': proof_resp
        })
        print("\n== 9 == the proof verifies as {}".format(ppjson(rc_json)))
        assert json.loads(rc_json)

        # 10. Exercise helper GET calls
        txn_json = await sag.process_get_txn(schema['seqNo'])
        print("=== 10 === schema by txn #{}: {}".format(schema['seqNo'], ppjson(txn_json)))
        assert json.loads(txn_json)
        txn_json = await sag.process_get_txn(99999)  # ought not exist
        assert not json.loads(txn_json)

        did_json = await bcrag.process_get_did()
        print("=== 11 === bcrag did: {}".format(ppjson(did_json)))
        assert json.loads(did_json)

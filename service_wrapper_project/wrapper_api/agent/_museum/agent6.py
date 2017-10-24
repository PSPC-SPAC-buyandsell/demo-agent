from binascii import b2a_hex
from indy import agent, anoncreds, ledger, signus, pool, wallet, IndyError
from indy.error import ErrorCode
from requests import post
from time import time
from typing import Set

import json


def asc2decstr(a: str):
    return str(int.from_bytes(b2a_hex(a.encode()), "big"))

def ha(host: str, port: int) -> str:
    """
    Formats input host and port into host:port string

    :param host: host IP address
    :param int: host port
    :return: formatted host:port string for indy-sdk consumption
    """

    return '{}:{}'.format(host, port)


class NodePool:
    """
    Class encapsulating indy-sdk node pool.
    """

    def __init__(self, name: str, genesis_txn_path: str) -> None:
        """
        Initializer for node pool. Does not open the pool, only retains input parameters.

        :param name: name of the pool
        :param genesis_txn_path: path to genesis transaction file
        """

        self._name = name
        self._genesis_txn_path = genesis_txn_path
        self._handle = None

    @property
    def name(self) -> str:
        """
        Accessor for pool name

        :return: pool name
        """

        return self._name

    @property
    def genesis_txn_path(self) -> str:
        """
        Accessor for path to genesis transaction file

        :return: path to genesis transaction file
        """

        return self._genesis_txn_path

    @property
    def handle(self) -> int:
        """
        Accessor for indy-sdk pool handle

        :return: indy-sdk pool handle
        """

        return self._handle

    async def __aenter__(self) -> 'NodePool':
        """
        Context manager entry. Opens pool as configured, for closure on context manager exit.
        For use in monolithic call opening, using, and closing the pool.

        :return: current object
        """

        return await self.open()

    async def open(self) -> 'NodePool':
        """
        Explicit entry. Opens pool as configured, for later closure via close().
        For use when keeping pool open across multiple calls.

        :return: current object
        """

        await pool.create_pool_ledger_config(self.name, json.dumps({'genesis_txn': str(self.genesis_txn_path)}))
        self._handle = await pool.open_pool_ledger(self.name, None)
        return self
        
    async def __aexit__(self, exc_type, exc, traceback) -> None: 
        """
        Context manager exit. Closes pool and deletes its configuration to ensure clean next entry.
        For use in monolithic call opening, using, and closing the pool.

        :param exc_type:
        :param exc:
        :param traceback:
        """

        await self.close()

    async def close(self) -> None:
        """
        Explicit exit. Closes pool and deletes its configuration to ensure clean next entry.
        For use when keeping pool open across multiple calls.
        """

        await pool.close_pool_ledger(self.handle)
        await pool.delete_pool_ledger_config(self.name)

    def __repr__(self) -> str:
        """
        Return representation for current object.

        :return: representation for current object
        """

        return 'NodePool({}, {})'.format(self.name, self.genesis_txn_path)


class BaseAgent:
    """
    Base class for agent
    """

    def __init__(self, pool: NodePool, seed: str, wallet_name: str, wallet_config: str) -> None:
        """
        Initializer for agent. Does not open its wallet, only retains input parameters.

        :param pool: node pool on which agent operates
        :param seed: seed to bootstrap agent
        :param wallet_name: name of wallet that agent uses
        :param wallet_config: wallet configuration json, None for default
        """

        self._pool = pool

        self._seed = seed
        self._did_seed = json.dumps({'seed': seed})

        self._wallet_name = wallet_name
        self._wallet_handle = None
        self._wallet_config = wallet_config

        self._did = None
        self._verkey = None
        self._pubkey = None
        # self._conn_handles = set()

        self._master_secret = None  # prover

    @property
    def pool(self) -> NodePool:
        """
        Accessor for node pool

        :return: node pool
        """

        return self._pool

    @property
    def wallet_name(self) -> str:
        """
        Accessor for wallet name

        :return: wallet name
        """

        return self._wallet_name

    @property
    def wallet_handle(self) -> int:
        """
        Accessor for wallet handle

        :return: wallet handle
        """

        return self._wallet_handle

    @property
    def wallet_config(self) -> str:
        """
        Accessor for wallet config json

        :return: wallet config json
        """

        return self._wallet_config

    @property
    def did(self) -> str:
        """
        Accessor for agent DID

        :return: agent DID
        """

        return self._did

    @property
    def verkey(self) -> str:
        """
        Accessor for agent verification key

        :return: agent verification key
        """

        return self._verkey

    @property
    def pubkey(self) -> str:
        """
        Accessor for agent public (encryption) key

        :return: agent public (encryption) key
        """

        return self._pubkey

    async def __aenter__(self) -> 'BaseAgent':
        """
        Context manager entry. Opens wallet and stores agent DID in it.
        For use in monolithic call opening, using, and closing the agent.

        :return: current object
        """

        return await self.open()

    async def open(self) -> 'BaseAgent':
        """
        Explicit entry. Opens wallet and stores agent DID in it.
        For use when keeping agent open across multiple calls.

        :return: current object
        """

        try:
            await wallet.create_wallet(
                pool_name=self.pool.name,
                name=self.wallet_name,
                xtype=None,
                config=self.wallet_config,
                credentials=None)
        except IndyError as e:
            if e.error_code != ErrorCode.WalletAlreadyExistsError:
                raise
        self._wallet_handle = await wallet.open_wallet(self.wallet_name, self.wallet_config, None)

        (self._did, self._verkey, self._pubkey) = (
            await signus.create_and_store_my_did(self.wallet_handle, self._did_seed))

        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        """
        Context manager exit. Closes wallet; closes and cleans up connections.
        For use in monolithic call opening, using, and closing the agent.

        :param exc_type:
        :param exc:
        :param traceback:
        """

        await self.close()

    async def close(self) -> None:
        """
        Explicit exit. Closes wallet; closes and cleans up connections.
        For use when keeping agent open across multiple calls.
        """

        # for conn_handle in self._conn_handles:
        #     await agent.agent_close_connection(conn_handle)
        # self._conn_handles.clear()
        await wallet.close_wallet(self.wallet_handle)

    async def get_nym(self, did: str) -> str:
        """
        Get cryptonym (including current verification key) for input (agent) DID from ledger.

        :param did: DID of cryptonym to fetch
        :return: cryptonym json 
        """

        get_nym_req = await ledger.build_get_nym_request(
            self.did,
            did)
        resp_json = await ledger.submit_request(self.pool.handle, get_nym_req)
        resp = (json.loads(resp_json))['result']
        return json.dumps(resp)

    async def send_nym(self, agent: 'BaseAgent') -> None:  # Trust Anchor
        """
        Method for trust anchor to send input agent's cryptonym (including DID and current verification key) to ledger.

        :param agent: agent whose cryptonym to send to ledger
        """

        req_json = await ledger.build_nym_request(
            self.did,
            agent.did,
            agent.verkey,
            None,
            None)
        await ledger.sign_and_submit_request(
            self.pool.handle,
            self.wallet_handle,
            self.did,
            req_json)

    """
    # Connection/disconnection/send: handle inter-agent communication through service wrapper
    async def connect_to(self, agent_to):
        send_handle = await agent.agent_connect(self.pool.handle, self.wallet_handle, self.did, agent_to.did)
        self._conn_handles.add(send_handle)
        event = await agent.agent_wait_for_event([agent_to.listener_handle])  # type: agent.MessageEvent
        return send_handle, event.connection_handle  # send, recv
        
    # Connection/disconnection/send: handle inter-agent communication through service wrapper
    async def disconnect_from(self, agent_to):
        conn_handle = agent_to.send_handle
        if handle in self._conn_handles:
            await agent.agent_close_connection(conn_handle)
            self._conn_handles.remove(conn_handle)

    # Connection/disconnection/send: handle inter-agent communication through service wrapper
    async def send(self, conn_send_handle, message):
        await agent.agent_send(conn_send_handle, message)
    """

    async def post_agent(self, recv_did: str, path_query_fragment: str, msg_json: str) -> None:
        """
        Get endpoint for input agent DID; append path, query, fragment; POST message json to its service wrapper.

        :param recv_did: DID of recipient agent
        :param path_query_fragment: string to append to host, port (and trailing slash) to form URL to which to POST
        :param msg_json: json to POST to recipient service wrapper
        """

        pass  # TODO: implement

    async def send_schema(self, schema_data_json: str) -> str:  # issuer
        """
        Method for issuer to send schema to ledger, then retrieve it as written (and completed through
        the write process to the ledger) and return it.

        :param schema_data_json: schema data json with name, version, attribute names;
            e.g.,: {
                'name': 'my-schema',
                'version': '1.234',
                'attr_names': ['favourite_drink', 'height', 'last_visit_date']
            }
        :return: schema json as written to ledger
        """

        req_json = await ledger.build_schema_request(self.did, schema_data_json)
        resp_json = await ledger.sign_and_submit_request(self.pool.handle, self.wallet_handle, self.did, req_json)
        resp = (json.loads(resp_json))['result']
        return await self.get_schema(resp['identifier'], resp['data']['name'], resp['data']['version'])

    async def get_schema(
            self,
            issuer_did: str,
            name: str,
            version: str) -> str:  # issuer, verifier, prover
        """
        Method for issuer/verifier/prover to get schema from ledger by issuer, name, and version.

        :param issuer_did: DID of schema issuer
        :param name: schema name
        :param version: schema version string

        :return: schema json as retrieved from ledger
        """

        req_json = await ledger.build_get_schema_request(
            self.did,
            issuer_did,
            json.dumps({'name': name, 'version': version}))
        resp_json = await ledger.submit_request(self.pool.handle, req_json)
        resp = json.loads(resp_json)
        resp['result']['data']['keys'] = resp['result']['data'].pop('attr_names')
        return json.dumps(resp['result'])

    async def send_claim_def(self, schema: dict, keys: tuple = None) -> str:  # issuer
        """
        Method for issuer to send claim definition to ledger, then retrieve it as written (and completed through
        the write process to the ledger) and return it.

        :param schema: schema dict, as retrieved from ledger, on which to base claim definition
        :param keys: keys to include as revealed attributes in claim definition (None defaults to all keys)
        :return: claim definition json as written to ledger
        """

        if keys:
            schema['data']['keys'] = [k for k in keys if k in schema['data']['keys']]
        schema_json = json.dumps(schema)

        claim_def_json = await anoncreds.issuer_create_and_store_claim_def(
            self.wallet_handle,
            self.did,  # NB: claim def issuer need not be schema issuer; use same for both for now
            schema_json,
            'CL',
            False)
        # print("\n\n~~~~~~ SK:0 SEND_CLAIM_DEF schema {}".format(json.dumps(schema, indent=4)))
        req_json = await ledger.build_claim_def_txn(
            self.did,
            schema['seqNo'],
            'CL',
            json.dumps(json.loads(claim_def_json)['data']))
        resp_json = await ledger.sign_and_submit_request(
            self.pool.handle,
            self.wallet_handle,
            self.did,
            req_json)
        # print("\n\n~~~~~~ SK:2 SEND_CLAIM_DEF resp_json {}".format(json.dumps(json.loads(resp_json), indent=4)))
        return await self.get_claim_def(schema)

    async def get_claim_def(self, schema: dict) -> str:  # issuer, verifier, prover
        """
        Method for issuer/verifier/prover to get claim definition from ledger by its parent schema.

        :param schema: schema dict, as retrieved from ledger, acting as base for claim definition
        :return: claim definition json as retrieved from ledger
        """
        req_json = await ledger.build_get_claim_def_txn(
            self.did,
            schema['seqNo'],
            'CL',
            schema['dest'])
        # print("\n\n~~~~~~ SK:10 GET_CLAIM_DEF req_json {}".format(json.dumps(json.loads(req_json), indent=4)))
        resp_json = await ledger.submit_request(self.pool.handle, req_json)
        resp = json.loads(resp_json)
        # print("\n\n~~~~~~ SK:11 GET_CLAIM_DEF build-get-claim-def-txn -> {}".format(json.dumps(resp, indent=4)))
        if resp['result']['data']['revocation'] is not None:
            resp['result']['data']['revocation'] = None  #TODO: support revocation
        return json.dumps(resp['result'])

    async def create_master_secret(self, master_secret: str) -> None:  # prover
        """
        Method for prover to create a master secret used in proofs.

        :param master_secret: label for master secret; indy-sdk uses label to generate master secret
        """
        await anoncreds.prover_create_master_secret(self.wallet_handle, master_secret)
        self._master_secret = master_secret  # prover

    async def store_claim_req(
            self,
            schema_issuer_did: str,
            schema_seq_no: int,
            claim_def_json: str) -> str:  # prover
        """
        Method for prover to create a claim request and store it in its wallet.

        :param schema_issuer_did: DID of schema issuer
        :param schema_seq_no: sequence number of schema on the ledger
        :param claim_def_json: claim definition as retrieved from ledger
        :return: claim request json as stored in wallet
        """
        if self._master_secret is None:
            raise ValueError('Master secret is not set')

        return await anoncreds.prover_create_and_store_claim_req(
            self.wallet_handle,
            self.did,
            json.dumps({'issuer_did': schema_issuer_did, 'schema_seq_no': schema_seq_no}),
            claim_def_json,
            self._master_secret);

    async def create_claim(self, claim_req_json: str, claim: dict) -> (str, str):  # issuer
        """
        Method for issuer to create claim out of claim request and dict of key:[value, encoding] entries
        for revealed attributes.

        :param claim_req_json: claim request as created by prover
        :param claim: claim dict mapping each revealed attribute to its [value, encoding];
            e.g., {
                'favourite_drink': ['martini', '1103189706537168622028552856221241'],
                'height': ['180', '180'],
                'last_visit_date': ['2017-12-31', '292278025700124567977725373155106423905275032369']
            }
        :return: revocation registry update json, newly issued claim json
        """
        return await anoncreds.issuer_create_claim(
            self.wallet_handle,
            claim_req_json,
            json.dumps(claim),
            -1)

    async def store_claim(self, claim_json: str) -> None:  # prover
        """
        Method for prover to store claim in wallet.

        :param claim_json: json claim as prover created
        """
        await anoncreds.prover_store_claim(self.wallet_handle, claim_json)

    async def create_proof(
            self,
            proof_req: dict,
            schema: dict,
            claim_def: dict,
            requested_claims: dict = None) -> str:  # prover
        """
        Method for prover to create proof.

        :param proof_req: proof request json as verifier creates; has entries for proof request's
            nonce, name, and version; plus claim's requested attributes, requested predicates.
            E.g., {
                'nonce': 12345,  # for verifier info, not prover matching
                'name': 'proof-request',  # for verifier info, not prover matching
                'version': '1.2',  # for verifier info, not prover matching
                'requested_attrs': {
                    'attr1_uuid': {
                        'schema_seq_no': 57,
                        'name': 'favourite_drink'
                    },
                    'attr2_uuid': {
                        'schema_seq_no': 57,
                        'name': 'height'
                    },
                    'attr3_uuid': {
                        'schema_seq_no': 57,
                        'name': 'last_visit_date'
                    },
                },
                'requested_predicates': {
                    'predicate1_uuid': {
                        'attr_name': 'age',
                        'p_type': 'GE',
                        'value': 19
                    }
                }
            }
        :param schema: schema used in proof, as retrieved from ledger (multiple schemata not supported yet)
        :param claim_def: claim definition as retrieved from ledger
        :param requested_claims: data structure with self-attested attribute info, requested attribute info
            and requested predicate info, assembled from get_claims_for_proof_req() and filtered for
            content of interest.
            E.g., {
                'self_attested_attributes': {},
                'requested_attrs': {
                    'attr0_uuid': ['claim::31291362-9b75-4353-a948-a7d02d0e7a00', True],
                    'attr1_uuid': ['claim::97977381-ca99-3817-8f22-a07cd3550287', True]
                },
                'requested_predicates': {
                    'predicate0_uuid': claim::31219731-9783-a772-bc98-12369780831f'
                }
            }
        :return: proof json
        """

        if self._master_secret is None:
            raise ValueError('Master secret is not set')

        # TODO: support empty requested-attributes?
        # TODO: support multiple schemata? Tricky.

        proof_json = await anoncreds.prover_create_proof(
            self.wallet_handle,
            json.dumps(proof_req),
            json.dumps(requested_claims),
            json.dumps({  # schemas_json
                claim_uuid[0]: schema
                    for claim_uuid in requested_claims['requested_attrs'].values()
            }),
            self._master_secret,
            json.dumps({  # claim_defs_json
                claim_uuid[0]: claim_def
                    for claim_uuid in requested_claims['requested_attrs'].values()
            }),
            json.dumps({})  # revoc_regs_json
        )

        return proof_json

    async def verify_proof(self, proof_req: dict, proof: dict, schema: dict, claim_def: dict) -> bool:  # verifier
        """
        Method for verifier to verify proof.

        :param proof_req: proof request json as verifier creates; has entries for proof request's
            nonce, name, and version; plus claim's requested attributes, requested predicates
            E.g., {
                'nonce': 12345,  # for verifier info, not prover matching
                'name': 'proof-request',  # for verifier info, not prover matching
                'version': '1.2',  # for verifier info, not prover matching
                'requested_attrs': {
                    'attr1_uuid': {
                        'schema_seq_no': 57,
                        'name': 'favourite_drink'
                    },
                    'attr2_uuid': {
                        'schema_seq_no': 57,
                        'name': 'height'
                    },
                    'attr3_uuid': {
                        'schema_seq_no': 57,
                        'name': 'last_visit_date'
                    },
                },
                'requested_predicates': {
                    'predicate1_uuid': {
                        'attr_name': 'age',
                        'p_type': 'GE',
                        'value': 19
                    }
                }
            }
        :param proof: proof as prover creates
        :param schema: schema used in proof, as retrieved from ledger (multiple schemata not supported yet)
        :param claim_def: claim definition as retrieved from ledger
        :return: true if proof is valid; false if not
        """

        return await anoncreds.verifier_verify_proof(
            json.dumps(proof_req),
            json.dumps(proof),
            json.dumps({  # schemas_json
                claim_uuid: schema for claim_uuid in proof['proofs']
            }),
            json.dumps({  # claim_defs_json
                claim_uuid: claim_def for claim_uuid in proof['proofs']
            }),
            json.dumps({})  # revoc_regs_json
        )

    async def get_claims_for_proof_req(self, proof_req_json: str, filter_enc: dict = None) -> (Set[str], str):  # prover
        """
        Method for prover to get claims (from wallet) corresponding to proof request

        :param proof_req: proof request json as verifier creates; has entries for proof request's
            nonce, name, and version; plus claim's requested attributes, requested predicates
            E.g., {
                'nonce': 12345,  # for verifier info, not prover matching
                'name': 'proof-request',  # for verifier info, not prover matching
                'version': '1.2',  # for verifier info, not prover matching
                'requested_attrs': {
                    'attr1_uuid': {
                        'schema_seq_no': 57,
                        'name': 'favourite_drink'
                    },
                    'attr2_uuid': {
                        'schema_seq_no': 57,
                        'name': 'height'
                    },
                    'attr3_uuid': {
                        'schema_seq_no': 57,
                        'name': 'last_visit_date'
                    },
                },
                'requested_predicates': {
                    'predicate1_uuid': {
                        'attr_name': 'age',
                        'p_type': 'GE',
                        'value': 19
                    }
                }
            }
        :param filter_enc: dict with encoded values to match in revealed attributes (default None for no filter);
            e.g., {
                'height': '175',
                'name': '1139481716457488690172217916278103335'
            }
        :return: tuple with (set of claim uuids, json with claims for input proof request)
        """
        claims_for_proof_json = await anoncreds.prover_get_claims_for_proof_req(self.wallet_handle, proof_req_json)

        claims_for_proof = json.loads(claims_for_proof_json)
        # print("\n\n^^^ SK CLAIMS_FOR_PROOF {}\n".format(json.dumps(claims_for_proof, indent=4)))
        claim_uuids = set()
        # retain only claim of interest: find corresponding claim uuid(s)
        for attr_uuid in claims_for_proof['attrs']:
            for candidate in claims_for_proof['attrs'][attr_uuid]:
                if filter_enc is None:
                    claim_uuids.add(candidate['claim_uuid'])
                else:
                    # print("\n\n^^^ SK CANDIDATE {}".format(json.dumps(candidate, indent=4)))
                    if filter_enc.items() <= candidate['attrs'].items():
                        claim_uuids.add(candidate['claim_uuid'])
                        print("\n\n^^^ SK GOT CLAIM UUID {}".format(candidate['claim_uuid']))
                    else:  # it's not of interest
                        claims_for_proof['attrs'][attr_uuid].pop(candidate)

        for pred_uuid in claims_for_proof['predicates']:
            for candidate in claims_for_proof['predicates'][pred_uuid]:
                if filter_enc is None:
                    claim_uuids.add(candidate['claim_uuid'])
                elif candidate['claim_uuid'] not in claim_uuids:
                    claims_for_proof['predicates'][pred_uuid].pop(candidate)

        return claim_uuids, json.dumps(claims_for_proof)

    async def get_endpoint_attrib(self, did: str) -> str:
        """
        Get endpoint for agent having input DID

        :param did: DID for agent whose endpoint to find
        :return: json endpoint data for agent having input DID
        """

        req_json = await ledger.build_get_attrib_request(
            self.did,
            did,
            'endpoint')
        resp_json = await ledger.submit_request(self.pool.handle, req_json)
        data_json = (json.loads(resp_json))['result']['data']
        endpoint = json.loads(data_json)['endpoint']
        return json.dumps(endpoint)

    def __repr__(self) -> str:
        """
        Return representation for current object.

        :return: representation for current object
        """

        return 'BaseAgent({}, {}, {}, {})'.format(
            repr(self.pool),
            '[SEED]',
            self.wallet_name,
            self.wallet_config)


class ListeningAgent(BaseAgent):
    """
    Class for agent that listens and responds to other agents. Note that a service wrapper will
    listen for requests, parse requests, dispatch to agents, and return content to callers;
    the current design is not to use indy-sdk for direct agent-to-agent communication.

    The ListeningAgent differs from the BaseAgent only in that it stores endpoint information
    to put on the ledger.
    """

    def __init__(self,
            pool: NodePool,
            seed: str,
            wallet_name: str,
            wallet_config: str,
            host: str,
            port: int,
            agent_api_path: str = '') -> None:
        """
        Initializer for agent. Does not open its wallet, only retains input parameters.

        :pool: node pool on which agent operates
        :seed: seed to bootstrap agent
        :wallet_name: name of wallet that agent uses
        :wallet_config: wallet configuration json, None for default
        :host: agent IP address
        :port: agent port
        :agent_api_path: URL path to agent API, for use in proxying to further agents
        """

        super().__init__(pool, seed, wallet_name, wallet_config)
        self._host = host
        self._port = port
        self._agent_api_path = agent_api_path
        self._schema_metadata = None

    @property
    def host(self):
        return self._host

    @property
    def port(self):
        return self._port

    @property
    def agent_api_path(self):
        return self._agent_api_path

    @property
    def schema_metadata(self):
        return self._schema_metadata

    async def send_endpoint_attrib(self) -> str:
        """
        Send endpoint attribute to ledger. Return endpoint json as written (the process of writing the attribute
        to the ledger does not add any additional content).

        :return: endpoint attibute entry json with public key (which indy-sdk labels 'verkey')
            and host address (string in format IP address:port)
        """

        raw_json = json.dumps({
            'endpoint': {
                'ha': ha(self.host, self.port),
                'verkey': self.pubkey
            }
        })
        req_json = await ledger.build_attrib_request(self.did, self.did, None, raw_json, None)
        return await ledger.sign_and_submit_request(self.pool.handle, self.wallet_handle, self.did, req_json)

    @staticmethod
    def _vet_keys(must: Set[str], have: Set[str], hint: str = '') -> None:
        if not must.issubset(have):
            raise ValueError('Bad token:{} missing keys {}'.format(' ' + hint, must - have))

    async def process_post(self, req: dict) -> str:
        """
        Takes a request from service wrapper POST and dispatches the applicable agent action.
        Returns (json) response arising from processing.

        :param req: request on which to operate
        :return: json response
        """

        self.__class__._vet_keys({'type', 'data'}, set(req.keys()))  # all tokens need type and data

        if req['type'] == 'schema-claim-def-init':
            # init schema and claim def; respond with dict on both
            self.__class__._vet_keys(
                {
                    'schema-name',
                    'schema-version',
                    'attr-names'
                },
                set(req['data'].keys()),
                hint='data')
            schema_json = self.send_schema(json.dumps({k: req['data'][k] for k in req['data'] if k in keys}))
            schema = json.loads(schema_json)
            claim_def_json = self.send_claim_def(schema)

            # cache schema metadata en passant for future use
            self.schema_metadata = {
                'issuer': req['data']['issuer-did'],
                'name': req['data']['schema-name'],
                'version': req['data']['schema-version'],
                'seq_no': schema['seqNo'],
                'json': schema_json,
                'claim_def_json': claim_def_json}

            await self.store_claim_req(req['data']['issuer-did'], schema['seqNo'])  # TODO: only prover needs

            return json.dumps({'schema': schema, 'claim_def': json.loads(claim_def_json)}) 

        elif req['type'] == 'set-master-secret':
            self.__class__._vet_keys({'label'}, set(req['data'].keys()), hint='data')
            await self.create_master_secret(req['data']['label'])
            return json.dumps({})

        elif req['type'] in ('claim-request', 'proof-request'):
            self.__class__._vet_keys({'claim-filter'}, set(req['data'].keys()), hint='data')
            self.__class__._vet_keys({'attr-match'}, set(req['data']['claim-filter'].keys()), hint='claim-filter')
            # TODO: predicates

            # if it's a proxy request, go to the source
            if ('prover-did' in req['data']) and (req['data']['prover-did'] != self.did):
                endpoint = json.loads(get_endpoint_attrib(req['data']['remote-did']))
                # (host, port) = tuple(endpoint['ha'].split(':'))
                req['data'].pop('prover-did')
                r = post(
                    'http://{}/{}/{}'.format(
                        endpoint['ha'],
                        self.agent_api_path,
                        req['type']),
                    json=req)  # requests module json-encodes
                r.raise_for_status()
                return r.json()

            # it's local, carry on

            if 'schema' in req['data']:
                self.__class__._vet_keys(
                    {'issuer-did', 'name', 'version'},
                    set(req['data']['schema'].keys()),
                    hint='schema')
                schema_json = self.get_schema(
                    req['data']['issuer-did'],
                    req['data']['schema-name'],
                    req['data']['schema-version'])
                schema = json.loads(schema_json)
                schema_seq_no = schema['seqNo']
                claim_def_json = self.get_claim_def(schema)
            elif self.schema_metadata is not None:
                schema_seq_no = self.schema_metadata['seq_no']
                schema_json = self.schema_metadata['json']
                claim_def_json = self.schema_metadata['claim_def_json']
            else:
                raise ValueError('No schema metadata available')

            find_req = {
                'nonce': str(int(time() * 1000)),
                'name': 'find_req_0',  # configure this?
                'version': '0',  # configure this?
                'requested_attrs': {
                    '{}_uuid'.format(attr): {
                        'schema_seq_no': schema_seq_no,
                        'name': attr
                    } for attr in req['data']['claim-filter']['attr-match']
                },
                'requested_predicates': {
                    # TODO: predicates
                }
            }
            filter_enc = {k: asc2decstr(req['data']['claim-filter']['attr-match'][k])
                for k in req['data']['claim-filter']['attr-match']}
            (claim_uuids, claims_found_json) = await self.get_claims_for_proof_req(json.dumps(find_req), filter_enc)
            assert(len(claim_uuids) == 1)

            if req['type'] == 'claim-request':
                return claims_found_json

            # FIXME: what if there are multiple matching claims to prove? How to encode requested attrs/preds?
            claims_for_proof = json.loads(claims_found_json)
            print("\n\n^^^ SK CLAIMS FOR PROOF {}\n".format(json.dumps(claims_for_proof, indent=4)))
            claim_uuid = claim_uuids.pop()
            requested_claims = {
                'self_attested_attributes': {},
                'requested_attrs': {
                    attr: [claim_uuid, True]
                        for attr in find_req['requested_attrs'] if attr in claims_for_proof['attrs']
                },
                'requested_predicates': {
                    pred: claim_uuid
                        for pred in find_req['requested_predicates']
                }
            }

            print("\n\n^^^ SK REQ_CLAIMS {}\n".format(json.dumps(requested_claims, indent=4)))

            return await self.create_proof(
                find_req, 
                json.loads(schema_json),
                self._master_secret,
                json.loads(claim_def_json),
                requested_claims)

        elif req['type'] == 'claim-request':
            self.__class__._vet_keys({'claim-filter'}, set(req['data'].keys()), hint='data')
            self.__class__._vet_keys({'attr-match'}, set(req['data']['claim-filter'].keys()), hint='claim-filter')

        else:  # token-type
            raise ValueError('Unsupported token - unsupported type field')

    async def process_get_txn(self, req: dict) -> int:
        """
        Takes a request from the service wrapper request to find a transaction on the distributed ledger,
        returns its sequence number or None if there is no match.

        :param req: request on which to operate
        :return: sequence number of transaction, None for no match
        """

        self.__class__._vet_keys({'type', 'data'}, set(req.keys()))

        if req['type'] in ('get-schema', 'get-claim-def'):
            self.__class__._vet_keys({'issuer-did', 'schema-name', 'schema-version'}, set(req['data'].keys()), 'data')

            schema = json.loads(await self.get_schema(
                req['data']['issuer-did'],
                req['data']['schema-name'],
                req['data']['schema-version']))

            if req['type'] == 'get-schema':
                return schema['seqNo']

            # req['type'] == 'get-claim-def'
            claim_def = json.loads(await self.get_claim_def(schema))
            return claim_def['seqNo']

        else:  # token-type
            raise ValueError('Bad token - unsupported type field')

    def __repr__(self) -> str:
        """
        Return representation for current object.

        :return: representation for current object
        """

        return 'ListeningAgent({}, {}, {}, {}, {}, {})'.format(
            repr(self.pool),
            '[SEED]',
            self.wallet_name,
            self.wallet_config,
            self.host,
            self.port)

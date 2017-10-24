from indy import agent, anoncreds, ledger, signus, pool, wallet, IndyError
from indy.error import ErrorCode

import json


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

        :name: name of the pool
        :genesis_txn_path: path to genesis transaction file
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

        :pool: node pool on which agent operates
        :seed: seed to bootstrap agent
        :wallet_name: name of wallet that agent uses
        :wallet_config: wallet configuration json, None for default
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
        self._conn_handles = set()

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

        :did: DID of cryptonym to fetch
        :return: cryptonym json, or empty production if not present
        """

        get_nym_req = await ledger.build_get_nym_request(
            self.did,
            did)
        resp_json = await ledger.submit_request(self.pool.handle, get_nym_req)
        data_json = (json.loads(resp_json))['result']['data']  # it's double-encoded on the ledger
        if data_json is None:
            return json.dumps('{}')
        return data_json

    async def send_nym(self, agent: 'BaseAgent') -> None:  # Trust Anchor
        """
        Method for trust anchor to send input agent's cryptonym (including DID and current verification key) to ledger.

        :agent: agent whose cryptonym to send to ledger
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

        :recv_did: DID of recipient agent
        :path_query_fragment: string to append to host, port (and trailing slash) to form URL to which to POST
        :msg_json: json to POST to recipient service wrapper
        """

        pass  # TODO: implement

    async def send_schema(self, schema_data_json: str) -> str:  # issuer
        """
        Method for issuer to send schema to ledger, then retrieve it as written (and completed through
        the write process to the ledger) and return it.

        :schema_data_json: schema data json with name, version, attribute names;
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

        :issuer_did: DID of schema issuer
        :name: schema name
        :version: schema version string

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

        :schema: schema dict, as retrieved from ledger, on which to base claim definition
        :keys: keys to include as revealed attributes in claim definition (None defaults to all keys)
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

        :schema: schema dict, as retrieved from ledger, acting as base for claim definition
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

        :master_secret: label for master secret; indy-sdk uses label to generate master secret
        """
        await anoncreds.prover_create_master_secret(self.wallet_handle, master_secret)

    async def store_claim_req(
            self,
            schema_issuer_did: str,
            schema_seq_no: int,
            claim_def_json: str,
            master_secret: str) -> str:  # prover
        """
        Method for prover to create a claim request and store it in its wallet.

        :schema_issuer_did: DID of schema issuer
        :schema_seq_no: sequence number of schema on the ledger
        :claim_def_json: claim definition as retrieved from ledger
        :master_secret: prover master secret (label)
        :return: claim request json as stored in wallet
        """
        return await anoncreds.prover_create_and_store_claim_req(
            self.wallet_handle,
            self.did,
            json.dumps({'issuer_did': schema_issuer_did, 'schema_seq_no': schema_seq_no}),
            claim_def_json,
            master_secret);

    async def create_claim(self, claim_req_json: str, claim: dict) -> (str, str):  # issuer
        """
        Method for issuer to create claim out of claim request and dict of key:[value, encoding] entries
        for revealed attributes.

        :claim_req_json: claim request as created by prover
        :claim: claim dict mapping each revealed attribute to its [value, encoding];
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

        :claim_json: json claim as prover created
        """
        await anoncreds.prover_store_claim(self.wallet_handle, claim_json)

    async def create_proof(self, proof_req: dict, schema: dict, master_secret: str, claim_def: dict) -> str:  # prover
        """
        Method for prover to create proof.

        :proof_req: proof request as verifier creates; has entries for proof request's nonce, name, version;
            claim's requested attributes, requested predicates
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
        :schema: schema used in proof, as retrieved from ledger (multiple schemata not supported yet)
        :master_secret: master secret (label)
        :claim_def: claim definition as retrieved from ledger
        :return: proof json
        """

        # TODO: support empty requested-attributes?
        # TODO: support multiple schema? Tricky.

        claims_for_proof_json = await anoncreds.prover_get_claims_for_proof_req(
            self.wallet_handle,
            json.dumps(proof_req))
        claims_for_proof = json.loads(claims_for_proof_json)

        print("\n\n^^^ SK CLAIMS_FOR_PROOF {}\n".format(json.dumps(claims_for_proof, indent=4)))
        requested_claims = {
            'self_attested_attributes': {},
            'requested_attrs': {
                attr: [claims_for_proof['attrs'][attr][0]['claim_uuid'], True]
                    for attr in proof_req['requested_attrs']
            },
            'requested_predicates': {
                pred: claims_for_proof['predicates'][pred][0]['claim_uuid']
                    for pred in proof_req['requested_predicates']
            }
        }
        print("\n\n^^^ SK REQ_CLAIMS {}\n".format(json.dumps(requested_claims, indent=4)))

        return await anoncreds.prover_create_proof(
            self.wallet_handle,
            json.dumps(proof_req),
            json.dumps(requested_claims),
            json.dumps({  # schemas_json
                claim_uuid[0]: schema
                    for claim_uuid in requested_claims['requested_attrs'].values()
            }),
            master_secret,
            json.dumps({  # claim_defs_json
                claim_uuid[0]: claim_def
                    for claim_uuid in requested_claims['requested_attrs'].values()
            }),
            json.dumps({})  # revoc_regs_json
        )

    async def verify_proof(self, proof_req: dict, proof: dict, schema: dict, claim_def: dict) -> bool:  # verifier
        """
        Method for verifier to verify proof.

        :proof_req: proof request as verifier creates (see above)
        :proof: proof as prover creates
        :schema: schema used in proof, as retrieved from ledger (multiple schemata not supported yet)
        :claim_def: claim definition as retrieved from ledger
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

    async def get_claims_for_proof_req(self, proof_req_json: str) -> str:  # prover
        """
        Method for prover to get claims (from wallet) corresponding to proof request

        :proof_req_json: proof request json as verifier creates (see above)
        :return: json with claims for input proof request
        """

        return await anoncreds.prover_get_claims_for_proof_req(self.wallet_handle, proof_req_json)

    async def get_endpoint_attrib(self, did: str) -> str:
        """
        Get endpoint for agent having input DID

        :did: DID for agent whose endpoint to find
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

    def __init__(self, pool: NodePool, seed: str, wallet_name: str, wallet_config: str, host: str, port: int) -> None:
        """
        Initializer for agent. Does not open its wallet, only retains input parameters.

        :pool: node pool on which agent operates
        :seed: seed to bootstrap agent
        :wallet_name: name of wallet that agent uses
        :wallet_config: wallet configuration json, None for default
        :host: agent IP address
        :port: agent port
        """

        super().__init__(pool, seed, wallet_name, wallet_config)
        self._host = host
        self._port = port

    @property
    def host(self):
        return self._host

    @property
    def port(self):
        return self._port

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
    def _vet_keys(must: set, have: set, hint: str = '') -> None:
        if not must.issubset(have):
            raise ValueError('Bad token:{} missing keys {}'.format(' ' + hint, must - have))

    async def process_post(self, req: dict) -> str:
        """
        Takes a request from service wrapper POST and dispatches the applicable agent action.
        Returns (json) response arising from processing.

        :req: request on which to operate
        :return: json response
        """

        self.__class__._vet_keys({'type', 'data'}, set(req.keys()))

        if req['type'] == 'schema-init':
            self.__class__._vet_keys({'schema-name', 'schema-version', 'attr-names'}, set(req['data'].keys()), 'data')
            self.send_schema(json.dumps({k: req['data'][k] for k in req['data'] if k in keys}))

        elif req['type'] == 'claim-def-init':
            self.__class__._vet_keys({'issuer-did', 'schema-name', 'schema-version'}, set(req['data'].keys()), 'data')
            schema = json.loads(await self.get_schema(
                req['data']['issuer-did'],
                req['data']['schema-name'],
                req['data']['schema-version']))

            self.send(claim_def(schema))

        elif req['type'] == 'set-master-secret':
            self.__class__._vet_keys({'label'}, set(req['data'].keys()), 'data')
            self.create_master_secret(req['data']['label'])

        else:  # token-type
            raise ValueError('Unsupported token - unsupported type field')

    async def process_get_txn(self, req: dict) -> int:
        """
        Takes a request from the service wrapper request to find a transaction on the distributed ledger,
        returns its sequence number or None if there is no match.

        :req: request on which to operate
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

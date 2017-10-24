import json

class NodePool:
    '''
    Class for node pool.
    '''

    def __init__(self, name, genesis_txn_path):
        self._name = name
        self._genesis_txn_path = genesis_txn_path
        self._handle = None

    @property
    def name(self):
        return self._name

    @property
    def genesis_txn_path(self):
        return self._genesis_txn_path

    @property
    def handle(self):
        return self._handle

    async def __aenter__(self):
        await pool.create_pool_ledger_config(self.name, json.dumps({'genesis_txn': str(self.genesis_txn_path)}))
        self._handle = await pool.open_pool_ledger(self.name, None)

    async def __aexit__(self, exc_type, exc, traceback): 
        await pool.close_pool_ledger(self.handle)

    def __repr__(self):
        return 'NodePool({}, {})'.format(
            self.name,
            self.genesis_txn_path)


class GCAgent:
    '''
    Class for Government of Canada agent
    '''

    def __init__(self, pool, seed, wallet_name, wallet_config):
        self._pool = pool

        self._seed = seed
        self._did_seed = json.dumps({'seed': seed})

        self._wallet_name = wallet_name
        self._wallet_handle = None
        self._wallet_config = wallet_config
        self._conn_handles = set()

    async def __aenter__(self):
        try:
            await wallet.create_wallet(
                pool_name=self.pool.name,
                name=self.wallet_name,
                xtype=None,
                config=self.wallet_config,
                credentials=None)
        except IndyError as e:
            if e.value.error_code !=ErrorCode.WalletAlreadyExistsError:
                raise
        self._wallet_handle = await wallet.open_wallet(self.wallet_name, self.wallet_config, None)

        (self._did, self._verkey, self._pubkey) = (
            await signus.create_and_store_my_did(self.wallet_handle, self._did_seed))

        return self

    async def __aexit__(self, exc_type, exc, traceback):
        for conn_handle in self._conn_handles:
            await agent.agent_close_connection(conn_handle)
        self._conn_handles.clear()
        await wallet.close_wallet(self.wallet_handle)

    @property
    def pool(self):
        return self._pool

    @property
    def wallet_name(self):
        return self._wallet_name

    @property
    def wallet_handle(self):
        return self._wallet_handle

    @property
    def wallet_config(self):
        return self._wallet_config

    @property
    def did(self):
        return self._did

    @property
    def verkey(self):
        return self._verkey

    @property
    def pubkey(self):
        return self._pubkey

    async def get_nym(self, did):
        get_nym_req = await ledger.build_get_nym_request(
            self.did,
            did)
        resp_json = await ledger.submit_request(self.pool.handle, get_nym_req)
        resp = (json.loads(resp_json))['result']
        return json.dumps(resp)

    async def send_nym(self, agent):  # Trust Anchor
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

    async def connect_to(self, gc_agent_to):
        send_handle = await agent.agent_connect(self.pool.handle, self.wallet_handle, self.did, gc_agent_to.did)
        self._conn_handles.add(send_handle)
        event = await agent.agent_wait_for_event([gc_agent_to.listener_handle])  # type: agent.MessageEvent
        return send_handle, event.connection_handle  # send, recv
        
    async def disconnect_from(self, gc_agent_to):
        conn_handle = gc_agent_to.send_handle
        if handle in self._conn_handles:
            await agent.agent_close_connection(conn_handle)
            self._conn_handles.remove(conn_handle)

    async def send(self, conn_send_handle, message):
        await agent.agent_send(conn_send_handle, message)

    async def send_schema(self, schema_data_json):  # issuer
        req_json = await ledger.build_schema_request(self.did, schema_data_json)
        resp_json = await ledger.sign_and_submit_request(self.pool.handle, self.wallet_handle, self.did, req_json)
        resp = (json.loads(resp_json))['result']
        return await self.get_schema(self.did, resp['identifier'], resp['data']['name'], resp['data']['version'])

    async def get_schema(self, issuer_did, schema_did, name, version):  # issuer, verifier
        req_json = await ledger.build_get_schema_request(
            issuer_did,
            schema_did,
            json.dumps({'name': name, 'version': version}))
        resp_json = await ledger.submit_request(self.pool.handle, req_json)
        resp = json.loads(resp_json)
        resp['result']['data']['keys'] = resp['result']['data'].pop('attr_names')
        return json.dumps(resp['result'])

    async def send_claim_def(self, schema, keys=None):  # issuer
        if keys:
            schema['data']['keys'] = [k for k in keys if k in schema['data']['keys']]
        schema_json = json.dumps(schema)

        claim_def_json = await anoncreds.issuer_create_and_store_claim_def(
            self.wallet_handle,
            self.did,  # NB: claim def issuer need not be schema issuer; use same for both for now
            schema_json,
            'CL',
            False)
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
        return await self.get_claim_def(schema)

    async def get_claim_def(self, schema):  # issuer
        req_json = await ledger.build_get_claim_def_txn(
            self.did,
            schema['seqNo'],
            'CL',
            schema['data']['origin'])
        resp_json = await ledger.submit_request(self.pool.handle, req_json)
        resp = json.loads(resp_json)
        resp['result']['data']['revocation'] = None  # TODO: support revocation
        return json.dumps(resp['result'])

    async def create_master_secret(self, master_secret):  # prover
        await anoncreds.prover_create_master_secret(self.wallet_handle, master_secret)

    async def store_claim_req(self, schema_issuer_did, schema_seq_no, claim_def_json, master_secret):  # prover
        return await anoncreds.prover_create_and_store_claim_req(
            self.wallet_handle,
            self.did,
            json.dumps({'issuer_did': schema_issuer_did, 'schema_seq_no': schema_seq_no}),
            claim_def_json,
            master_secret);

    async def create_claim(self, claim_req_json, claim):  # issuer
        return await anoncreds.issuer_create_claim(
            self.wallet_handle,
            claim_req_json,
            json.dumps(claim),
            -1)

    async def store_claim(self, claim_json):  # prover
        await anoncreds.prover_store_claim(self.wallet_handle, claim_json)

    async def send_proof(self, proof_req, schema, master_secret, claim_def):  # prover
        # TODO: support empty requested-attributes?
        # TODO: support multiple schema? Tricky.
        print('\n\n\nCREATEPROOF {}, {}'.format(type(claim_def), claim_def))
        claims_for_proof_json = await anoncreds.prover_get_claims_for_proof_req(
            self.wallet_handle,
            json.dumps(proof_req))
        claims_for_proof = json.loads(claims_for_proof_json)

        requested_claims = {
            'self_attested_attributes': {},
            'requested_attrs': {
                attr: [claims_for_proof['attrs'][attr][0]['claim_uuid'], True]
                    for attr in proof_req['requested_attrs']},
            'requested_predicates': {}
        }

        proof = json.loads(await anoncreds.prover_create_proof(
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
        ))

        proof_json = json.dumps({'proof': proof})
        req_json = await ledger.build_attrib_request(self.did, self.did, None, proof_json, None)
        resp = json.loads(await ledger.sign_and_submit_request(
            self.pool.handle,
            self.wallet_handle,
            self.did,
            req_json))

        return resp['result']['seqNo']

    async def get_proof_by_seq_no(self, seq_no):
        req_json = await ledger.build_get_txn_request(self.did, seq_no)
        resp_json = await ledger.submit_request(self.pool.handle, req_json)
        # print("\n**** **** RESP_JSON {}".format(json.dumps(json.loads(resp_json), indent=4)))
        raw_json = (json.loads(resp_json))['result']['data']['raw']
        proof_json = (json.loads(raw_json))['proof']
        return json.dumps(proof_json)

    async def verify_proof(self, proof_req, proof, schema, claim_def):  # verifier
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

    async def get_claims_for_proof_req(self, proof_req_json):  # prover
        return await anoncreds.prover_get_claims_for_proof_req(self.wallet_handle, proof_req_json)

    async def get_endpoint_attrib(self, did):
        req_json = await ledger.build_get_attrib_request(
            self.did,
            did,
            'endpoint')
        resp_json = await ledger.submit_request(self.pool.handle, req_json)
        data_json = (json.loads(resp_json))['result']['data']
        endpoint = json.loads(data_json)['endpoint']
        return json.dumps(endpoint)

    def __repr__(self):
        return 'GCAgent({}, {}, {}, {})'.format(
            repr(self.pool),
            '[SEED]',
            self.wallet_name,
            self.wallet_config)


class ListeningAgent(GCAgent):
    '''
    Class for Government of Canada agent that listens and responds to other agents
    '''

    def __init__(self, pool, seed, wallet_name, wallet_config, host, port):
        super().__init__(pool, seed, wallet_name, wallet_config)
        self._host = host
        self._port = port

    async def __aenter__(self):
        await super().__aenter__()
        self._listener_handle = await agent.agent_listen(ha(self.host, self.port))
        await agent.agent_add_identity(self.listener_handle, self.pool.handle, self.wallet_handle, self._did)
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        await agent.agent_close_listener(self.listener_handle)
        await super().__aexit__(exc_type, exc, traceback)

    @property
    def listener_handle(self):
        return self._listener_handle

    @property
    def host(self):
        return self._host

    @property
    def port(self):
        return self._port

    async def send_endpoint_attrib(self):
        raw_json = json.dumps({
            'endpoint': {
                'ha': ha(self.host, self.port),
                'verkey': self.pubkey
            }
        })
        req_json = await ledger.build_attrib_request(self.did, self.did, None, raw_json, None)
        return await ledger.sign_and_submit_request(self.pool.handle, self.wallet_handle, self.did, req_json)

    async def wait_for_message(self, handles):
        germane = handles if isinstance(handles, list) else [handles]
        germane.append(self.listener_handle)
        return (await agent.agent_wait_for_event(germane)).message

    def __repr__(self):
        return 'ListeningAgent({}, {}, {}, {}, {}, {})'.format(
            repr(self.pool),
            '[SEED]',
            self.wallet_name,
            self.wallet_config,
            self.host,
            self.port)

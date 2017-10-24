
    async def process_post(self, form: dict) -> str:
        self.__class__._vet_keys({'type', 'data'}, set(form.keys()))  # all tokens need type and data

        if form['type'] == 'schema-claim-def-send':
            # write schema and claim def to ledger; respond with dict on both
            self.__class__._vet_keys(
                {'schema', 'attr-names'},
                set(form['data'].keys()),
                hint='data')
            self.__class__._vet_keys(
                {'issuer-did', 'name', 'version'},
                set(form['data']['schema'].keys()),
                hint='schema')
            schema_json = self.send_schema(json.dumps({k: form['data'][k] for k in form['data'] if k in keys}))
            schema = json.loads(schema_json)
            claim_def_json = self.send_claim_def(schema)

            # cache schema metadata en passant for future use
            self.schema_metadata = {
                'issuer': form['data']['issuer-did'],
                'name': form['data']['schema-name'],
                'version': form['data']['schema-version'],
                'seq_no': schema['seqNo'],
                'json': schema_json,
                'claim_def_json': claim_def_json}

            return json.dumps({'schema': schema, 'claim-def': json.loads(claim_def_json)})

        elif form['type'] == 'schema-claim-def-lookup':
            # init schema and claim def; respond with dict on both
            self.__class__._vet_keys(
                {'schema', 'attr-names'},
                set(form['data'].keys()),
                hint='data')
            self.__class__._vet_keys(
                {'issuer-did', 'name', 'version'},
                set(form['data']['schema'].keys()),
                hint='schema')
            schema_json = self.send_schema(json.dumps({k: form['data'][k] for k in form['data'] if k in keys}))
            schema = json.loads(schema_json)
            claim_def_json = self.send_claim_def(schema)

            # cache schema metadata en passant for future use
            self.schema_metadata = {
                'issuer': form['data']['issuer-did'],
                'name': form['data']['schema-name'],
                'version': form['data']['schema-version'],
                'seq_no': schema['seqNo'],
                'json': schema_json,
                'claim_def_json': claim_def_json}

            return json.dumps({'schema': schema, 'claim-def': json.loads(claim_def_json)})

        elif form['type'] == 'set-master-secret':
            self.__class__._vet_keys({'label'}, set(form['data'].keys()), hint='data')
            if self.schema_metadata == None:
                raise ValueError('Schema metadata not set')
            await self.create_master_secret(form['data']['label'])
            await self.store_claim_req(
                self.schema_metadata['issuer'],
                self.schema_metadata['seq_no'],
                self.schema_metadata['claim_def_json'])

            return json.dumps({})

        elif form['type'] in ('claim-request', 'proof-request'):
            self.__class__._vet_keys(
                {'claim-filter'},
                set(form['data'].keys()),
                hint='data')
            self.__class__._vet_keys(
                {'attr-match', 'predicate-match'},
                set(form['data']['claim-filter'].keys()),
                hint='claim-filter')
            # TODO: predicates

            resp_proxy_json = self._response_from_proxy(form, 'prover-did')
            if resp_proxy_json != None:
                return resp_proxy_json  # it's proxied

            # it's local, carry on
            schema_json, schema_seq_no, claim_def_json = self._schema_and_claim_def_info(form['data'])
            find_req = {
                'nonce': str(int(time() * 1000)),
                'name': 'find_req_0',  # configure this?
                'version': '0',  # configure this?
                'requested_attrs': {
                    '{}_uuid'.format(attr): {
                        'schema_seq_no': schema_seq_no,
                        'name': attr
                    } for attr in form['data']['claim-filter']['attr-match']
                },
                'requested_predicates': {
                    # TODO: predicates
                }
            }
            filter_enc = {k: asc2decstr(form['data']['claim-filter']['attr-match'][k])
                for k in form['data']['claim-filter']['attr-match']}
            (claim_uuids, claims_found_json) = await self.get_claims_for_proof_req(json.dumps(find_req), filter_enc)
            assert(len(claim_uuids) == 1)
            claims_found = json.loads(claims_found_json)

            if form['type'] == 'claim-request':
                return json.dumps({
                    'proof-req': find_req,
                    'claims': claims_found
                })

            # FIXME: what if there are multiple matching claims to prove? How to encode requested attrs/preds?
            print("\n\n^^^ SK CLAIMS FOR PROOF {}\n".format(json.dumps(claims_found, indent=4)))
            claim_uuid = claim_uuids.pop()
            requested_claims = {
                'self_attested_attributes': {},
                'requested_attrs': {
                    attr: [claim_uuid, True]
                        for attr in find_req['requested_attrs'] if attr in claims_found['attrs']
                },
                'requested_predicates': {
                    pred: claim_uuid
                        for pred in find_req['requested_predicates']
                }
            }

            print("\n\n^^^ SK REQ_CLAIMS {}\n".format(json.dumps(requested_claims, indent=4)))
            proof_json = await self.create_proof(
                find_req,
                json.loads(schema_json),
                self._master_secret,
                json.loads(claim_def_json),
                requested_claims)
            return json.dumps({
                'proof-req': find_req,
                'proof': json.loads(proof_json)
            })

        elif form['type'] == 'verification-request':
            self.__class__._vet_keys({'proof-req', 'proof'}, set(form['data'].keys()), hint='data')

            resp_proxy_json = self._response_from_proxy(form, 'verifier-did')
            if resp_proxy_json != None:
                return resp_proxy_json  # it's proxied

            # it's local, carry on
            schema_json, schema_seq_no, claim_def_json = self._schema_and_claim_def_info(form['data'])
            return await self.verify_proof(
                form['data']['proof-req'],
                form['data']['proof'],
                json.loads(schema_json),
                json.loads(claim_def_json))

        elif form['type'] == 'claim-hello':
            resp_proxy_json = self._response_from_proxy(form, 'prover-did')
            if resp_proxy_json != None:
                return resp_proxy_json  # it's proxied

            # it's local, carry on
            schema_json, schema_seq_no, claim_def_json = self._schema_and_claim_def_info(form['data'])
            if self.claim_req_json is None:  # FIXME: support multiple schema, a claim req per schema
                await self.store_claim_req(
                    json.loads(schema_json)['dest'],
                    schema_seq_no,
                    claim_def_json)

            return self.claim_req_json

        elif form['type'] == 'claim-create':
            self.__class__._vet_keys({'claim-req', 'claim-attrs'}, set(form['data'].keys()), hint='data')

            # it's local, carry on (no use case for proxy claim creation, so far)
            _, rv = await self.create_claim(
                json.dumps(form['data']['claim-req']),
                {k: [form['data']['claim-attrs'][k], asc2decstr(form['data']['claim-attrs'][k])]
                    for k in form['data']['claim-attrs']})
            return rv

        elif form['type'] == 'claim-store':
            self.__class__._vet_keys({'claim-req'}, set(form['data'].keys()), hint='data')

            resp_proxy_json = self._response_from_proxy(form, 'prover-did')
            if resp_proxy_json != None:
                return resp_proxy_json  # it's proxied

            # it's local, carry on
            self.store_claim(json.dumps(form['data']['claim']))
            return json.dumps({})

        else:  # token-type
            raise ValueError('Unsupported token - unsupported type field')


        """ not necessary? get it fresh every time from ledger?
        elif form['type'] == 'claim-def-lookup':  # local only, no use case for proxying
            # init claim def from ledger
            self.__class__._vet_keys(
                {'schema', 'attr-names'},
                set(form['data'].keys()),
                hint='data')
            self.__class__._vet_keys(
                {'issuer-did', 'name', 'version'},
                set(form['data']['schema'].keys()),
                hint='schema')
            schema_json = await self.send_schema(json.dumps({k: form['data'][k] for k in form['data'] if k in keys}))
            schema = json.loads(schema_json)
            claim_def_json = await self.send_claim_def(schema)

            # cache schema metadata en passant for future use
            self.schema_metadata = {
                'issuer': form['data']['issuer-did'],
                'name': form['data']['schema-name'],
                'version': form['data']['schema-version'],
                'seq_no': schema['seqNo'],
                'json': schema_json,
                'claim_def_json': claim_def_json}

            return json.dumps({'schema': schema, 'claim-def': json.loads(claim_def_json)})
        """


    ''' DELETE ME: Issuer does this
    async def send_claim_def(self, schema: dict) -> str:
        """
        Method for claim def author create, store, and to send claim definition to ledger, then retrieve
        it as written (and completed through the write process to the ledger) and return it.

        :param schema: schema dict, as retrieved from ledger, on which to base claim definition
        :return: claim definition json as written to ledger
        """

        schema_json = json.dumps(schema)

        claim_def_json = await anoncreds.issuer_create_and_store_claim_def(
            self.wallet_handle,
            self.did,  # NB: claim def issuer need not be schema issuer, in theory
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
    '''

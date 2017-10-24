        """
        try:
            print("### 1 ###")
            self._handle = await pool.open_pool_ledger(self.name, None)
            print("### 2 ###")
            logger.info('NewPool.open: opened node pool {}'.format(self.name))
        except IndyError as e:
            print("### 3 ### {}".format(e.error_code))
            if e.error_code in (ErrorCode.PoolLedgerTerminated, ErrorCode.PoolLedgerNotCreatedError): 
                print("### 4 ###")
                logger.info('NewPool.open: could not open node pool {}, trying to create it'.format(self.name))
                await pool.create_pool_ledger_config(
                    self.name,
                    json.dumps({'genesis_txn': str(self.genesis_txn_path)}))
                print("### 5 ###")
            else:
                logger.exception(e)
                print("### 6 ###")
                raise e
            print("### 7 ###")
            self._handle = await pool.open_pool_ledger(self.name, None)

        print("### 8 ###")
        logger.debug('NewPool.open: <<<')
        return self
        """

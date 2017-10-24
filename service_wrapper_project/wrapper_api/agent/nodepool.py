from indy import pool, IndyError
from indy.error import ErrorCode

import json
import logging


class NamedPool:
    """
    Base class for indy-sdk node pool.
    """

    def __init__(self, name: str) -> None:
        """
        Initializer for named pool. Retains input parameters.

        :param name: name of the pool
        """

        logger = logging.getLogger(__name__)
        logger.debug('NamedPool.__init__: >>> name: {}'.format(name))
        self._name = name

    @property
    def name(self) -> str:
        """
        Accessor for pool name

        :return: pool name
        """

        return self._name

    async def __aenter__(self) -> 'NamedPool':
        """
        Context manager entry. Opens pool as configured, for closure on context manager exit.
        For use in monolithic call opening, using, and closing the pool. For formalism only.

        :return: current object
        """

        logger = logging.getLogger(__name__)
        logger.debug('NamedPool.__aenter__: >>>')

        rv = await self.open()

        logger.debug('NamedPool.__aenter__: <<<')
        return rv

    async def open(self) -> 'NamedPool':
        """
        Explicit entry. Opens pool as configured, for later closure via close().
        For use when keeping pool open across multiple calls. For formalism only.

        :return: current object
        """

        logger = logging.getLogger(__name__)
        logger.debug('NamedPool.open: >>>')

        logger.debug('NamedPool.open: <<<')
        return self
        
    async def __aexit__(self, exc_type, exc, traceback) -> None: 
        """
        Context manager exit. Closes pool. For use in monolithic call opening,
        using, and closing the pool. For formalism only.

        :param exc_type:
        :param exc:
        :param traceback:
        """

        logger = logging.getLogger(__name__)
        logger.debug('NamedPool.__aexit__: >>>')

        await self.close()

        logger.debug('NamedPool.__aexit__: <<<')

    async def close(self) -> None:
        """
        Explicit exit. Closes pool. For use when keeping pool open across multiple calls. For formalism only.
        """

        logger = logging.getLogger(__name__)
        logger.debug('NamedPool.close: >>>')

        logger.debug('NamedPool.close: <<<')

    def __repr__(self) -> str:
        """
        Return representation for current object.

        :return: representation for current object
        """

        return 'NamedPool({})'.format(self.name)


class LivePool(NamedPool):
    """
    Class encapsulating node pool that indy-sdk counts as already created.
    """

    def __init__(self, name: str, handle: int) -> None:
        """
        Initializer for node pool. Does not open the pool, only retains input parameters.

        :param name: name of the pool
        :param handle: handle to the pool within indy-sdk
        """

        logger = logging.getLogger(__name__)
        logger.debug('LivePool.__init__: >>> name: {}, handle: {}'.format(name, handle))

        super().__init__(name)
        self._handle = handle

        logger.debug('LivePool.__init__: <<<')

    @property
    def handle(self) -> int:
        """
        Accessor for indy-sdk pool handle

        :return: indy-sdk pool handle
        """

        return self._handle

    def __repr__(self) -> str:
        """
        Return representation for current object.

        :return: representation for current object
        """

        return 'LivePool({}, {})'.format(self.name, self.handle)


class NewPool(NamedPool):
    """
    Class encapsulating indy-sdk node pool with creation.
    """

    def __init__(self, name: str, genesis_txn_path: str) -> None:
        """
        Initializer for node pool. Does not open the pool, only retains input parameters.

        :param name: name of the pool
        :param genesis_txn_path: path to genesis transaction file
        """

        logger = logging.getLogger(__name__)
        logger.debug('NewPool.__init__: >>> name: {}, genesis_txn_path: {}'.format(name, genesis_txn_path))

        super().__init__(name)
        self._genesis_txn_path = genesis_txn_path
        self._handle = None

        logger.debug('NewPool.__init__: <<<')

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

    async def __aenter__(self) -> 'NewPool':
        """
        Context manager entry. Opens pool as configured, for closure on context manager exit.
        For use in monolithic call opening, using, and closing the pool.

        :return: current object
        """

        logger = logging.getLogger(__name__)
        logger.debug('NewPool.__aenter__: >>>')

        rv = await self.open()

        logger.debug('NewPool.__aenter__: <<<')
        return rv

    async def open(self) -> 'NewPool':
        """
        Explicit entry. Opens pool as configured, for later closure via close().
        For use when keeping pool open across multiple calls.

        :return: current object
        """

        logger = logging.getLogger(__name__)
        logger.debug('NewPool.open: >>>')

        await pool.create_pool_ledger_config(self.name, json.dumps({'genesis_txn': str(self.genesis_txn_path)}))
        self._handle = await pool.open_pool_ledger(self.name, None)

        logger.debug('NewPool.open: <<<')
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None: 
        """
        Context manager exit. Closes pool and deletes its configuration to ensure clean next entry.
        For use in monolithic call opening, using, and closing the pool.

        :param exc_type:
        :param exc:
        :param traceback:
        """

        logger = logging.getLogger(__name__)
        logger.debug('NewPool.__aexit__: >>>')

        await self.close()

        logger.debug('NewPool.__aexit__: <<<')

    async def close(self) -> None:
        """
        Explicit exit. Closes pool and deletes its configuration to ensure clean next entry.
        For use when keeping pool open across multiple calls.
        """

        logger = logging.getLogger(__name__)
        logger.debug('NewPool.close: >>>')

        await pool.close_pool_ledger(self.handle)
        await pool.delete_pool_ledger_config(self.name)

        logger.debug('NewPool.close: <<<')

    def __repr__(self) -> str:
        """
        Return representation for current object.

        :return: representation for current object
        """

        return 'NewPool({}, {})'.format(self.name, self.genesis_txn_path)

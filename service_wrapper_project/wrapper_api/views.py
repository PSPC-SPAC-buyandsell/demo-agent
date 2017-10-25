from django.shortcuts import render
from django.contrib.auth.models import User
from django.core.cache import cache
from rest_framework.response import Response
from rest_framework.parsers import JSONParser
from rest_framework.views import APIView
from wrapper_api.serializers import UserSerializer
from wrapper_api.config import get_config
from time import time as epoch

import logging
logger = logging.getLogger(__name__)

import asyncio


"""
async def hello():
    return 'hello world {}'.format(epoch())
"""

class IndyGet(APIView):
    """
    API endpoint accepting GET requests for via current agent for ledger transaction by sequence number
    """

    def get(self, req, seq_no=None):
        logger.info("+++ seq_no {}".format(seq_no))
        if cache.get('x') == None:
            cache.set('x', 1)
        rv = 0
        if seq_no is None:
            rv = cache.get('x')
        else:
            cache.incr('x')
            rv = seq_no
        return Response({'hello': rv})


class IndyPost(APIView):
    """
    API endpoint accepting JSON forms via POST for agent processing
    """

    parser_classes = (JSONParser,)

    def post(self, req, format=None):
        logger.warn("req-data: {}, {}".format(type(req.data), req.data))

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        # greeting = loop.run_until_complete(asyncio.gather(hello()))[0]
        return Response({'greeting': greeting, 'recv_data': req.data, 'config': get_config()})



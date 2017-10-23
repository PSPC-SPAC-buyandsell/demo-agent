from django.shortcuts import render
from django.contrib.auth.models import User
# from rest_framework import viewsets
# from django.http import HttpResponse
from rest_framework.response import Response
from rest_framework.parsers import JSONParser
from rest_framework.views import APIView
# from django.views import View
from wrapper_api.serializers import UserSerializer
from wrapper_api.config import config
from time import time as epoch

import logging
logger = logging.getLogger(__name__)

import asyncio
async def hello():
    return 'hello world {}'.format(epoch())

class IndyPostView(APIView):
    """
    API endpoint accepting JSON
    """
    parser_classes = (JSONParser,)

    def get(self, req):
        return Response(str(int(epoch())))

    def post(self, req, format=None):
        logger.warn("req-data: {}, {}".format(type(req.data), req.data))

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        greeting = loop.run_until_complete(asyncio.gather(hello()))[0]
        return Response({'greeting': greeting, 'recv_data': req.data, 'config': config})

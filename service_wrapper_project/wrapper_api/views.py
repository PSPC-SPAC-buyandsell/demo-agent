from django.shortcuts import render
from django.contrib.auth.models import User
from django.core.cache import cache
from rest_framework.response import Response
from rest_framework.parsers import JSONParser
from rest_framework.views import APIView
from time import time as epoch
from wrapper_api.eventloop import do
from wrapper_api.apps import PATH_PREFIX_SLASH
from indy.error import IndyError

import asyncio
import json
import logging


logger = logging.getLogger(__name__)


class ServiceWrapper(APIView):
    """
    API endpoint accepting requests for current agent
    """

    def post(self, req):
        """
        Wiring for agent POST processing
        """

        ag = cache.get('agent')
        assert ag is not None
        try:
            form = json.loads(req.body.decode("utf-8"))
            rv_json = do(ag.process_post(form))
            return Response(json.loads(rv_json))  # FIXME: this only loads it to dump it: it's already json
        except Exception as e:
            return Response(
                status=500,
                data={
                    'error-code': e.error_code if isinstance(e, IndyError) else 500,
                    'message': str(e)
                })
        finally:
            cache.set('agent', ag)  #  in case agent state changes over process_post

    def get(self, req, seq_no=None):
        """
        Wiring for agent helper (GET) methods
        """

        ag = cache.get('agent')
        assert ag is not None
        try:
            if req.path.startswith('/{}txn'.format(PATH_PREFIX_SLASH)):
                rv_json = do(ag.process_get_txn(int(seq_no)))
                return Response(json.loads(rv_json))  # FIXME: this only loads it to dump it: it's already json
            elif req.path.startswith('/{}did'.format(PATH_PREFIX_SLASH)):
                rv_json = do(ag.process_get_did())
                return Response(json.loads(rv_json))  # FIXME: this only loads it to dump it: it's already json
            else:
                raise ValueError(
                    'Agent service wrapper API does not respond on GET to URL on path {}'.format(req.path))
        except Exception as e:
            return Response(
                status=500,
                data={
                    'error-code': e.error_code if isinstance(e, IndyError) else 500,
                    'message': str(e)
                })

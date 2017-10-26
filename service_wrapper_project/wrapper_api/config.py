from configparser import ConfigParser
from django.conf import settings
from django.core.cache import cache
from os.path import abspath, dirname, isfile, join as pjoin
from os import environ

_inis = [
    pjoin(dirname(abspath(__file__)), 'config', 'config.ini'),
    pjoin(dirname(abspath(__file__)), 'config', 'agent-profile', environ.get('AGENT_PROFILE') + '.ini')
]

def init_config():
    global _inis
    if cache.get('config') == None:
        if all(isfile(ini) for ini in _inis):
            parser = ConfigParser()
            for ini in _inis: 
                parser.read(ini)
            cache.set(
                'config',
                {s: dict(parser[s].items()) for s in parser.sections()})
        else:
            raise FileNotFoundError('Configuration file(s) mission; check {}'.format(_inis))
    return cache.get('config')

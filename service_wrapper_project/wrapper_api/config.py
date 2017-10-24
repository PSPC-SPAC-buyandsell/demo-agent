from configparser import ConfigParser
from django.conf import settings
from os.path import abspath, dirname, isfile, join as pjoin
from os import environ

_inis = [
    pjoin(dirname(abspath(__file__)), 'config', 'config.ini'),
    pjoin(dirname(abspath(__file__)), 'config', 'agent-profile', environ.get('AGENT_PROFILE') + '.ini')
]

_config = None

def _set_config():
    global _config
    if not _config:
        if all(isfile(ini) for ini in _inis):
            parser = ConfigParser()
            parser.read(_inis[0])
            parser.read(_inis[1])
            _config = {s: dict(parser[s].items()) for s in parser.sections()}
        else:
            raise FileNotFoundError('Configuration files not both present at {}'.format(_inis))

def get_config():
    if not _config:
        _set_config()
    return _config

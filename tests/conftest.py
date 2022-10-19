from pathlib import Path
import logging
import asyncio
import sys

import pytest
import pytest_asyncio


BASEDIR = Path(__file__).resolve().parents[1] / 'src'
sys.path.insert(0, str(BASEDIR))

from cybereason import Cybereason

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@pytest.fixture(scope='session')
def config():
    import os, inspect
    config = dict()

    for param in inspect.signature(Cybereason).parameters:
        try:
            config[param] = os.environ[f'cybereason_{param}'.upper()]
        except KeyError as e:
            pass

    if not all(x in config for x in ('server', 'username', 'password')):
        raise RuntimeError(
            'You need to set at least CYBEREASON_SERVER, '
            'CYBEREASON USERNAME, and CYBEREASON PASSWORD '
            'environment variables to run the tests.'
        )

    return config


@pytest.fixture(scope='session')
def log():
    return logger


@pytest.fixture(scope='session')
def event_loop():
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope='session')
async def client(config):
    async with Cybereason(**config) as client:
        yield client


class NotEnoughData(RuntimeError):
    def __init__(self, msg=None):
        default = 'Not enough data in the server to run this test.'
        super().__init__(msg or default)

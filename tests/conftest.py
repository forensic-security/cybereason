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
    required = list()

    for name, param in inspect.signature(Cybereason)._parameters.items():
        if param.default is param.empty:
            required.append(name)
        try:
            config[name] = os.environ[f'cybereason_{name}'.upper()]
        except KeyError as e:
            pass

    if not all(x in config for x in required):
        r = ', '.join(f"'CYBEREASON_{p.upper()}'" for p in required)
        raise RuntimeError(
            'You need to set at least the following environment variables '
            f'to run the tests: {r}'
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

from collections.abc import AsyncIterator
from pathlib import Path
import logging
import inspect
import asyncio
import sys

import pytest
import pytest_asyncio

HERE = Path(__file__).resolve().parent
BASEDIR = HERE.parent / 'src'
SCHEMAS = HERE / 'schemas'
sys.path.insert(0, str(BASEDIR))

from cybereason import Cybereason

logging.basicConfig(level=logging.INFO)
logging.getLogger('httpx').setLevel(logging.WARNING)

logger = logging.getLogger(__name__)


@pytest.fixture(scope='session')
def log():
    return logger


@pytest.fixture(scope='session')
def event_loop():
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope='session')
def validate():
    from jsonschema import validate as val
    from yaml import safe_load

    def tighten_schema(schema):
        if schema.get('type') == 'array':
            if 'items' in schema:
                schema['items'] = tighten_schema(schema['items'])
        elif schema.get('type') == 'object':
            # set `additionalProperties` and `required` if not set
            if 'properties' in schema:
                schema.setdefault('additionalProperties', False)
                schema.setdefault('required', list(schema['properties'].keys()))
                schema['properties'] = {
                    k: tighten_schema(v) for k, v in schema['properties'].items()
                }

        return schema

    def _validate(data, schema_name):
        if isinstance(data, list) and not data:
            raise NotEnoughData
        frame = inspect.stack()[1]
        file = Path(frame.filename).with_suffix('.yaml').name.removeprefix('test_')
        common = SCHEMAS.joinpath('_common.yaml').read_text()
        specific = SCHEMAS.joinpath(file).read_text()
        schemata = safe_load('\n'.join((common, specific)))
        schemata = {k: tighten_schema(v) for k, v in schemata.items()}

        return val(instance=data, schema=schemata[schema_name])

    return _validate


@pytest_asyncio.fixture(scope='session')
async def client():
    async with Cybereason.from_env() as client:
        yield client


class aenumerate(AsyncIterator):
    def __init__(self, aiterable, start=0):
        self._aiterable = aiterable
        self._i = start - 1

    def __aiter__(self):
        self._aiter = self._aiterable.__aiter__()
        return self

    async def __anext__(self):
        value = await self._aiter.__anext__()
        self._i += 1
        return self._i, value


class NotEnoughData(RuntimeError):
    def __init__(self, msg=None):
        default = 'Not enough data in the server to run this test.'
        super().__init__(msg or default)


class MismatchingDataModel(ValueError):
    def __init__(self, msg=None):
        default = 'The data model does not match the expected one.'
        super().__init__(msg or default)

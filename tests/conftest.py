from pathlib import Path
import asyncio
import sys

BASEDIR = Path(__file__).resolve().parents[1] / 'src'
sys.path.insert(0, str(BASEDIR))

from cybereason import Cybereason


def get_config_from_env():
    import os, inspect

    config = dict()

    for param in inspect.signature(Cybereason).parameters:
        try:
            config[param] = os.environ[f'cybereason_{param}']
        except KeyError:
            pass

    return config


def run(fn):
    async def _run(fn):
        async with Cybereason(**get_config_from_env()) as client:
            return await fn(client)

    return asyncio.run(_run(fn))

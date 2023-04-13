from typing import TYPE_CHECKING
from collections.abc import Iterable, Iterator
from csv import DictReader
from pathlib import Path
from io import BytesIO
from copy import copy
import re


if TYPE_CHECKING:
    from typing import Any, AsyncIterator, Dict, List
    from httpx import Response


BOOL = {'true': True, 'false': False}
NONE = {'null': None}


class Unset:
    def __bool__(self):
        return False

    def __contains__(self, o):
        return False


unset = Unset()


def parse_csv(
    text:       str,
    *, boolean: 'List[str]' = [],
    optional:   'List[str]' = [],
) -> 'Iterator[Dict[str, Any]]':
    csv = text.splitlines()

    for item in DictReader(csv):
        for key in boolean:
            item[key] = BOOL[item[key]]  # type: ignore
        for key in optional:
            item[key] = NONE.get(item[key], item[key])  # type: ignore
        yield item


def to_list(obj: 'Any') -> 'List[Any]':
    if isinstance(obj, Iterator):
        return list(obj)
    elif isinstance(obj, Iterable):
        if not isinstance(obj, (str, bytes)):
            return obj
    return [obj]


# TODO: complete, but beware of SensorsMixin.download_file:
#   the lack of the header is used as an indicator of the
#   "file not found" error
def get_filename(response: 'Response') -> str:
    '''Extract filename from an HTTP response.
    '''
    try:
        header = response.headers['content-disposition']
        return re.search(r'\"(.*?)(?=\"|\Z)', header).group(1)  # type: ignore
    except (KeyError, AttributeError):
        raise FileNotFoundError from None


async def extract_logfiles(fileobj, logname, rotated: bool = True) -> 'AsyncIterator[bytes]':
    '''Extracts latest logfile and rotated gzipped logfiles from a
    zipped logs archive.
    '''
    from zipfile import ZipFile
    from gzip import GzipFile

    logname, *_ = logname.split('.')

    with ZipFile(fileobj) as archive:
        yield archive.open(f'{logname}.log').read()

        if rotated:
            for file in sorted(archive.filelist, key=lambda f: f.filename):
                if file.filename[-3:] == '.gz' and logname in file.filename:
                    archived = BytesIO(archive.open(file.filename).read())
                    with GzipFile(fileobj=archived, mode='rb') as f:
                        yield f.read()


def find_next_version(path: Path) -> Path:
    '''Returns an available versioned path for a file or a directory.

        foo.tar.gz -> foo.0.tar.gz
        foo.0.tar.gz -> foo.1.tar.gz
    '''
    path = Path(path)
    if not path.exists():
        return path

    parent = path.parent
    suffix = ''.join(path.suffixes)
    stem = path.name.split('.')[0]

    value = -1
    for item in parent.glob(f'*{suffix}'):
        if item.name.startswith(stem):
            name = item.name.split('.')
            if name[1:-1] and name[1].isdigit():
                value = max(value, int(name[1]))
    value += 1
    return parent / f'{stem}.{value}{suffix}'


def get_config_from_env(cls):
    import inspect
    import os

    config = dict()
    required = list()

    for name, param in inspect.signature(cls)._parameters.items():
        if param.default is param.empty:
            required.append(name)
        try:
            config[name] = os.environ[f'{cls.__name__}_{name}'.upper()]
        except KeyError:
            pass

    if not all(x in config for x in required):
        r = ', '.join(f"'{cls.__name__}_{p}'".upper() for p in required)
        raise RuntimeError(
            'You need to set at least the following environment variables '
            f'to run the tests: {r}'
        )

    if 'timeout' in config:
        try:
            config['timeout'] = float(config['timeout'])
        except ValueError:
            config['timeout'] = None

    return config


def _get_simple_values(totalValues: int, values: 'List[Any]') -> 'Any':
    if totalValues == 1:
        return values[0]
    elif totalValues > 1:
        return values
    elif totalValues == 0:  # TODO: return empty list?
        return None


def parse_query_response(item):
    output = copy(item)

    simple = output.pop('simpleValues', {})
    output.update({
        k: _get_simple_values(**v) for k, v in simple.items()
        # XXX: don't overwrite duplicated values (such as `hasMalops`)
        #   since they lose their type when packed into simpleValues
        if k not in output
    })

    elements = output.pop('elementValues', {})
    output.update({
        k: [parse_query_response(i) for i in v['elementValues']]
        for k, v in elements.items() if k not in output
    })

    return output

from typing import Any, Dict, List
from collections.abc import Iterable, Iterator
from csv import DictReader
from pathlib import Path

BOOL = {'true': True, 'false': False}
NONE = {'null': None}


def parse_csv(
    text:       str,
    *, boolean: List[str]=[],
    optional:   List[str]=[],
) -> Iterator[Dict[str, Any]]:
    csv = text.splitlines()

    for item in DictReader(csv):
        for key in boolean:
            item[key] = BOOL[item[key]]
        for key in optional:
            item[key] = NONE.get(item[key], item[key])
        yield item


def to_list(obj) -> List[Any]:
    if isinstance(obj, Iterator):
        return list(obj)
    elif isinstance(obj, Iterable):
        if not isinstance(obj, (str, bytes)):
            return obj
    return [obj]


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
        name = item.name
        if name.startswith(stem):
            name = name.split('.')
            if name[1:-1] and name[1].isdigit():
                value = max(value, int(name[1]))
    value +=1
    return parent / f'{stem}.{value}{suffix}'

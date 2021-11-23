from typing import Any, Dict, List
from collections.abc import Iterable, Iterator
from csv import DictReader

BOOL = {'true': True, 'false': False}
NONE = {'null': None}


def parse_csv(
    text:       str,
    *, boolean: List[str]=[],
    optional:   List[str]=[],
) -> Dict[str, Any]:
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

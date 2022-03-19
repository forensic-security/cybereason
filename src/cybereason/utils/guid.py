from textwrap import wrap
from ctypes import c_uint32, c_uint64

_BASE64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'


def _a2b(binary: str) -> str:
    return _BASE64URL[int(binary, 2)]


def _b2a(char: str) -> str:
    return f'{_BASE64URL.index(char):06b}'


def _compl2(binary: str) -> int:
    if binary[0] == '1':
        return int(binary, 2) - (1 << len(binary))
    return int(binary, 2)


def guid_to_string(guid: str) -> str:
    i1, i2 = map(int, guid.split('.'))
    y = f'{c_uint32(i1).value:032b}{c_uint64(i2).value:064b}'
    return ''.join(_a2b(x) for x in wrap(y, 6))


def string_to_guid(string: str) -> str:
    b = ''.join(_b2a(c) for c in string)
    return f'{_compl2(b[:32])}.{_compl2(b[32:])}'


__all__ = ['guid_to_string', 'string_to_guid']

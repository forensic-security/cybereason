# patch to cope with a bug in /rest/file-search/fetch-direct that
#   returns two {'file-encoding': 'chunked'} headers
import re
from typing import Type

from h11._abnf import field_name, field_value
from h11._util import bytesify, LocalProtocolError, validate
from h11._headers import Headers

_content_length_re = re.compile(br'[0-9]+')
_field_name_re = re.compile(field_name.encode('ascii'))
_field_value_re = re.compile(field_value.encode('ascii'))


def normalize_and_validate(headers, _parsed: bool=False):
    new_headers = []
    seen_content_length = None
    saw_transfer_encoding = False
    for name, value in headers:
        # For headers coming out of the parser, we can safely skip some steps,
        # because it always returns bytes and has already run these regexes
        # over the data:
        if not _parsed:
            name = bytesify(name)
            value = bytesify(value)
            validate(_field_name_re, name, 'Illegal header name {!r}', name)
            validate(_field_value_re, value, 'Illegal header value {!r}', value)
        if not isinstance(name, bytes):
            raise TypeError(f'Header name must be bytes, not {type(name)}')
        if not isinstance(name, bytes):
            raise TypeError(f'Header value must be bytes, not {type(name)}')

        raw_name = name
        name = name.lower()
        if name == b'content-length':
            lengths = {length.strip() for length in value.split(b',')}
            if len(lengths) != 1:
                raise LocalProtocolError('conflicting Content-Length headers')
            value = lengths.pop()
            validate(_content_length_re, value, 'bad Content-Length')
            if seen_content_length is None:
                seen_content_length = value
                new_headers.append((raw_name, name, value))
            elif seen_content_length != value:
                raise LocalProtocolError('conflicting Content-Length headers')
        elif name == b'transfer-encoding':
            # "A server that receives a request message with a transfer coding
            # it does not understand SHOULD respond with 501 (Not
            # Implemented)."
            # https://tools.ietf.org/html/rfc7230#section-3.3.1
            if saw_transfer_encoding:
                if saw_transfer_encoding == value:
                    continue
                raise LocalProtocolError(
                    'multiple Transfer-Encoding headers', error_status_hint=501
                )
            # "All transfer-coding names are case-insensitive"
            # -- https://tools.ietf.org/html/rfc7230#section-4
            value = value.lower()
            if value != b'chunked':
                raise LocalProtocolError(
                    'Only Transfer-Encoding: chunked is supported',
                    error_status_hint=501,
                )
            saw_transfer_encoding = value
            new_headers.append((raw_name, name, value))
        else:
            new_headers.append((raw_name, name, value))
    return Headers(new_headers)

from typing import TYPE_CHECKING, Optional
import logging

if TYPE_CHECKING:
    from typing import Union, AsyncIterator, Callable, Awaitable, TypeVar

    F = TypeVar('F', bound=Callable[..., Union[AsyncIterator, Awaitable]])


log = logging.getLogger(__name__)


class CybereasonException(Exception):
    ...


class ClientError(CybereasonException):
    ...


class UnauthorizedRequest(CybereasonException):
    def __init__(self, url: str, role: Optional[str] = None) -> None:
        if role:
            msg = f'You must have the {role} role'
        else:
            msg = 'You don\'t have the role required'

        super().__init__(f'{msg} to make a request to {url}.')
        self.url = url
        self.status_code = 403


class AuthenticationError(CybereasonException):
    ...


class ServerError(CybereasonException):
    ...


class TooManyRequests(ClientError):
    ...


class ResourceNotFoundError(CybereasonException):
    ...


class ResourceExistsError(CybereasonException):
    ...


class FilterSyntaxError(CybereasonException, SyntaxError):
    ...


class AccessDenied(CybereasonException):
    ...


class ServiceDisabled(ServerError):
    ...


class ConnectionError(CybereasonException):
    ...


# response errors
class ResponseError(CybereasonException):
    ...


class Failure(ResponseError):
    ...


class PartialSuccess(ResponseError):
    ...


class NoServersConfigured(ResponseError):
    ...


class QueryLimitCrossed(ResponseError):
    ...


class TimeoutError(ResponseError):
    ...


RESPONSE_ERRORS = {
    'FAILURE':               Failure,
    'PARTIAL_SUCCESS':       PartialSuccess,
    'NO_SERVERS_CONFIGURED': NoServersConfigured,
    'QUERY_LIMIT_CROSSED':   QueryLimitCrossed,
    'TIMEOUT_ERROR':         TimeoutError,
}


def get_response_error(status):
    exc = RESPONSE_ERRORS.get(status)
    if exc is None:
        log.warning('Unknown response status: %r', status)
        return ResponseError
    return exc


def _add_to_doc(doc: Optional[str], text: str) -> str:
    from textwrap import dedent

    doc = dedent((doc or '').strip())
    return f'{doc}\n\n{dedent(text)}'


def authz(role) -> 'Callable[[F], F]':
    '''Adds context to authorization errors.
    '''
    from inspect import isasyncgenfunction
    from functools import wraps

    def inner(func):
        doc = f'''\
            Raises:
                UnauthorizedRequest: if the user does not have the {role}
                    role assigned.
        '''
        func.__doc__ = _add_to_doc(func.__doc__, doc)

        if isasyncgenfunction(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                try:
                    async for item in func(*args, **kwargs):
                        yield item
                except UnauthorizedRequest as e:
                    raise UnauthorizedRequest(e.url, role) from None
        else:
            @wraps(func)
            async def wrapper(*args, **kwargs):
                try:
                    return await func(*args, **kwargs)
                except UnauthorizedRequest as e:
                    raise UnauthorizedRequest(e.url, role) from None

        return wrapper
    return inner


# TODO: exception is always status == 404?
def min_version(major: int, minor: int, release: int = 0) -> 'Callable[[F], F]':
    from inspect import isasyncgenfunction
    from functools import wraps

    def inner(func):
        version = f'{major}.{minor}.{release or "x"}'
        func.__doc__ = _add_to_doc(func.__doc__, f'.. versionadded:: {version}')

        if isasyncgenfunction(func):
            @wraps(func)
            async def wrapper(self, *args, **kwargs):
                try:
                    async for item in func(self, *args, **kwargs):
                        yield item
                except Exception:
                    if self.version < (major, minor, release):
                        raise NotImplementedError(
                            f'This feature is only available since version {version}'
                        ) from None
                    raise
        else:
            @wraps(func)
            async def wrapper(self, *args, **kwargs):
                try:
                    return await func(self, *args, **kwargs)
                except Exception:
                    if self.version < (major, minor, release):
                        raise NotImplementedError(
                            f'This feature is only available since version {version}'
                        ) from None
                    raise
        return wrapper
    return inner

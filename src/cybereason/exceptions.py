from typing import Optional
from functools import wraps
from textwrap import dedent


class CybereasonException(Exception):
    pass


class UnauthorizedRequest(CybereasonException):
    def __init__(self, url: str, role: Optional[str] = None):
        if role:
            msg = f'You must have the {role} role'
        else:
            msg = 'You don\'t have the role required'

        super().__init__(f'{msg} to make a request to {url}.')
        self.url = url
        self.status_code = 403


class AuthenticationError(CybereasonException):
    pass


class ServerError(CybereasonException):
    pass


class ClientError(CybereasonException):
    pass


class ResourceNotFoundError(CybereasonException):
    pass


class ResourceExistsError(CybereasonException):
    pass


class FilterSyntaxError(CybereasonException, SyntaxError):
    pass


def _add_to_doc(doc, text):
    doc = dedent((doc or '').strip())
    return f'{doc}\n\n{dedent(text)}'


def authz(role):
    '''Adds context to authorization errors.
    '''
    def inner(func):
        doc = f'''\
            Raises:
                UnauthorizedRequest: if the user does not have the {role}
                    role assigned.            
        '''
        func.__doc__ = _add_to_doc(func.__doc__, doc)

        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except UnauthorizedRequest as e:
                raise UnauthorizedRequest(e.url, role) from None
        return wrapper
    return inner


def min_version(major, minor, release=0):
    def inner(func):
        version = f'{major}.{minor}.{release or "x"}'
        func.__doc__ = _add_to_doc(func.__doc__, f'.. versionadded:: {version}')

        @wraps(func)
        async def wrapper(self, *args, **kwargs):
            try:
                return await func(self, *args, **kwargs)
            # TODO: status == 404?
            except Exception as e:
                if self.version < (major, minor, release):
                    raise NotImplementedError(
                        f'This feature is only available since version {version}'
                    ) from None
        return wrapper
    return inner

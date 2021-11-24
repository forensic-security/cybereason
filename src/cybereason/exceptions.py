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


def authz(role):
    '''Adds context to authorization errors.
    '''
    def inner(func):
        func.__doc__ = dedent(f'''\
        {(func.__doc__ or '').rstrip()}

        Raises:
            UnauthorizedRequest: if the user does not have the {role}
                role assigned.
        ''')

        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except UnauthorizedRequest as e:
                raise UnauthorizedRequest(e.url, role) from None
        return wrapper
    return inner

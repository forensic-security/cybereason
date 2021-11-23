from typing import Optional
from functools import wraps

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


class FilterSyntaxError(CybereasonException, SyntaxError):
    pass


def authz(role):
    def inner(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except UnauthorizedRequest as e:
                raise UnauthorizedRequest(e.url, role) from None
        return wrapper
    return inner

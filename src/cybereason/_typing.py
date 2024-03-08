from typing import TYPE_CHECKING


class Unset:
    __slots__ = ()

    def __bool__(self):
        return False

    def __contains__(self, o):
        return False


unset = Unset()


if TYPE_CHECKING:
    from typing import Any, AsyncIterator, Dict, Literal, NewType, Optional, Protocol, Union, Tuple, TypeVar
    from pathlib import Path
    from os import PathLike
    from httpx import AsyncClient, URL

    T = TypeVar('T')
    Unforced = Union[Unset, T]
    Query = Optional[Dict[str, Any]]
    UrlPath = Union[URL, str]

    MalopId = NewType('MalopId', str)
    SensorId = NewType('SensorId', str)

    class CybereasonProtocol(Protocol):
        proxy:        Optional[str]
        totp_code:    Optional[str]

        @property
        def session(self) -> AsyncClient: ...

        def check_resp(self, resp: Dict[str, Any]) -> Any: ...
        async def get(self, path: UrlPath, query: Query=None, raw: bool=False) -> Any: ...
        async def post(self, path: UrlPath, data: Any, files: Query=None, raw_data: bool=False) -> Any: ...
        async def put(self, path: UrlPath, data: Any) -> Any: ...
        async def delete(self, path: UrlPath, query: Query=None) -> Any: ...
        async def download(self, path: UrlPath, folder: PathLike, *, query: Query=None, extract: bool=False) -> Path: ...
        async def aiter_pages(self, path: UrlPath, data: Any, key: str, *, page_size: int=0, check_resp: bool=False, sort: Literal['ASC', 'DESC']='ASC') -> AsyncIterator[Dict[str, Any]]:
            if False: yield
        async def aiter_items(self, path: UrlPath, data: Any, key: str, *, page_size: int=0, check_resp: bool=False, pagination: bool=False) -> AsyncIterator[Dict[str, Any]]:
            if False: yield
        async def post_sage(self, path: UrlPath, data: Any) -> Any: ...
else:
    class CybereasonProtocol:
        ...

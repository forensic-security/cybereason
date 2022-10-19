from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, AsyncIterator, Dict, Literal, NewType, Optional, Protocol, Union
    from pathlib import Path
    from os import PathLike
    from httpx import AsyncClient, URL

    Query = Optional[Dict[str, Any]]
    UrlPath = Union[URL, str]

    MalopId = NewType('MalopId', str)
    SensorId = NewType('SensorId', str)

    class CybereasonProtocol(Protocol):
        proxy:     Optional[str]
        totp_code: Optional[str]

        @property
        def session(self) -> AsyncClient: ...

        def get(self, path: UrlPath, query: Query=None, raw: bool=False) -> Any: ...
        def post(self, path: UrlPath, data: Any, files: Query=None, raw_data: bool=False) -> Any: ...
        def delete(self, path: UrlPath, query: Query=None) -> Any: ...
        def download(self, path: UrlPath, folder: PathLike, query: Query=None, extract: bool=False) -> Path: ...
        def aiter_pages(self, path: UrlPath, data: Any, key: str, page_size: int=0, sort: Literal['ASC', 'DESC']='ASC') -> AsyncIterator[Dict[str, Any]]: ...
        def post_sage(self, path: UrlPath, data: Any) -> Any: ...
else:
    class CybereasonProtocol:
        ...

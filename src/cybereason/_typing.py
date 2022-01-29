from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, AsyncIterator, Dict, Literal, Optional, Protocol, Union
    from pathlib import Path
    from httpx import AsyncClient, URL

    Query = Optional[Dict[str, Any]]
    UrlPath = Union[URL, str]


    class CybereasonProtocol(Protocol):
        proxy:     Optional[str]
        totp_code: Optional[str]

        @property
        def session(self) -> AsyncClient: ...

        def get(self, UrlPath, query: Query=None, raw: bool=False) -> Any: ...
        def post(self, UrlPath, data: Any, files: Query=None) -> Any: ...
        def delete(self, UrlPath, query: Query=None) -> Any: ...
        def download(self, UrlPath, folder: Path, query: Query=None, extract: bool=False) -> Path: ...
        def aiter_pages(self, UrlPath, data: Any, key: str, page_size: int=0, sort: Literal['ASC', 'DESC']='ASC') -> AsyncIterator[Dict[str, Any]]: ...

else:
    class CybereasonProtocol:
        ...

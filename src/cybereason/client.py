from typing import Any, Optional, TYPE_CHECKING, cast
from json.decoder import JSONDecodeError
from functools import cached_property
from pathlib import Path
from os import PathLike
from io import BytesIO
import logging

# monkey-patch to allow multiple {'file-encoding': 'chunked'} headers
import httpx
from ._patch import normalize_and_validate
httpx._transports.default.httpcore._async.http11.h11._headers.normalize_and_validate = normalize_and_validate
from httpx import AsyncClient, HTTPStatusError, ConnectError

from .exceptions import (
    AccessDenied, AuthenticationError, ResourceNotFoundError,
    ServiceDisabled, UnauthorizedRequest,
    CybereasonException, ServerError, ClientError,
    authz, min_version,
)
from .utils import find_next_version, get_filename, to_list
from .custom_rules import CustomRulesMixin
from .incident_reponse import IncidentResponseMixin
from .malops import MalopsMixin
from .sensors import SensorsMixin
from .system import SystemMixin
from .threat_intel import ThreatIntelligenceMixin

if TYPE_CHECKING:
    from typing import AsyncIterator, Callable, Dict, List, Literal, Tuple, Union
    from io import BufferedIOBase
    from tarfile import TarFile
    from zipfile import ZipFile
    from os import PathLike
    from ._typing import Query, UrlPath, URL

DEFAULT_TIMEOUT = 30.0
DEFAULT_PAGE_SIZE = 50

log = logging.getLogger(__name__)


class Cybereason(
    CustomRulesMixin,
    IncidentResponseMixin,
    MalopsMixin,
    SensorsMixin,
    SystemMixin,
    ThreatIntelligenceMixin,
):
    def __init__(
        self,
        server:    str,
        username:  str,
        password:  str,
        proxy:     Optional[str] = None,
        totp_code: Optional[str] = None,
        timeout:   float = DEFAULT_TIMEOUT,
    ):
        self.server = server.split('.')[0]
        self.username = username
        self.password = password
        self.proxy = proxy
        self.totp_code = totp_code
        self.timeout = timeout

    @cached_property
    def session(self) -> AsyncClient:
        from . import __version__

        base_url = f'https://{self.server}.cybereason.net'
        headers  = {
            'content-type': 'application/json',
            'user-agent': f'python-cybereason/{".".join(map(str, __version__))}',
        }

        if self.proxy and self.proxy.startswith('socks'):
            # https://github.com/encode/httpx/discussions/2305
            # TODO: go back to socksio when ^ it's resolved
            # see: commit f439393
            try:
                from httpx_socks import AsyncProxyTransport
            except ImportError as e:
                msg = 'Install SOCKS proxy support using `pip install cybereason[socks]`.'
                raise ImportError(msg) from None

            return AsyncClient(
                base_url=base_url,
                headers=headers,
                transport=AsyncProxyTransport.from_url(self.proxy),
                timeout=self.timeout,
            )

        else:
            return AsyncClient(
                base_url=base_url,
                headers=headers,
                proxies=self.proxy,
                timeout=self.timeout,
            )

    @cached_property
    def session_sage(self) -> AsyncClient:
        return AsyncClient(
            base_url=f'https://sage.cybereason.com/rest',
            headers={'content-type': 'application/json'},
            cookies=self.session.cookies,
            timeout=self.timeout,
            verify=False,
        )

    async def login(self) -> None:
        headers = {'content-type': 'application/x-www-form-urlencoded'}
        options = {'headers': headers, 'follow_redirects': True}

        auth = {'username': self.username, 'password': self.password}
        log.debug('Logging %r in on %r', self.username, self.server)

        try:
            resp = await self.session.post('login.html', data=auth, **options)  # type: ignore
        except ConnectError as e:
            raise ConnectionError(e) from None

        if 'error' in str(resp.url):
            await self.session.aclose()
            raise AuthenticationError('Invalid credentials')

        if 'Two factor authentication' in resp.text:
            if not self.totp_code:
                await self.session.aclose()
                raise AuthenticationError('TOTP code (2FA) is required')

            totp = {'totpCode': self.totp_code, 'submit': 'Login'}
            resp = await self.session.post('', data=totp, **options)  # type: ignore

            if 'error' in str(resp.url):
                await self.session.aclose()
                raise AuthenticationError('Invalid TOTP code')

        self.session.base_url = cast('URL', f'{self.session.base_url}/rest')

    async def logout(self) -> None:
        try:
            await self.get(self.session.base_url.copy_with(path='/logout'))
        except AuthenticationError:
            pass

    async def __aenter__(self) -> 'Cybereason':
        await self.login()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback) -> None:
        await self.aclose()
        if exc_type:
            raise exc_type(*to_list(exc_value))

    async def aclose(self) -> None:
        if 'session' in self.__dict__:
            await self.logout()
            await self.session.aclose()
        if 'session_sage' in self.__dict__:
            await self.session_sage.aclose()

    async def gather_limit(num, *tasks):
        '''Limits concurrency.

        Args:
            num: max of simultaneous tasks.
        '''
        import asyncio

        semaphore = asyncio.Semaphore(num)

        async def run_task(task):
            async with semaphore:
                return await task

        return await asyncio.gather(*(run_task(task) for task in tasks))

    async def _request(
        self,
        method:   str,
        path:     'UrlPath',
        data:     Any = None,
        query:    'Query' = None,
        files:    'Query' = None,
        raw:      bool = False,
        raw_data: bool = False,
    ) -> Any:
        if raw_data:
            kwargs = dict(data=data, params=query, files=files)
        else:
            kwargs = dict(json=data, params=query, files=files)

        resp = await self.session.request(method, path, **kwargs)

        try:
            resp.raise_for_status()
        except HTTPStatusError as e:
            if e.response.status_code == 403:
                raise UnauthorizedRequest(str(e.request.url)) from None
            elif e.response.status_code == 400:
                raise ClientError(e.response.text) from None
            elif e.response.status_code == 412:
                raise AccessDenied(e.response.text) from None
            elif e.response.status_code == 500:
                raise ServerError(e.response.text) from None
            elif e.response.status_code == 302:
                raise AuthenticationError from None
            raise

        if raw:
            return resp.content
        else:
            try:
                return resp.json()
            except JSONDecodeError:
                return resp.content.decode()

    async def get(
        self,
        path:  'UrlPath',
        query: 'Query' = None,
        raw:   bool = False,
    ) -> Any:
        return await self._request('GET', path, query=query, raw=raw)

    async def post(
        self,
        path:     'UrlPath',
        data:     Any,
        files:    'Query' = None,
        raw_data: bool = False,
    ) -> Any:
        return await self._request('POST', path, data=data, files=files, raw_data=raw_data)

    async def put(self, path: 'UrlPath', data: Any) -> Any:
        return await self._request('PUT', path, data=data)

    async def delete(
        self,
        path:  'UrlPath',
        query: 'Query' = None,
    ) -> Any:
        return await self._request('DELETE', path, query=query)

    async def raw_download(
        self,
        path:  'UrlPath',
        query: 'Query' = None,
    ) -> 'Tuple[str, BufferedIOBase]':

        buffer = BytesIO()
        async with self.session.stream('GET', path, params=query) as resp:
            resp.raise_for_status()

            filename = get_filename(resp)

            async for chunk in resp.aiter_bytes():
                # filter out keep-alive chunks
                if chunk:
                    buffer.write(chunk)

        buffer.seek(0)
        return filename, buffer

    async def download(
        self,
        path:     'UrlPath',
        folder:   'PathLike',
        *, query: 'Query' = None,
        extract:  bool = False,
    ) -> Path:
        filename, buffer = await self.raw_download(path, query=query)
        unknown = False
        folder = Path(folder)
        folder.mkdir(exist_ok=True, parents=True)

        if extract:
            openfile: 'Callable[[Any], Union[TarFile, ZipFile]]'

            subfolder, ext = filename.rsplit('.', 1)
            if ext == 'zip':
                import zipfile
                openfile = lambda b: zipfile.ZipFile(b, mode='r')
            elif ext == 'gz':
                import tarfile
                openfile = lambda b: tarfile.open(fileobj=b, mode='r:gz')
            else:
                unknown = True
                log.warning('Unknown compression method: %s', filename)

            if not unknown:
                destpath = folder / subfolder
                archive = openfile(buffer)
                archive.extractall(path=destpath)
                log.info('%s extracted into %s', filename, destpath)

        if not extract or unknown:
            destpath = folder / filename

            with open(folder / filename, 'wb') as f:
                f.write(buffer.read())

            log.info('%s saved as %s', filename, destpath)

        return destpath.resolve()

    async def aiter_pages(
        self,
        path:          'UrlPath',
        data:          Any,
        key:           str,
        page_size:     int = DEFAULT_PAGE_SIZE,
        sort:          'Literal["ASC", "DESC"]' = 'ASC',
    ) -> 'AsyncIterator[Dict[str, Any]]':
        data = {**data, 'limit': page_size, 'offset': 0, 'sortDirection': sort}

        while True:
            resp = await self.post(path, data)
            # XXX: not all results have the same schema
            items = resp[key] if key in resp else resp['data'][key]

            for item in items:
                yield item

            # XXX: ditto
            if 'hasMoreResults' in resp:
                if not resp['hasMoreResults']:
                    break
            elif not resp['data']['hasMoreResults']:
                break

            data['offset'] += 1  # XXX: page number

    async def post_sage(self, path, data):
        resp = await self.session_sage.post(path, json=data)
        resp.raise_for_status()
        return resp.json()

# region ISOLATION RULES
    async def get_isolation_rules(self) -> 'List[Dict[str, Any]]':
        '''Retrieve a list of isolation rules.
        '''
        return await self.get('settings/isolation-rule')

    async def get_isolation_rule(self, id) -> 'Dict[str, Any]':
        rules = await self.get_isolation_rules()
        try:
            return [r for r in rules if r['ruleId'] == id][0]
        except IndexError:
            raise ResourceNotFoundError(id) from None

    async def create_isolation_rule(
        self,
        direction: str,
        blocking:  bool,
        ip:        str,  # TODO: validate
        port:      Optional[int] = None,
    ) -> 'Dict[str, Any]':
        '''
        Args:
            direction: The direction of the allowed communication.
                {'ALL', 'OUTGOING', 'INCOMING'}
            blocking: States whether communication with the given IP or
                port is allowed. If ``True`` communication is blocked.
            ip: The IP address of the machine to which the rule applies.
            port: The port by which Cybereason communicates with an
                isolated machine, according to the rule.
        '''
        rule = {
            'ruleId':          None,
            'port':            port or '',
            'ipAddressString': ip,
            'blocking':        blocking,
            'direction':       direction,
        }
        return await self.post('settings/isolation-rule', rule)

    async def update_isolation_rule(
        self,
        id:           str,
        *, direction: Optional[str] = None,
        blocking:     Optional[bool] = None,
        ip:           Optional[str] = None,
        port:         Optional[int] = None,
    ) -> 'Dict[str, Any]':
        '''
        Args:
            id: rule ID.
            port: ``0`` means any port.
        '''
        rule = await self.get_isolation_rule(id)
        if direction is not None:
            rule['direction'] = direction
        if blocking is not None:
            rule['blocking'] = blocking
        if ip is not None:
            rule['ipAddressString'] = ip or ''
        if port is not None:
            rule['port'] = port

        return await self.put('settings/isolation-rule', rule)

    async def delete_isolation_rule(self, id: str) -> None:
        '''Deletes an isolation exception rule.
        '''
        rule = await self.get_isolation_rule(id)
        await self.post('settings/isolation-rule/delete', rule)
# endregion

    @cached_property
    def features_map(self) -> 'Dict[str, Dict[str, Any]]':
        import asyncio
        async def func():
            return await self.get('translate/features/all/')
        return asyncio.run(func())

    async def get_user_audit_logs(self, rotated: bool = True) -> 'AsyncIterator[Dict]':
        '''The User Audit log (aka Actions log) displays all user
        activity on the platform.
        '''
        from .utils import extract_logfiles
        from .parse import cefparse

        _, archive = await self.raw_download('monitor/global/userAuditLog')
        async for content in extract_logfiles(archive, 'userAuditSyslog', rotated):
            # yield latest logs first
            for line in content.splitlines()[::-1]:
                yield cefparse(line.decode())

    # TODO: https://nest.cybereason.com/documentation/api-documentation/all-versions/how-build-queries
    async def query(self, data: 'Dict[str, Any]') -> 'Dict[str, Any]':
        # default since version 20.1.381
        data.setdefault('perGroupLimit', 100)
        if data['perGroupLimit'] > 1000:
            data['perGroupLimit'] = 1000

        # log.debug('Running query %s', data)
        resp = await self.post('visualsearch/query/simple', data)
        if resp['status'] == 'FAILURE':
            raise CybereasonException(resp['message'])
        return resp['data']

    # TODO: https://nest.cybereason.com/documentation/product-documentation/221/machine-timeline
    async def get_process_timeline(self, guid: str, minutes: int):
        '''
        Provides additional context for a process by displaying details
        about sensor activity before and after the selected event,
        within a certain time frame.

        Args:
            minutes: time range in minutes before and after the event.
        '''
        query = {'guid': guid, 'timeRangeInMinutes': minutes}
        return await self.get('process-timeline/v1', query)

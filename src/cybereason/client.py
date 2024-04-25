from typing import TYPE_CHECKING, cast
from json.decoder import JSONDecodeError
from functools import cached_property
from pathlib import Path
from io import BytesIO
import logging
import asyncio

from httpx import AsyncClient, HTTPStatusError, ConnectError, Timeout

from .exceptions import (
    AccessDenied, AuthenticationError, UnauthorizedRequest,
    ServerError, ClientError, CybereasonException, TooManyRequests,
    get_response_error,
)
from .utils import get_filename, to_list, get_config_from_env, parse_query_response
from .rules import CustomRulesMixin, IsolationRulesMixin
from .incident_response import IncidentResponseMixin
from .malops import MalopsMixin
from .sensors import SensorsMixin
from .system import SystemMixin
from .threat_intel import ThreatIntelligenceMixin

if TYPE_CHECKING:
    from typing import Any, AsyncIterator, Callable, Dict, Literal, Optional, Tuple, Union
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
    IsolationRulesMixin,
    IncidentResponseMixin,
    MalopsMixin,
    SensorsMixin,
    SystemMixin,
    ThreatIntelligenceMixin,
):
    def __init__(
        self,
        tenant:       str,
        username:     str,
        password:     str,
        proxy:        'Optional[str]' = None,
        totp_code:    'Optional[str]' = None,
        timeout:      'Union[float, Timeout]' = DEFAULT_TIMEOUT,
        new_password: 'Optional[str]' = None,
    ):
        self.tenant       = tenant.split('.')[0]
        self.username     = username
        self.password     = password
        self.proxy        = proxy
        self.totp_code    = totp_code
        self.timeout      = timeout
        self.new_password = new_password

    @cached_property
    def session(self) -> AsyncClient:
        from . import __version__

        base_url = f'https://{self.tenant}.cybereason.net'
        headers  = {
            'content-type': 'application/json',
            'user-agent': f'python-cybereason/{".".join(map(str, __version__))}',
        }

        if self.proxy and self.proxy.startswith('socks'):
            # https://github.com/encode/httpx/discussions/2305
            # TODO: go back to socksio when ^ is resolved
            # see: commit f439393
            try:
                from httpx_socks import AsyncProxyTransport
            except ImportError:
                msg = 'Install SOCKS proxy support using `pip install cybereason[socks]`.'
                raise ImportError(msg) from None

            return AsyncClient(
                base_url=base_url,
                headers=headers,
                transport=AsyncProxyTransport.from_url(self.proxy),
                timeout=self.timeout,
                http2=True,
            )

        else:
            return AsyncClient(
                base_url=base_url,
                headers=headers,
                proxies=self.proxy,
                timeout=self.timeout,
                http2=True,
            )

    @cached_property
    def session_sage(self) -> AsyncClient:
        return AsyncClient(
            base_url='https://sage.cybereason.com/rest',
            headers={'content-type': 'application/json'},
            cookies=self.session.cookies,
            timeout=self.timeout,
            verify=False,
        )

    async def login(self) -> None:
        headers = {'content-type': 'application/x-www-form-urlencoded'}
        options = {'headers': headers, 'follow_redirects': True}

        auth = {'username': self.username, 'password': self.password}
        log.debug('Logging %r in on %r', self.username, self.tenant)

        try:
            resp = await self.session.post('login.html', data=auth, **options)  # type: ignore
        except ConnectError as e:
            raise ConnectionError(e) from None

        if 'error' in str(resp.url):
            await self.session.aclose()
            raise AuthenticationError('Invalid credentials')
        elif 'reset' in str(resp.url):
            if not self.new_password:
                await self.session.aclose()
                raise AuthenticationError('Expired password')
            else:
                log.warning('Renewing expired password.')
                data = {
                    'oldPassword':        self.password,
                    'newPassword':        self.new_password,
                    'confirmNewPassword': self.new_password,
                    'submit':             'Login',
                }
                await self.session.post('?originalurl=/current?', data=data, **options)  # type: ignore
                self.password = self.new_password

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

    @classmethod
    def from_env(cls) -> 'Cybereason':
        '''Retrieves class parameters from environment variables.
        '''
        config = get_config_from_env(cls)
        return cls(**config)

    async def aclose(self) -> None:
        if 'session' in self.__dict__:
            await self.logout()
            await self.session.aclose()
        if 'session_sage' in self.__dict__:
            await self.session_sage.aclose()

    @staticmethod
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

    def check_resp(self, resp):
        if 'status' in resp:
            if resp['status'] == 'SUCCESS':
                return resp['data']
            else:
                exc = get_response_error(resp['status'])
                raise exc(resp.get('message'))
        elif 'outcome' in resp:
            if resp['outcome'] == 'success':
                return resp['data']
            else:
                # TODO: same model?
                exc = get_response_error(resp['outcome'].upper())
                raise exc(resp['outcome'])
        else:
            raise CybereasonException(resp)

    async def _request(
        self,
        method:   str,
        path:     'UrlPath',
        data:     'Any' = None,
        query:    'Query' = None,
        files:    'Query' = None,
        raw:      bool = False,
        raw_data: bool = False,
        retried:  bool = False,
    ) -> 'Any':
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
            elif e.response.status_code == 429:
                # throttling
                if retried is False:
                    WAIT = 60

                    log.warning('Too many requests. Waiting %i seconds...', WAIT)
                    await asyncio.sleep(WAIT)

                    if 'json' in kwargs:
                        kwargs['data'] = kwargs.pop('json')
                    kwargs['query'] = kwargs.pop('params')
                    return await self._request(
                        method, path, **kwargs, raw=raw, raw_data=raw_data, retried=True
                    )
                else:
                    raise TooManyRequests(e.response.text) from None
            else:
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
    ) -> 'Any':
        return await self._request('GET', path, query=query, raw=raw)

    async def post(
        self,
        path:     'UrlPath',
        data:     'Any',
        files:    'Query' = None,
        raw_data: bool = False,
    ) -> 'Any':
        return await self._request('POST', path, data=data, files=files, raw_data=raw_data)

    async def put(self, path: 'UrlPath', data: 'Any') -> 'Any':
        return await self._request('PUT', path, data=data)

    async def delete(
        self,
        path:  'UrlPath',
        query: 'Query' = None,
    ) -> 'Any':
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
        folder = Path(folder)
        folder.mkdir(exist_ok=True, parents=True)

        if extract and filename.endswith(('.zip', '.gz')):
            openfile: 'Callable[[Any], Union[TarFile, ZipFile]]'
            subfolder, ext = filename.rsplit('.', 1)
            if ext == 'zip':
                import zipfile
                openfile = lambda b: zipfile.ZipFile(b, mode='r')
            else:  # gz
                import tarfile
                openfile = lambda b: tarfile.open(fileobj=b, mode='r:gz')

            destpath = folder / subfolder
            archive = openfile(buffer)
            archive.extractall(path=destpath)
            log.info('%s extracted into %s', filename, destpath)

        else:
            if extract:
                log.warning('Unknown compression method: %s', filename)

            destpath = folder / filename
            destpath.write_bytes(buffer.read())
            log.info('%s saved as %s', filename, destpath)

        return destpath.resolve()

    async def aiter_pages(
        self,
        path:         'UrlPath',
        data:         'Dict[str, Any]',
        key:          str,
        *, page_size: int = DEFAULT_PAGE_SIZE,
        check_resp:   bool = False,
        sort:         'Literal["ASC", "DESC"]' = 'ASC',
    ) -> 'AsyncIterator[Dict[str, Any]]':
        '''
        Args:
            check_resp: ``True`` if the response returns either a
                {status, data} or a {outcome, data} schema.
        '''
        data = {**data, 'limit': page_size, 'offset': 0}
        data.setdefault('sortDirection', sort)

        while True:
            resp = await self.post(path, data)
            if check_resp is True:
                resp = self.check_resp(resp)

            for item in resp[key]:
                yield item

            if not resp['hasMoreResults']:
                break

            data['offset'] += 1  # page number

    # some endpoints use a different pagination schema than `aiter_pages()``
    async def aiter_items(
        self,
        path:           'UrlPath',
        data:           'Dict[str, Any]',
        key:            str,
        *, page_size:   int = DEFAULT_PAGE_SIZE,
        check_resp:     bool = False,
        pagination:     bool = False,
    ) -> 'AsyncIterator[Dict[str, Any]]':
        '''
        Args:
            check_resp: ``True`` if the response returns either a
                {status, data} or a {outcome, data} schema.
            pagination: ``True`` if ``size`` and ``page`` go inside a
                ``pagination`` object.
        '''
        if pagination:
            data = {**data, 'pagination': {'size': page_size}}
        else:
            data = {**data, 'size': page_size}

        page = 0

        while True:
            if pagination:
                data['pagination']['page'] = page
            else:
                data['page'] = page

            resp = await self.post(path, data)
            if check_resp is True:
                resp = self.check_resp(resp)

            for item in resp[key]:
                yield item

            if len(resp[key]) < page_size:
                break

            page += 1

    async def post_sage(self, path, data):
        resp = await self.session_sage.post(path, json=data)
        resp.raise_for_status()
        return resp.json()

    @property
    async def features_map(self) -> 'Dict[str, Dict[str, Any]]':
        if not hasattr(self, '__features_map'):
            self.__features_map = await self.get('translate/features/all/')
        return self.__features_map

    async def get_user_audit_logs(self, rotated: bool = True) -> 'AsyncIterator[Dict[str, Any]]':
        '''The User Audit log (aka Actions log) displays all user
        activity on the platform.
        '''
        from .utils import extract_logfiles
        from .parse import cefparse

        _, archive = await self.raw_download('monitor/global/userAuditLog')
        async for content in extract_logfiles(archive, 'userAuditSyslog', rotated):
            # yield latest logs first
            for line in content.splitlines()[::-1]:
                if line is not None:
                    yield cefparse(line.decode())  # type: ignore

    # https://nest.cybereason.com/documentation/api-documentation/all-versions/how-build-queries
    async def query(self, query: 'Dict[str, Any]', parsed: bool = True) -> 'Dict[str, Any]':
        # default since version 20.1.381
        query.setdefault('perGroupLimit', 100)
        if query['perGroupLimit'] > 1000:
            query['perGroupLimit'] = 1000

        # log.debug('Running query %s', query)
        resp = await self.post('visualsearch/query/simple', query)
        data = self.check_resp(resp)

        if parsed is True:
            return parse_query_response(data)
        else:
            return data

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

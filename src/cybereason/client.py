from typing import Any, Optional, Dict, List, Tuple, Any, AsyncIterator, TYPE_CHECKING, cast
from json.decoder import JSONDecodeError
from io import BytesIO, BufferedIOBase
from functools import cached_property
from datetime import datetime, timedelta
from pathlib import Path
from os import PathLike
import logging

# monkey-patch to allow multiple {'file-encoding': 'chunked'} headers
import httpx
from ._patch import normalize_and_validate
httpx._transports.default.httpcore._async.http11.h11._headers.normalize_and_validate = normalize_and_validate
from httpx import AsyncClient, HTTPStatusError, ConnectError

from .exceptions import (
    AccessDenied, AuthenticationError, ResourceNotFoundError,
    ServiceDisabled, UnauthorizedRequest,
    ServerError, ClientError,
    authz, min_version,
)
from .utils import parse_csv, find_next_version, get_filename
from .sensors import SensorsMixin
from .system import SystemMixin
from .threats import ThreatIntelligenceMixin

if TYPE_CHECKING:
    from typing import Callable, Literal, Union
    from tarfile import TarFile
    from zipfile import ZipFile
    from ._typing import Query, UrlPath, URL

DEFAULT_TIMEOUT = 10.0
DEFAULT_PAGE_SIZE = 20

log = logging.getLogger(__name__)


class Cybereason(SystemMixin, SensorsMixin, ThreatIntelligenceMixin):
    def __init__(
        self,
        organization: str,
        username:     str,
        password:     str,
        proxy:        Optional[str] = None,
        totp_code:    Optional[str] = None,
        timeout:      float = DEFAULT_TIMEOUT,
    ):
        self.organization = organization
        self.username = username
        self.password = password
        self.proxy = proxy
        self.totp_code = totp_code
        self.timeout = timeout

    @cached_property
    def session(self) -> AsyncClient:
        return AsyncClient(
            base_url=f'https://{self.organization}.cybereason.net',
            headers={'content-type': 'application/json'},
            proxies=self.proxy,
            timeout=self.timeout,
        )

    async def login(self) -> None:
        headers = {'content-type': 'application/x-www-form-urlencoded'}
        options = {'headers': headers, 'follow_redirects': True}

        auth = {'username': self.username, 'password': self.password}
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
            raise exc_type(exc_value)

    async def aclose(self) -> None:
        if hasattr(self, 'session'):
            await self.logout()
            await self.session.aclose()

    async def _request(
        self,
        method: str,
        path:   'UrlPath',
        data:   Any = None,
        query:  'Query' = None,
        files:  'Query' = None,
        raw:    bool = False,
    ) -> Any:
        resp = await self.session.request(
            method, path, json=data, params=query, files=files,
        )

        try:
            resp.raise_for_status()
        except HTTPStatusError as e:
            if e.response.status_code == 403:
                raise UnauthorizedRequest(str(e.request.url)) from None
            elif e.response.status_code == 400:
                raise ClientError
            elif e.response.status_code == 412:
                raise AccessDenied(e.response.text) from None
            elif e.response.status_code == 500:
                raise ServerError
            elif e.response.status_code == 302:
                raise AuthenticationError from None
            raise

        try:
            return resp.json()
        except JSONDecodeError:
            if raw:
                return resp.content
            else:
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
        path:  'UrlPath',
        data:  Any,
        files: 'Query' = None,
    ) -> Any:
        return await self._request('POST', path, data=data, files=files)

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
    ) -> Tuple[str, BufferedIOBase]:

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
        folder:   Path,
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

        return destpath

    async def aiter_pages(
        self,
        path:      'UrlPath',
        data:      Any,
        key:       str,
        page_size: int = DEFAULT_PAGE_SIZE,
        sort:      'Literal["ASC", "DESC"]' = 'ASC',
    ) -> AsyncIterator[Dict[str, Any]]:
        data = {**data, 'limit': page_size, 'offset': 0, 'sortDirection': sort}

        while True:
            resp = await self.post(path, data)

            for item in resp[key]:
                yield item

            if not resp['hasMoreResults']:
                break

            data['offset'] += 1  # XXX: page number

# region MALOPS
    async def get_malops(self, days_ago: int=7) -> Any:
        '''Retrieve all Malops of all types (default: during the last week).
        '''
        # TODO: allow to specify end date
        now = datetime.utcnow()
        ago = now - timedelta(days=days_ago)
        data = {
            'startTime': int(ago.timestamp() * 1000),
            'endTime': int(now.timestamp() * 1000),
        }
        return await self.post('detection/inbox', data)

    async def get_active_malops(self):
        '''Get all Malops currently active.
        '''
        return await self.post('crimes/unified', None)  # TODO

    @min_version(20, 1, 43)
    async def get_malops_labels(
        self,
        malops_ids: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        '''Returns a list of all Malop labels.

        Args:
            malops_ids: You can add specific Malop GUID identifiers.
        '''
        return await self.post('detection/labels', malops_ids or [])
# endregion

# region CUSTOM DETECTION RULES
    async def get_active_custom_rules(self) -> List[Dict[str, Any]]:
        '''Retrieve a list of all active custom detection rules.
        '''
        resp = await self.get('customRules/decisionFeature/live')
        # TODO: resp['limitExceed']: bool ?
        return resp['rules']
# endregion

# region REPUTATIONS
    async def get_reputations(
        self,
        reputation: Optional[str] = None,
    ) -> AsyncIterator[Dict[str, Any]]:
        '''Returns a list of custom reputations for files, IP addresses,
        and domain names.

        Args:
            reputation: 'blacklist' or 'whitelist'.
        '''
        # TODO: could be reputation filtered in the query?
        csv = await self.get('classification/download')

        for item in parse_csv(
            csv,
            boolean=['prevent execution', 'remove'],
            optional=['comment'],
        ):
            if reputation:
                if item['reputation'] == reputation:
                    yield item
            else:
                yield item

    async def get_ip_reputations(self):
        return await self.post('download_v1/ip_reputation', {})
# endregion

# region ISOLATION RULES
    async def get_isolation_rules(self) -> List[Dict[str, Any]]:
        '''Retrieve a list of isolation rules.
        '''
        return await self.get('settings/isolation-rule')

    async def get_isolation_rule(self, id) -> Dict[str, Any]:
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
    ) -> Dict[str, Any]:
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
            'ruleId': None,
            'port': port or '',
            'ipAddressString': ip,
            'blocking': blocking,
            'direction': direction,
        }
        return await self.post('settings/isolation-rule', rule)

    async def update_isolation_rule(
        self,
        id:           str,
        *, direction: Optional[str] = None,
        blocking:     Optional[bool] = None,
        ip:           Optional[str] = None,
        port:         Optional[int] = None,
    ) -> Dict[str, Any]:
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

# region INCIDENT RESPONSE
    @min_version(21, 1, 81)
    @authz('Responder L2')
    async def get_irtools_packages(self):
        '''Retrieves a list of previously uploaded packages from your
        environment.
        '''
        return await self.get('irtools/packages')

    @min_version(21, 1, 81)
    @authz('Responder L2')
    async def upload_irtools_package(
        self,
        name:        str,
        filepath:    PathLike,
        description: str,
        run_command: Optional[str] = None,
        output_dir:  Optional[str] = None,
        platform:    Optional['Literal["x86", "x64"]'] = None,
    ) -> None:
        '''Enables you to upload a package for a third-party IR tool to
        your Cybereason platform or upgrade a previously uploaded package,
        and then deploy that package to selected machines.

        The maximum file size for a tool package file is 100 MB.

        Args:
            name: The name for the package. You must use a unique name.
            info: The full file name for the package file.
            description: A description for the tool.
            run_command: An appropriate command for the tool when it runs.
            output_dir: The folder to which to send the output from the
                tool's execution.
            platform: OS bitness: either ``x64`` or ``x86``.
        '''
        data = {
            'pacakgeName': name,
            'packageOSInfoList': {'osTypeGroup': 'WINDOWS_TYPES'},
            'packageContentType': 'FILE',
            'posixPermissions': 'EXECUTE',
            'description': description,
        }

        if platform:
            try:
                _platform = dict(x86='ARCH_X86', x64='ARCH_AMD64')[platform]
            except KeyError:
                raise ValueError("Platform must be 'x86' or 'x64'") from None
            data['packageOSInfoList']['platform'] = _platform

        if run_command or output_dir:
            data['packageRunConfiguration'] = {}
            if run_command:
                data['packageRunConfiguration']['runCommand'] = run_command
            if output_dir:
                data['packageRunConfiguration']['outputDir'] = output_dir

        try:
            package_info = 'file', open(filepath, 'rb'), 'application/octet-stream'
        except FileNotFoundError:
            raise ResourceNotFoundError(filepath) from None
        files = {'packageInfo': package_info}

        try:
            await self.post('irtools/upload', data=data, files=files)
        except ServiceDisabled:
            raise ServiceDisabled('Packages delivery service is disabled') from None

    async def get_credentials(self):
        '''Retrieves credentials for a predefined GCP bucket of your
        environment that you can use to access the tool results output.
        '''
        # TODO
        resp = await self.get('irtools/credentials')
# endregion

from typing import Any, Optional, Dict, List, Tuple, Any, TYPE_CHECKING, cast
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
    CybereasonException, ServerError, ClientError,
    authz, min_version,
)
from .utils import find_next_version, get_filename
from .custom_rules import CustomRulesMixin
from .sensors import SensorsMixin
from .system import SystemMixin
from .threats import ThreatIntelligenceMixin

if TYPE_CHECKING:
    from typing import AsyncIterator, Callable, Literal, Union
    from tarfile import TarFile
    from zipfile import ZipFile
    from ._typing import Query, UrlPath, URL

DEFAULT_TIMEOUT = 30.0
DEFAULT_PAGE_SIZE = 50

log = logging.getLogger(__name__)


class Cybereason(CustomRulesMixin, SystemMixin, SensorsMixin, ThreatIntelligenceMixin):
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
        try:
            return AsyncClient(
                base_url=f'https://{self.server}.cybereason.net',
                headers={'content-type': 'application/json'},
                proxies=self.proxy,
                timeout=self.timeout,
            )
        except ImportError:
            if self.proxy and self.proxy.startswith('socks'):
                msg = 'Install SOCKS proxy support using `pip install cybereason[socks]`.'
                raise ImportError(msg) from None
            raise

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
        if hasattr(self, 'session_sage'):
            await self.session_sage.aclose()

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
                raise ClientError(e.response.text) from None
            elif e.response.status_code == 412:
                raise AccessDenied(e.response.text) from None
            elif e.response.status_code == 500:
                raise ServerError(e.response.text) from None
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

# region MALOPS
    async def get_malops(self, days_ago: Optional[int]=None) -> Any:
        '''Retrieve all Malops of all types (default: during the last week).

        Args:
            days_ago: If not set, all entries will be returned.
        '''
        # TODO: allow to specify end date
        now = datetime.utcnow()

        if days_ago is None:
            start = 0
        else:
            ago = now - timedelta(days=days_ago + 1)
            start = int(ago.timestamp() * 1000)

        data = {'startTime': start, 'endTime': int(now.timestamp() * 1000)}
        return await self.post('detection/inbox', data)

    async def get_active_malops(self, logon=False):
        '''Get all Malops currently active.
        '''
        data = {
            'totalResultLimit': 10000,
            'perGroupLimit': 10000,
            'perFeatureLimit': 100,
            'templateContext': 'OVERVIEW',
        }
        if logon:
            data.update({
                'customFields': [],
                'queryPath': [{'requestedType': 'MalopLogonSession', 'result': True, 'filters': None}],
            })
        else:
            data.update({
            'customFields': ['isMitigated'],
            'queryPath': [{'requestedType': 'MalopProcess', 'result': True, 'filters': None}],
            })
        return await self.post('crimes/unified', data)  # TODO

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

    @min_version(17, 5)
    @authz('Analyst L1')
    async def get_malware_alerts(self, filters=None) -> 'AsyncIterator[Any]':
        data = {'filters': filters or [], 'sortingFieldName': 'timestamp'}
        async for alert in self.aiter_pages('malware/query', data, key='malwares'):
            yield alert
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
    async def query(self, data):
        resp = await self.post('visualsearch/query/simple', data)
        if resp['status'] == 'FAILURE':
            raise CybereasonException(resp['message'])
        return resp['data']

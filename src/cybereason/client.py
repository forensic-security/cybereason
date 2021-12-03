from typing import Optional, Dict, List, Tuple, Any, AsyncIterator
from json.decoder import JSONDecodeError
from io import BytesIO, BufferedIOBase
from functools import cached_property
from datetime import datetime, timedelta
from pathlib import Path
import re

from httpx import AsyncClient, HTTPStatusError

from .exceptions import (
    AuthenticationError, UnauthorizedRequest, ServerError, ClientError,
    authz, min_version,
)
from .utils import parse_csv, find_next_version
from .sensors import SensorsMixin
from .system import SystemMixin
from .threats import ThreatIntelligenceMixin

DEFAULT_TIMEOUT = 10.0
DEFAULT_PAGE_SIZE = 10


class Cybereason(SystemMixin, SensorsMixin, ThreatIntelligenceMixin):
    def __init__(
        self,
        organization: str,
        username:     str,
        password:     str,
        proxy:        Optional[str]=None,
        timeout:      float=DEFAULT_TIMEOUT,
    ):
        self.organization = organization
        self.username = username
        self.password = password
        self.proxy = proxy
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
        auth = {'username': self.username, 'password': self.password}
        headers = {'content-type': 'application/x-www-form-urlencoded'}
        resp = await self.session.post('login.html', data=auth, headers=headers)
        if 'error' in str(resp.next_request):
            await self.session.aclose()
            raise AuthenticationError
        self.session.base_url = f'{self.session.base_url}/rest'

    async def __aenter__(self) -> 'Cybereason':
        await self.login()
        return self

    async def __aexit__(self, exc_type, exc_value, traceback) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if hasattr(self, 'session'):
            await self.session.aclose()

    async def _request(self, method: str, path: str, data: Any=None, query: Any=None) -> Any:
        resp = await self.session.request(method, path, json=data, params=query)

        try:
            resp.raise_for_status()
        except HTTPStatusError as e:
            if e.response.status_code == 403:
                raise UnauthorizedRequest(e.request.url) from None
            elif e.response.status_code == 400:
                raise ClientError
            elif e.response.status_code == 500:
                raise ServerError
            elif e.response.status_code == 302:
                raise AuthenticationError from None
            raise

        try:
            return resp.json()
        except JSONDecodeError:
            return resp.content.decode()

    async def get(self, path: str, query: Optional[Dict[str, Any]]=None):
        return await self._request('GET', path, query=query)

    async def post(self, path: str, data: Any):
        return await self._request('POST', path, data=data)

    async def put(self, path: str, data: Any):
        return await self._request('PUT', path, data=data)

    async def delete(self, path: str, query: Optional[Dict[str, Any]]=None):
        return await self._request('DELETE', path, query=query)

    async def raw_download(
        self,
        path:  str,
        query: Optional[Dict[str,Any]]=None,
    ) -> Tuple[str, BufferedIOBase]:

        buffer = BytesIO()
        async with self.session.stream('GET', path, params=query) as resp:
            resp.raise_for_status()

            filename = resp.headers['content-disposition']
            filename = re.search(r'\"(.*?)(?=\"|\Z)', filename).group(1)

            async for chunk in resp.aiter_bytes():
                # filter out keep-alive chunks
                if chunk:
                    buffer.write(chunk)

        buffer.seek(0)
        return filename, buffer

    async def download(
        self,
        path:     str,
        folder:   Path,
        *, query: Optional[Dict[str, Any]]=None,
        extract:  bool=False,
    ) -> Path:
        filename, buffer = await self.raw_download(path, query=query)

        if extract:
            folder = find_next_version(folder)
            # TODO
            return folder
        else:
            filepath = find_next_version(Path(folder, filename))
            with open(filepath, 'wb') as f:
                f.write(buffer.read())
            return filepath

    # FIXME
    async def aiter_pages(
        self,
        path:      str,
        data:      Any,
        key:       str,
        page_size: int=DEFAULT_PAGE_SIZE,
        sort:      str='ASC',
    ) -> AsyncIterator[Dict[str, Any]]:
        data = {**data, 'limit': page_size, 'offset': 0, 'sortDirection': sort}
        while True:
            resp = await self.post(path, data)
            for item in resp[key]:
                yield item
            if not resp['hasMoreResults']:
                break
            data['offset'] += page_size  # TODO: page number?

# region MALOPS
    async def get_malops(self) -> Any:
        '''Retrieve all Malops of all types (during the last week).
        '''
        # TODO: allow to specify dates
        now = datetime.utcnow()
        week_ago = now - timedelta(days=7)
        data = {
            'startTime': int(week_ago.timestamp() * 1000),
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
        malops_ids: Optional[List[str]]=None,
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
        reputation: Optional[str]=None,
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

    # TODO: create, update, delete rules
    async def create_isolation_rule(self, data) -> Dict[str, Any]:
        '''
        '''
        return await self.post('settings/isolation-rule', data)

    async def update_isolation_rule(self, data) -> Dict[str, Any]:
        return await self.put('settings/isolation-rule', data)

    async def delete_isolation_rule(self, data) -> None:
        '''Deletes an isolation exception rule.
        '''
        return await self.put('settings/isolation-rule/delete', data)
# endregion

# region INCIDENT RESPONSE
    @min_version(21, 1, 81)
    @authz('Responder L2')
    async def get_irtools_packages(self):
        '''Retrieves a list of previously uploaded packages from your
        environment.
        '''
        return await self.get('irtools/packages')

    async def get_credentials(self):
        '''Retrieves credentials for a predefined GCP bucket of your
        environment that you can use to access the tool results output.
        '''
        # TODO
        resp = await self.get('irtools/credentials')
# endregion

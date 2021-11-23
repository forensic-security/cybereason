from typing import Optional, Dict, List, Tuple, Any, AsyncIterator
from json.decoder import JSONDecodeError
from functools import cached_property
from ipaddress import ip_address
from httpx import AsyncClient, HTTPStatusError

from .exceptions import (
    UnauthorizedRequest, ServerError, ClientError,
    authz,
)
from .utils import parse_csv
from .sensors import SensorsMixin


class Cybereason(SensorsMixin):
    def __init__(
        self,
        organization: str,
        username:     str,
        password:     str,
        proxy:        Optional[str]=None,
        timeout:      float=10.0,
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
        await self.session.post('login.html', data=auth, headers=headers)
        self.session.base_url = f'{self.session.base_url}/rest'

    async def __aenter__(self) -> 'Cybereason':
        await self.login()
        return self

    async def __aexit__(self, *e) -> None:
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

    # FIXME
    async def aiter_pages(
        self,
        path:      str,
        data:      Any,
        key:       str,
        page_size: int=10,
        sort:      str='ASC',
    ) -> AsyncIterator[Dict[str, Any]]:
        data = {**data, 'limit': page_size, 'offset': 0, 'sortDirection': sort}
        while True:
            resp = await self.post(path, data)
            for item in resp[key]:
                yield item
            if not resp['hasMoreResults']:
                break
            data['offset'] += page_size

# region SYSTEM
    @cached_property
    async def version(self) -> Tuple[int, int, int]:
        resp = await self.get('monitor/global/server/version/all')
        return tuple(int(x) for x in resp['data']['version'].split('.'))
# endregion

# region MALOPS
    async def get_malops(self):
        '''Retrieve all Malops of all types.
        '''
        return await self.post('detection/inbox', None)  # TODO

    async def get_active_malops(self):
        '''Get all Malops currently active.
        '''
        return await self.post('crimes/unified', None)  # TODO

    async def get_malops_labels(
        self,
        malops_ids: Optional[List[str]]=None,
    ) -> List[Dict[str, Any]]:
        '''Returns a list of all Malop labels.

        .. versionadded:: 20.1.43

        Args:
            malops_ids: You can add specific Malop GUID identifiers.
        '''
        return await self.post('detection/labels', malops_ids or [])
# endregion

# region CUSTOM DETECTION RULES
    async def get_active_custom_rules(self):
        '''Retrieve a list of all active custom detection rules.
        '''
        return await self.get('customRules/decisionFeature/live')
# endregion

# region REPUTATIONS
    async def get_reputations(self) -> AsyncIterator[Dict[str, Any]]:
        '''Returns a list of custom reputations for files, IP addresses,
        and domain names.
        '''
        csv = await self.get('classification/download')

        for reputation in parse_csv(
            csv,
            boolean=['prevent execution', 'remove'],
            optional=['comment'],
        ):
            yield reputation

    async def get_ip_reputations(self):
        return await self.post('download_v1/ip_reputation', {})
# endregion

# region THREAT INTELLIGENCE
    async def get_ip_threats(self, ip):
        '''Returns details on IP address reputations based on the Cybereason
        threat intelligence service.
        '''
        # TODO: multiple ips?
        ip = ip_address(ip)
        data = {
            'requestData': [{
                'requestKey': {
                    'ipAddress': str(ip),
                    'addressType': f'Ipv{ip.version}',
                }
            }]
        }
        return await self.post('classification_v1/ip_batch', data)
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
    @authz('Responder L2')
    async def get_irtools_packages(self):
        '''Retrieves a list of previously uploaded packages from your
        environment.

        .. versionadded:: 21.1.81

        Raises:
            UnauthorizedRequest: if the user does not have the Responder L2
                role assigned.
        '''
        return await self.get('irtools/packages')

    async def get_credentials(self):
        '''Retrieves credentials for a predefined GCP bucket of your environment
        that you can use to access the tool results output.
        '''
        # TODO
        resp = await self.get('irtools/credentials')
# endregion

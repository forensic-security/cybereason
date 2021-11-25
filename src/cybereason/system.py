from typing import Union, Optional, Any, Dict, List, Tuple
from functools import cached_property

from .exceptions import ServerError


class SystemMixin:
    @cached_property
    async def version(self) -> Tuple[int, int, int]:
        resp = await self.get('monitor/global/server/version/all')
        return tuple(int(x) for x in resp['data']['version'].split('.'))

    async def get_users(self) -> List[Dict[str, Any]]:
        return await self.get('users')

    async def get_user(self, username: Optional[str]=None) -> List[Dict[str, Any]]:
        '''
        Args:
            username: If not specified, returns the client's logged user.
        '''
        username = username or 'current'
        return await self.get(f'users/{username}')

    async def get_registration_servers(self):
        return await self.get('settings/get-registration-servers')

    async def get_detection_servers(self):
        return await self.get('settings/get-detection-servers')

    async def get_registration_config(self):
        # XXX: returns detection servers
        resp = await self.get('settings/configuration/general/get-registration-config')
        if resp['outcome'] == 'success':
            return resp['data']
        else:
            raise ServerError(resp)

    async def get_investigation_config(self) -> Dict[str, Dict[str, List[Dict[str, Union[str, List[str]]]]]]:
        resp = await self.get('investigation/configuration')
        return resp['configurationModel']

    async def download_malop_syslog(self, server_id, folder: str, extract: bool=False):
        resp = await self.download(
            'monitor/global/server/logs',
            folder,
            query={'serverId': server_id},
            extract=extract,
        )

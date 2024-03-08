from typing import Union, Optional, Any, Dict, List, Tuple
from pathlib import Path
from os import PathLike

from .exceptions import ServerError, min_version
from ._typing import CybereasonProtocol


class SystemMixin(CybereasonProtocol):
    @property
    async def version(self) -> Tuple[int, int, int]:
        if self.__version is None:
            resp = await self.get('monitor/global/server/version/all')
            self.__version = tuple(int(x) for x in resp['data']['version'].split('.'))
            # TODO: monitor/global/server/version?serverId=<server_id>
        return self.__version

    @property
    async def server_id(self) -> str:
        if self.__server_id is None:
            servers = [s['id'] for s in await self.get_detection_servers()]
            if len(servers) == 1:
                self.__server_id = servers[0]
            elif not servers:
                raise ServerError('No detection server has been found.')
            else:
                raise ValueError(f'Please specify one serverId: {", ".join(servers)}')
        return self.__server_id

    async def get_users(self) -> List[Dict[str, Any]]:
        return await self.get('users')

    async def get_user(self, username: Optional[str] = None) -> List[Dict[str, Any]]:
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
        return self.check_resp(resp)

    async def get_investigation_config(
        self
    ) -> Dict[str, Dict[str, List[Dict[str, Union[str, List[str]]]]]]:
        resp = await self.get('investigation/configuration')
        return resp['configurationModel']

    async def get_latest_installers(self, server_id: Optional[str] = None) -> List[Dict[str, Any]]:
        query = {'serverId': server_id or await self.server_id}
        resp = await self.get('monitor/global/versions/latest', query=query)
        # denormalize output
        return [{**d, **v, **s} for s in resp
                for v in s.pop('versions')['full']
                for d in v.pop('downloads')]

    async def download_installer(
        self,
        system:    str,
        folder:    PathLike,
        server_id: Optional[str] = None,
    ) -> Path:
        '''
        Args:
            system: {'win32', 'win64', 'osx', 'deb', 'rpm'}
        '''
        try:
            name = dict(win='WINDOWS', osx='OSX', deb='LINUX_DEB', rpm='LINUX')[system[0:3]]
            arch = {'32': 'ARCH_32BIT', '64': 'ARCH_64BIT', '': 'ARCH_64BIT'}[system[3:]]
        except KeyError:
            raise ValueError(system)

        server_id = server_id or await self.server_id

        # download_id = [
        #     a['downloadId'] for n in await self.get_latest_installers(server_id)
        #     for (k, v) in n.items() if n['osName'] == name and k == 'versions'
        #     for a in v['full'][0]['downloads'] if a['architecture'] == arch
        # ][0]

        download_id = [
            s['downloadId'] for s in await self.get_latest_installers(server_id)
            if s['osName'] == name and s['architecture'] == arch
        ][0]

        return await self.download(
            'monitor/global/version/download/platform/',
            folder=folder,
            query={'serverId': server_id, 'downloadId': download_id},
        )

    async def download_malop_syslog(
        self,
        folder:    PathLike,
        extract:   bool = False,
        server_id: Optional[str] = None,
    ) -> Path:
        return await self.download(
            'monitor/global/server/logs',
            folder=folder,
            query={'serverId': server_id or await self.server_id},
            extract=extract,
        )

    @min_version(20, 2, 61)
    async def get_settings(self):
        '''Get details on settings updates including Malop notification
        settings.
        '''
        return await self.get('settings/configurations')

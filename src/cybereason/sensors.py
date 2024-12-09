from typing import TYPE_CHECKING, cast
from pathlib import Path
import logging
import asyncio

from .utils import to_list, get_filename
from .exceptions import (
    AccessDenied, ServerError, ClientError, FilterSError,
    ResourceExistsError, ResourceNotFoundError,
    authz, min_version,
)
from ._typing import CybereasonProtocol, unset

if TYPE_CHECKING:
    from typing import Any, AsyncIterator, Dict, List, Optional, Union
    from ._typing import SensorId, Unset, Unforced
    from os import PathLike


log = logging.getLogger(__name__)


class SensorsMixin(CybereasonProtocol):
    @authz('System Admin')
    async def get_sensors(
        self,
        *, archived: bool = True,
        filters:     'Optional[List[Any]]' = None,
    ) -> 'AsyncIterator[Dict[str, Any]]':
        '''Returns details on all or a selected group of sensors.

        Args:
            archived: show archived sensors.
        '''
        data = {'filters': filters or []}

        if not archived:
            data['filters'].append({
                'fieldName': 'status',
                'operator':  'NotEquals',
                'values':    ['Archived'],
            })

        try:
            async for sensor in self.aiter_pages('sensors/query', data, 'sensors'):
                yield sensor
        except KeyError:
            raise FilterSError(filters) from None

    @authz('System Admin')
    async def get_sensors_actions(self) -> 'Any':
        '''Returns a list of all the current or queued actions on sensors.
        '''
        return await self.get('sensors/allActions')

    # TODO: add timeout
    @authz('System Admin')
    async def get_sensors_logs(self, *sensors_ids) -> bytes:
        '''Returns a compressed archive with the logs from one or more
        sensors.
        '''
        # create batch job
        data = {'sensorsIds': sensors_ids}
        resp = await self.post('sensors/action/fetchLogs', data)
        if not resp:
            raise ResourceNotFoundError
        batch = resp['batchId']

        # retrieve job results
        while True:
            await asyncio.sleep(2)
            log.debug('Waiting for batch job %s', batch)
            resp = await self.get(f'sensors/action/download-logs/{batch}', raw=True)
            if resp:
                # TODO: write to disk
                return resp

    async def get_sensors_overview(self) -> 'Dict[str, Dict[str, Any]]':
        return await self.get('sensors/overview')

    @min_version(21, 2, 142)
    @authz('System Admin')
    async def delete_sensor(self, sensor_id: 'SensorId') -> 'Any':
        '''Deletes a sensor or all sensors from the list of sensors.
        '''
        data = {'sensorsIds': [sensor_id], 'filters': []}
        return self.post('sensors/action/delete', data)

    @min_version(21, 2, 145)
    @authz('System Admin')
    async def remove_sensor(self, sensor_id: 'SensorId') -> 'Any':
        data = {'sensorsIds': [sensor_id], 'filters': []}
        return self.post('sensors/action/purgeSensors', data)

    @min_version(22, 1, 168)
    @authz('System Admin')
    async def uninstall_sensor(self, sensor_id: 'SensorId') -> 'Any':
        data = {'sensorsIds': [sensor_id]}
        return await self.post('sensors/action/uninstall', data)

    @min_version(21, 2, 145)
    @authz('System Admin')
    async def purge_sensor(self, sensor_id: 'SensorId') -> 'Any':
        raise NotImplementedError

    @min_version(21, 2, 145)
    @authz('System Admin')
    async def unpurge_sensor(self, sensor_id: 'SensorId') -> 'Any':
        raise NotImplementedError

# region GROUPS
    @min_version(20, 1)
    @authz('System Admin')
    async def get_groups(self) -> 'List[Dict[str, Any]]':
        '''Retrieves a list of sensor groups.
        '''
        return await self.get('groups')

    async def get_group_by_name(self, name: str) -> 'Dict[str, Any]':
        resp = await self.get_groups()
        try:
            return [g for g in resp if g['name'] == name][0]
        except IndexError:
            raise ResourceNotFoundError(f'There is not a group with name: {name!r}') from None

    async def get_group_by_id(self, group_id: str) -> 'Dict[str, Any]':
        resp = await self.get_groups()
        try:
            return [g for g in resp if g['id'] == group_id][0]
        except IndexError:
            raise ResourceNotFoundError(f'There is not a group with ID: {group_id!r}') from None

    @authz('System Admin')
    async def create_group(
        self,
        *, name:     str,
        description: 'Optional[str]' = None,
        rules:       'Optional[List[Dict[str, Any]]]' = None,
        policy_id:   'Optional[str]' = None,
    ) -> str:
        '''Creates a sensor group to help organize sensors in your
        environment. Returns the group's ID.

        Args:
            name: A string with a name for the group.
            description: A string that describes the group.
            rules: The automatic assignment rules for groups that will
                be applied on new sensors.
            policy_id: The ID of a specific sensor policy that will be
                applied to all sensors in the group.
        '''
        data = {
            'name': name,
            'description': description or '',
            'groupAssignRule': rules,
            'policyId': policy_id,
        }

        try:
            resp = await self.post('groups', data)
        except ServerError as e:
            try:
                await self.get_group_by_name(name)
            except ResourceNotFoundError:
                raise e
            raise ResourceExistsError(f'The group {name!r} already exists.') from None

        return resp['groupId']

    @min_version(20, 2, 2)
    @authz('System Admin')
    async def edit_group(
        self,
        group_id:    str,
        name:        'Unforced[str]' = unset,
        description: 'Unforced[str]' = unset,
        rules:       'Unforced[List[Dict[str, Any]]]' = unset,
        policy_id:   'Unforced[str]' = unset,
    ) -> 'Any':
        '''Edits the details of an existing sensor group.
        '''
        group = await self.get_group_by_id(group_id)
        data = {
            'name':            group['name'] if name is unset else name,
            'description':     group['description'] if description is unset else description,
            'groupAssignRule': group['groupAssignRule'] if rules is unset else rules,
            'policyId':        group['policyId'] if policy_id is unset else policy_id,
        }
        return await self.put(f'groups/{group_id}', data)

    @min_version(20, 2, 201)
    @authz('System Admin')
    async def delete_group(
        self,
        group_id:     str,
        new_group_id: 'Optional[str]' = None,
    ) -> 'Dict[str, Any]':
        '''Deletes an existing sensor group.

        Args:
            group_id: The ID of the group to be deleted.
            new_group_id: You can add the group ID for the new group to which
                to assign the sensors. If no group is specified, the sensors
                will be assigned to the default unassigned group.
        '''
        query = {'assignToGroupId': new_group_id or '00000000-0000-0000-0000-000000000000'}
        try:
            return await self.delete(f'groups/{group_id}', query)
        except ClientError as e:
            try:
                await self.get_group_by_id(group_id)
            except ResourceNotFoundError:
                raise
            raise e

    @min_version(20, 1)
    @authz('Sensor Admin L1 or System Admin')
    async def add_to_group(
        self,
        group_id:    str,
        sensors_ids: 'Union[SensorId, List[SensorId]]',
    ) -> 'Any':
        '''Adds the selected sensor(s) to a sensor group to help organize
        sensors in your environment.
        '''
        data = {
            'sensorsIds': to_list(sensors_ids),
            'argument': group_id,
        }
        return await self.post('sensors/action/addToGroup', data)

    # TODO: you must be assigned to a group to run this request.
    @min_version(20, 1)
    @authz('Sensor Admin L1')
    async def remove_from_group(self, *sensors_ids, filters: 'Optional[Any]' = None) -> 'Any':
        '''Removes a sensor from a sensor group, and assigns it to the
        unassigned group.
        '''
        data = {'sensorsIds': sensors_ids, 'filters': filters}
        return await self.post('sensors/action/removeFromGroup', data)
# endregion

# region POLICIES
    # TODO: paginate
    async def get_policies(
        self,
        show_config: bool = True,
        filters:     'Optional[Dict[str, Any]]' = None,
    ) -> 'AsyncIterator[Dict[str, Any]]':
        query = {'filter': filters or dict()}
        resp = await self.get('policies', query=query)

        if show_config:
            for policy in resp['policies']:
                yield await self.get_policy(policy['id'])
        else:
            for policy in resp['policies']:
                yield policy

    async def get_policy(self, policy_id: str) -> 'Dict[str, Any]':
        return await self.get(f'policies/{policy_id}')

    async def get_default_policy(self) -> 'Dict[str, Any]':
        async for policy in self.get_policies():
            if policy['metadata']['isDefault']:
                return policy
        raise ResourceNotFoundError('Default policy not found')

    async def create_policy(self, data, unique_name: bool = False) -> None:
        if unique_name:
            async for policy in self.get_policies():
                if policy['metadata']['name'] == data['nameDescription']['name']:
                    raise ResourceExistsError(data['nameDescription']['name'])
        return await self.post('policies', data)

    async def delete_policy(
        self,
        policy_id: str,
        assign_to: 'Optional[str]' = None,
    ) -> 'Dict[str, Any]':
        if assign_to is None:
            default = await self.get_default_policy()
            assign_to = default['metadata']['id']
        query = {'assignToPolicyId': assign_to}
        return await self.delete(f'policies/{policy_id}', query)
# endregion

# region ACTIONS
    async def restart_sensor(self, **kwargs):
        raise NotImplementedError

    @min_version(18, 0)
    @authz('System Admin')
    async def set_sensor_tags(
        self,
        pylum_id:       str,
        department:     'Union[Unset, None, str]' = unset,
        location:       'Union[Unset, None, str]' = unset,
        device_type:    'Union[Unset, None, str]' = unset,
        critical_asset: 'Union[Unset, None, bool]' = unset,
        custom_tags:    'Union[Unset, None, str]' = unset,
    ) -> 'Dict[str, Dict[str, Union[str, bool]]]':
        '''Creates, modifies or delete tags for a specific sensor or
        group of sensors. To delete a tag set the value to ``None``.
        '''
        ops: 'Dict[str, Dict[str, Union[str, bool]]]' = dict()

        for name, value, typ in (
            ('department',     department,     str),
            ('location',       location,       str),
            ('device type',    device_type,    str),
            ('critical asset', critical_asset, bool),
            ('custom tags',    custom_tags,    str),
        ):
            if value is not unset:
                if value is None:
                    ops[name] = {'operation': 'REMOVE'}
                elif isinstance(value, typ):
                    if typ == str and len(value) > 100:  # type: ignore
                        msg = f'The maximum length for the {name!r} tag is 100 characters'
                        raise ValueError(msg)
                    ops[name] = {'operation': 'SET', 'value': cast('Union[str, bool]', value)}
                else:
                    raise TypeError(f'{name!r} tag must be a {typ.__name__!r}')

        data = {'entities': {pylum_id: {'tags': ops, 'entityType': 'MACHINE'}}}
        resp = await self.post('tagging/process_tags', data)
        resp = resp['entities'][pylum_id]['results']

        err = dict()
        for tag, result in resp.items():
            if not result['success']:
                # ignore unsuccessful deletions of missing tags
                if not (result['operation'] == 'REMOVE' and result['oldValue'] == ''):
                    err[tag] = result
        if err:
            raise ClientError(err)
        return resp

    async def set_remote_shell_mode(
        self,
        sensors_ids: 'Union[str, List[SensorId]]',
        enabled:     bool = False,
    ) -> 'Dict[str, Any]':
        data = {
            'argument': 'AC_ENABLED' if enabled else 'AC_DISABLED',
            'sensorsIds': to_list(sensors_ids),
        }
        return await self.post('sensors/action/setRemoteShellStatus', data=data)

    async def set_app_control_mode(
        self,
        sensors_ids: 'Union[str, List[SensorId]]',
        enabled:     bool = False,
    ) -> 'Dict[str, Any]':
        data = {
            'argument': 'ENABLE' if enabled else 'DISABLE',
            'sensorsIds': to_list(sensors_ids),
        }
        return await self.post('sensors/action/setPreventionMode', data=data)

    @authz('System Admin')
    async def start_collection(
        self,
        sensors_ids: 'Optional[List[SensorId]]' = None,
        filters:     'Optional[List[Any]]' = None,
    ) -> 'Any':
        '''Begins collecting data for all sensors or a group of filtered
        sensors.
        '''
        raise NotImplementedError

    @authz('System Admin')
    async def stop_collection(
        self,
        sensors_ids: 'Optional[List[SensorId]]' = None,
        filters:     'Optional[List[Any]]' = None,
    ) -> 'Any':
        '''Stops collecting data for all sensors or a group of filtered
        sensors.
        '''
        raise NotImplementedError
# endregion

    @authz('Responder L1, Responder L2, Local Responder or Local Analyst')
    async def open_remote_shell(
        self,
        pylum_id:   str,
        restricted: bool = True,
    ) -> 'Dict[str, Optional[str]]':
        '''Opens a remote shell session and returns the data needed to
        establish a websocket connection.
        '''
        data = {
            'cols':      112,
            'pylumId':   pylum_id,
            'mode':      'RESTRICTED' if restricted else 'NON_RESTRICTED',
            'twoFaCode': self.totp_code,
        }

        try:
            resp = await self.post('shell/start', data=data)
        except AccessDenied:
            # TODO: check if remote shell is enabled
            raise

        path = '/'.join(('', 'shell', pylum_id, resp['sensorSessionId']))

        return {
            'uri':        str(self.session.base_url.copy_with(scheme='wss', path=path)),
            'cookie':     f'JSESSIONID={self.session.cookies.get("JSESSIONID")}',
            'proxy':      self.proxy,
            'session_id': resp['sensorSessionId'],
        }

    async def close_remote_shell(self, pylum_id: str, session_id: str) -> None:
        '''Closes a remote shell session.
        '''
        data = {'pylumId': pylum_id, 'sensorSessionId': session_id}
        await self.post('shell/terminate', data=data)

    async def download_file(
        self,
        pylum_id: str,
        filepath: 'PathLike',
        destdir:  'Optional[PathLike]' = None,
        extract:  bool = False,
    ) -> Path:
        '''
        Downloads a file from a sensor.

        If ``extract`` is ``True`` returns the folder where the archive
        was extracted. Otherwise returns the path where the archive was
        downloaded.
        '''
        from io import BytesIO

        destdir = Path('.').resolve() if not destdir else Path(destdir)

        if not destdir.exists():
            destdir.mkdir(parents=True)
        elif destdir.is_file():
            raise NotADirectoryError(destdir)

        data = {'path': str(filepath), 'pylumId': pylum_id}

        async with self.session.stream('POST', 'file-search/fetch-direct', json=data) as resp:
            try:
                filename = get_filename(resp)
            except FileNotFoundError:
                raise FileNotFoundError(filepath) from None

            buffer = BytesIO()
            async for chunk in resp.aiter_bytes():
                if chunk:
                    buffer.write(chunk)
            buffer.seek(0)

        if extract:
            try:
                # XXX: ZipFile only supports CRC32 encrypted zip files
                from pyzipper import AESZipFile
            except ImportError:
                raise RuntimeError('Install as `pip install cybereason[zip]` to'
                                   'allow file extraction.')

            with AESZipFile(buffer, mode='r') as archive:
                # TODO: add drive to target
                archive.extractall(path=destdir, pwd=b'cautionhandlewithcare')

            return destdir
        else:
            with open(destdir / filename, 'wb') as archive:
                archive.write(buffer.read())

            return destdir / filename

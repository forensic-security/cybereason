from typing import Optional, List, Dict, Any

from .utils import to_list
from .exceptions import (
    ServerError, ClientError,
    ResourceExistsError, ResourceNotFoundError, authz,
)


class SensorsMixin:
    async def get_sensors(self, filters=[], page_size: int=10):
        '''Returns details on all or a selected group of sensors.
        '''
        async for sensor in self.aiter_pages(
            path='sensors/query',
            data={'filters': filters},
            key='sensors',
            page_size=page_size,
        ):
            yield sensor

    @authz('System Admin')
    async def get_sensors_actions(self):
        '''Returns a list of all the current or queued actions on sensors.

        Raises:
            UnauthorizedRequest: if the user does not have the System Admin
                role assigned.
        '''
        return await self.get('sensors/allActions')

    @authz('System Admin')
    async def get_sensors_logs(self, *sensors_ids):
        '''Retrieves logs from one or more sensors.
        '''
        # create batch job
        data = {'sensorsIds': sensors_ids}
        resp = await self.post('sensors/action/fetchLogs', data)

        # retrieve job results
        return await self.get(f'sensors/action/download-logs/{resp["batchId"]}')

    @authz('System Admin')
    async def get_groups(self):
        '''Retrieves a list of sensor groups.

        .. versioadded:: 20.1.x

        Raises:
            UnauthorizedRequest: if the user does not have the System Admin
                role assigned.
        '''
        return await self.get('groups')

    async def get_group_by_name(self, name: str) -> Dict[str, Any]:
        resp = await self.get_groups()
        try:
            group = [g for g in resp if g['name'] == name][0]
        except IndexError:
            raise ResourceNotFoundError(f'There is not a group with name: "{name}".')
        return group

    async def get_group_by_id(self, group_id: str) -> Dict[str, Any]:
        resp = await self.get_groups()
        try:
            group = [g for g in resp if g['id'] == group_id][0]
        except IndexError:
            raise ResourceNotFoundError(f'There is not a group with ID: "{group_id}"')
        return group

    @authz('System Admin')
    async def create_group(
        self,
        *, name:     str,
        description: Optional[str]=None,
        rules:       Optional[List[Dict[str, Any]]]=None,
        policy_id:   Optional[str]=None,
    ) -> str:
        '''Creates a sensor group to help organize sensors in your
        environment. Returns the group's ID.

        Args:
            name: A string with a name for the group.
            description: A string that describes the group.
            rules: The automatic assignment rules for groups that will
                be applied on new sensors.
            policy_id: The Id of a specific sensor policy that will be
                applied to all sensors in the group 
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
            raise ResourceExistsError(f'The group "{name}" already exists.')

        return resp['groupId']

    @authz('System Admin')
    async def edit_group(self, group_id, data):
        '''Edits the details of an existing sensor group.

        .. versioadded:: 20.2.2

        Raises:
            UnauthorizedRequest: if the user does not have the System Admin
                role assigned.
        '''
        return await self.post(f'groups/{group_id}', data)

    @authz('System Admin')
    async def delete_group(
        self,
        group_id:     str,
        new_group_id: Optional[str]=None,
    ) -> Dict[str, Any]:
        '''Deletes an existing sensor group.

        .. versionadded:: 20.2.201

        Args:
            group_id: The ID of the group to be deleted.
            new_group_id: You can add the group ID for the new group to which
                to assign the sensors. If no group is specified, the sensors
                will be assigned to the default unassigned group.

        Raises:
            UnauthorizedRequest: if the user does not have the System Admin
                role assigned.
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

    @authz('Sensor Admin L1 or System Admin')
    async def add_to_group(self, group_id, sensors_ids):
        '''Adds the selected sensor(s) to a sensor group to help organize
        sensors in your environment.

        .. versionadded:: 20.1.x
        '''
        data = {
            'sensorsIds': to_list(sensors_ids),
            'argument': group_id,
        }
        return await self.post('sensors/action/addToGroup', data)

    # TODO: # you must be assigned to a group to run this request.
    @authz('Sensor Admin L1')
    async def remove_from_group(self, *sensors_ids, filters: Optional[Any]=None):
        '''Removes a sensor from a sensor group, and assigns it to the
        unassigned group.

        .. versionadded:: 20.1.x
        '''
        data = {'sensorsIds': sensors_ids, 'filters': filters}
        return await self.post('sensors/action/removeFromGroup', data)

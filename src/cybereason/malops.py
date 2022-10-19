from datetime import datetime, timedelta
from typing import TYPE_CHECKING
import logging

from .exceptions import CybereasonException, authz, min_version
from ._typing import CybereasonProtocol

if TYPE_CHECKING:
    from typing import Any, AsyncIterator, Dict, List, Optional, Union
    from ._typing import MalopId

    Label = Dict[str, Union[str, int]]

log = logging.getLogger(__name__)


class MalopsMixin(CybereasonProtocol):
    async def get_malops(self, days_ago: 'Optional[int]'=None) -> 'List[Dict[str, Any]]':
        '''Retrieve all malops of all types.

        Args:
            days_ago: Sets the oldest malops to retrieve. If not set,
                all malops will be returned.
        '''
        # TODO: allow to specify end date
        now = datetime.utcnow()

        if days_ago is None:
            start = 0
        else:
            ago = now - timedelta(days=days_ago + 1)
            start = int(ago.timestamp() * 1000)

        data = {'startTime': start, 'endTime': int(now.timestamp() * 1000)}
        return (await self.post('detection/inbox', data))['malops']

    async def get_active_malops(self, logon: bool=False) -> 'AsyncIterator[Dict[str, Any]]':
        '''Get all Malops currently active.
        '''

        data = {
            'totalResultLimit': 10000,
            'perGroupLimit': 10000,
            'perFeatureLimit': 100,
            'templateContext': 'OVERVIEW',
            'customFields': [],
            'queryPath': [{'result': True, 'filters': None}],
        }

        for req_type in ('MalopProcess', 'MalopLogonSession'):
            data['queryPath'][0]['requestedType'] = req_type

            resp = await self.post('crimes/unified', data)

            if not resp['status'] == 'SUCCESS':
                raise CybereasonException(resp['message'])

            for malop in resp['data']['resultIdToElementDataMap'].values():
                yield malop

    # TODO: retrieve details for Auto Hunt Malops
    # TODO: endpoint fails
    # @min_version(20, 1, 43)
    # async def get_edr_malop_details(self, malop_id: 'MalopId'):
    #     '''Returns details about a specified Endpoint Protection Malop.
    #     '''
    #     data = {'malopGuid': malop_id}
    #     return await self.post('detection/details', data)

    async def has_malop_history(self, malop_id: 'MalopId') -> bool:
        data = {'guids': [malop_id], 'elementType': 'MalopProcess'}
        return await self.post('remediate/has-history', data)  # TODO: also bool if True?

    @min_version(17, 5)
    @authz('Analyst L1')
    async def get_malware_alerts(self, filters=None) -> 'AsyncIterator[Any]':
        data = {'filters': filters or [], 'sortingFieldName': 'timestamp'}
        async for alert in self.aiter_pages('malware/query', data, key='malwares'):
            yield alert

    async def get_malop_comments(self, malop_id: 'MalopId') -> 'List[Dict[str, Union[str, int]]]':
        from html import unescape

        resp = await self.post('crimes/get-comments', malop_id, raw_data=True)
        for msg in resp:
            msg['message'] = unescape(msg['message'])
        return resp

# region LABELS
    @min_version(20, 1, 43)
    async def get_malops_labels(
        self,
        malops_ids: 'Optional[List[MalopId]]' = None,
    ) -> 'List[Label]':
        '''Returns a list of all Malop labels.

        Args:
            malops_ids: You can add specific Malop GUID identifiers.
        '''
        return await self.post('detection/labels', malops_ids or [])

    @min_version(20, 1, 43)
    async def add_malop_label(self, label: str) -> 'Label':
        '''Add a new malop label to the list of labels available for use
        to add to malops.
        '''
        return await self.post('detection/add-label', {'labelText': label})

    @min_version(20, 1, 43)
    async def update_malop_labels(
        self,
        malops_ids:     'List[MalopId]',
        added_labels:   'List[int]',
        removed_labels: 'List[int]',
    ) -> 'Any':
        '''Updates an existing malop label from the list of labels
        available for use to add to malops.
        '''
        data = {
            'malopGuids':    malops_ids,
            'addedLabels':   added_labels,
            'removedLabels': removed_labels,
        }
        return await self.post('detection/update-labels', data)

    @min_version(20, 1, 43)
    async def delete_malop_label(self, label_id: int) -> bool:
        '''Deletes an existing malop label from the list of labels
        available for use to add to malops.
        '''
        # resp = await self.post('detection/delete-labels', label_id)
        # XXX: this ^ is the method documented, but it fails on 21.1.401
        resp = await self.post('labels/delete', {'id': label_id})

        # XXX: returns 'success' even if the label doesn't exist
        return resp == 'success'
# endregion

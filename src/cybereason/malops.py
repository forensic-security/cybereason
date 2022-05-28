from typing import TYPE_CHECKING
from datetime import datetime, timedelta

from .exceptions import CybereasonException, authz, min_version
from ._typing import CybereasonProtocol

if TYPE_CHECKING:
    from typing import Any, AsyncIterator, Dict, List, Optional, Union


class MalopsMixin(CybereasonProtocol):
    async def get_malops(self, days_ago: 'Optional[int]'=None) -> 'List[Dict[str, Any]]':
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
    # async def get_edr_malop_details(self, malop_id: str):
    #     '''Returns details about a specified Endpoint Protection Malop.
    #     '''
    #     data = {'malopGuid': malop_id}
    #     return await self.post('detection/details', data)

    @min_version(20, 1, 43)
    async def get_malops_labels(
        self,
        malops_ids: 'Optional[List[str]]' = None,
    ) -> 'List[Dict[str, Any]]':
        '''Returns a list of all Malop labels.

        Args:
            malops_ids: You can add specific Malop GUID identifiers.
        '''
        return await self.post('detection/labels', malops_ids or [])

    async def get_malop_comments(self, malop_id: str) -> 'List[Dict[str, Union[str, int]]]':
        from html import unescape

        resp = await self.post('crimes/get-comments', malop_id, raw_data=True)
        for msg in resp:
            msg['message'] = unescape(msg['message'])
        return resp

    @min_version(17, 5)
    @authz('Analyst L1')
    async def get_malware_alerts(self, filters=None) -> 'AsyncIterator[Any]':
        data = {'filters': filters or [], 'sortingFieldName': 'timestamp'}
        async for alert in self.aiter_pages('malware/query', data, key='malwares'):
            yield alert

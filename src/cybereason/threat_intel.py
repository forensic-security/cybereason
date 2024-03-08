from typing import TYPE_CHECKING, Any
from ipaddress import ip_address
from datetime import datetime
from pathlib import Path
from os import PathLike
import hashlib

from ._typing import CybereasonProtocol

if TYPE_CHECKING:
    from typing import AsyncIterator, Dict, List, Optional, Literal


class ThreatIntelligenceMixin(CybereasonProtocol):

# region QUERIES
    @property
    async def reputation_list(self):
        if not hasattr (self, '__reputation_list'):
            url = 'dynamic/v1/ti-reputation/api/v1/entity/lists/default'
            self.__reputation_list = await self.get(url)
        return self.__reputation_list

    # async def get_custom_reputations(
    #     self,
    #     included_expired: bool = False,
    # ) -> 'AsyncIterator[Dict[str, Any]]':
    #     '''Returns a list of custom reputations for files, IP addresses,
    #     and domain names.
    #     '''
    #     url = 'classification/reputations/list'
    #     data = {'filter': {'includeExpired': included_expired}}
    #     async for x in self.aiter_items(url, data, 'reputations', check_resp=True):
    #         yield x

    async def get_reputations(self) -> 'AsyncIterator[Dict[str, Any]]':
        rep_list = await self.reputation_list
        url = f'dynamic/v1/ti-reputation/api/v1/lists/{rep_list}/reputations/search'
        async for x in self.aiter_items(url, {}, 'reputations', pagination=True):
            yield x

    async def update_reputation(
        self,
        id:         int,
        *, comment: str,
        action:     'Literal["ALLOW", "DENY"]',
        keys:       'List[Dict[str, str]]',
        groups:     'Optional[List[str]]' = None,
        expiration: 'Optional[datetime]' = None,
    ) -> 'Dict[str, Any]':
        '''
        Args:
            groups: ``None`` means "Global".
        '''
        data = {
            'comment':          comment,
            'action':           action,
            'keys':             keys,
            'groupIds':         groups,
            'reputationListId': await self.reputation_list,
        }
        # TODO: remove expiration?
        if expiration is not None:
            data['expiresAt'] = int(expiration.timestamp() * 1000)

        rep_list = await self.reputation_list
        url = f'dynamic/v1/ti-reputation/api/v1/lists/{rep_list}/reputations/{id}'
        return await self.put(url, data)

    async def get_file_reputation(self, path: PathLike, use_sha1: bool = True) -> Any:
        '''Returns details on a file’s reputation based on the threat
        intelligence service.

        Args:
            path: path to the file.
            use_sha1: if ``True`` uses SHA-1 to hash the file. Otherwise
                uses MD5.
        '''
        func = hashlib.sha1 if use_sha1 else hashlib.md5
        key = 'sha1' if use_sha1 else 'md5'
        hash_ = func(Path(path).read_bytes()).hexdigest()

        data = {'requestData': [{'requestKey': {key: hash_}}]}
        return await self.post_sage('classification_v1/file_batch', data)

    async def get_domain_reputation(self, domain: str) -> Any:
        '''Returns details on domain reputations based on the threat
        intelligence service.
        '''
        data = {'requestData': [{'requestKey': {'domain': domain}}]}
        resp = await self.post_sage('classification_v1/domain_batch', data)
        return resp['classificationResponses']

    async def get_ip_reputation(self, ip: str) -> Any:
        '''Returns details on IP address reputations based on the
        threat intelligence service.
        '''
        # TODO: multiple ips?
        _ip = ip_address(ip)
        data = {
            'requestData': [{
                'requestKey': {
                    'ipAddress': str(ip),
                    'addressType': f'Ipv{_ip.version}',
                }
            }]
        }
        resp = await self.post_sage('classification_v1/ip_batch', data)
        return resp['classificationResponses']

    async def check_reputation_update(self, resource: str) -> Any:
        '''Check the threat intelligence server to see if it has been
        updated recently.
        '''
        # The Cybereason platform uses the retrieved timestamp to check
        # if the data set has been updated and will send a request for
        # the specific service if the data set is newer than the current data.
        RESOURCES = {
            'ip_reputation', 'domain_reputation', 'process_classification',
            'file_extension', 'process_hierarchy', 'product_classification',
            'const',
        }
        if resource not in RESOURCES:
            msg = "Invalid resource API: '{}'. Accepted values: {}"
            raise ValueError(msg.format(resource, ', '.join(RESOURCES)))
        return await self.post_sage(f'download_v1/{resource}/service', {})
# endregion

# region LISTS
    async def get_product_classifications(self) -> 'List[Dict[str, Dict[str, Any]]]':
        '''Returns details on product classifications based on the
        threat intelligence service. This is used to identify the
        application type based on the product name and process image
        file signature.
        '''
        resp = await self.post_sage('download_v1/productClassifications', {})
        return resp['recordList']

    async def get_process_classifications(self) -> Any:
        '''Returns details on process classifications based on the
        threat intelligence service. This is used by to identify the
        application type based on the process name, process image file
        signature, process image file path and description, product
        name, and company name for the product.
        '''
        return await self.post_sage('download_v1/process_classification', {})

    async def get_process_hierarchies(self) -> Any:
        '''Returns details on process hierarchy based on the threat
        intelligence service. This is used to identify the expected
        hierarchy of operating system processes.
        '''
        return await self.post_sage('download_v1/process_hierarchy', {})

    async def get_file_extensions_details(self) -> Any:
        '''Returns details on file extensions based on the threat
        intelligence service. This is used to classify files and
        processes based on the extension of the file.
        '''
        return await self.post_sage('download_v1/file_extension', {})

    async def get_ports_details(self) -> Any:
        '''Returns details on ports based on the threat intelligence
        service. This is used to classify communications based on the
        port of the connection.
        '''
        return await self.post_sage('download_v1/port', {})

    async def get_collections_details(self) -> 'List[Dict[str, Dict[str, Any]]]':
        '''Returns details on collections of reference information used
        by the threat intelligence service.
        '''
        return (await self.post_sage('download_v1/const', {}))['recordList']

    async def get_ip_reputations(self) -> Any:
        '''Returns a list of all IP address reputations used by the
        threat intelligence service.
        '''
        from warnings import warn
        warn("'get_ip_reputations' is deprecated", DeprecationWarning)
        return await self.post_sage('download_v1/ip_reputation', {})

    async def get_domain_reputations(self) -> Any:
        '''Returns a list of all domain reputations used by the threat
        intelligence service.
        '''
        from warnings import warn
        warn("'get_domain_reputations' is deprecated", DeprecationWarning)
        return await self.post_sage('download_v1/domain_reputation', {})
# endregion

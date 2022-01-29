from typing import Any
from ipaddress import ip_address
from pathlib import Path
from os import PathLike
import hashlib

from ._typing import CybereasonProtocol


class ThreatIntelligenceMixin(CybereasonProtocol):
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
        return await self.post('classification_v1/file_batch', data)

    async def get_domain_reputation(self, domain: str) -> Any:
        '''Returns details on domain reputations based on the threat
        intelligence service.
        '''
        data = {'requestData': [{'requestKey': {'domain': domain}}]}
        return await self.post('classification_v1/domain_batch', data)

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
        return await self.post('classification_v1/ip_batch', data)

    async def get_product_classifications(self):
        '''Returns details on product classifications based on the
        threat intelligence service. This is used to identify the
        application type based on the product name and process
        image file signature.
        '''
        return await self.post('download_v1/productClassifications', {})

    async def get_process_classifications(self):
        '''Returns details on process classifications based on the
        threat intelligence service. This is used by to identify the
        application type based on the process name, process image file
        signature, process image file path and description, product
        name, and company name for the product.
        '''
        return await self.post('download_v1/process_classification', {})

    async def get_process_hierarchies(self):
        '''Returns details on process hierarchy based on the threat
        intelligence service. This is used to identify the expected
        hierarchy of operating system processes.
        '''
        return await self.post('download_v1/process_hierarchy', {})

    async def get_file_extensions_details(self):
        '''Returns details on file extensions based on the threat
        intelligence service. This is used to classify files and
        processes based on the extension of the file.
        '''
        return await self.post('download_v1/file_extension', {})

    async def get_ports_details(self):
        '''Returns details on ports based on the threat intelligence
        service. This is used to classify communications based on the
        port of the connection.
        '''
        return await self.post('download_v1/port', {})

    async def get_collections_details(self):
        '''Returns details on collections of reference information used
        by the threat intelligence service.
        '''
        return await self.post('download_v1/const', {})

    async def check_reputation_update(self, resource: str):
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
        return await self.post(f'download_v1/{resource}/service', {})

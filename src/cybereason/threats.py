from ipaddress import ip_address


class ThreatIntelligenceMixin:
    async def get_ip_threats(self, ip):
        '''Returns details on IP address reputations based on the
        Cybereason threat intelligence service.
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

    async def get_product_classifications(self):
        '''Returns details on product classifications based on the
        threat intelligence service. This information is used to
        identify the application type based on the product name and
        process image file signature.
        '''
        return await self.post('download_v1/productClassifications', {})

    async def get_process_classifications(self):
        '''Returns details on process classifications based on the
        threat intelligence service. This information is used by to
        identify the application type based on the process name,
        process image file signature, process image file path and
        description, product name, and company name for the product.
        '''
        return await self.post('download_v1/process_classification', {})

    async def get_process_hierarchies(self):
        '''Returns details on process hierarchy based on the threat
        intelligence service. This is used to identify the expected
        hierarchy of operating system processes.
        '''
        return await self.post('download_v1/process_hierarchy', {})

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

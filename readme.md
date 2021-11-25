# Cybereason

> Unofficial Cybereason API client  
> __(Work in progress)__

## Examples

### Save metadata and config for every policy
```python
from cybereason import Cybereason
import asyncio
import json


async def dump_policies_config():
    '''Save metadata and config for every policy.
    '''
    async with Cybereason(<organization>, <username>, <password>) as client:
        async for policy in client.get_policies(show_config=True):
            filename = f'{policy["metadata"]["name"]}.json'
            with open(filename, 'w') as f:
                json.dump(policy, f, indent=4)

asyncio.run(dump_policies_config())
```

### Download all malop syslogs (via script)
```python
#!/usr/bin/env python3 -m asyncio

# this shebang is only available since Python 3.8
# for earlier versions use the asyncio.run approach

from cybereason import Cybereason

async with Cybereason(<organization>, <username>, <password>) as client:
    for server in await client.get_detection_servers():
        path = await client.download_malop_syslog(server['id'], '.')
        print(f'{server["serverName"]} malop syslog was saved in {path.absolute()}')
```

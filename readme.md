# Cybereason

> Unofficial Cybereason API client  
> __(Work in progress)__

## Example

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


# Cybereason

> Async Cybereason API client


## Installation

<a href="https://pypi.org/project/cybereason/"><pre>
pip install cybereason
</pre></a>

Run `pip install cybereason[zip]` to enable on-the-fly extraction of files
downloaded from sensors.

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

### Download and parse into JSON all user audit logs (action log)
```python
from cybereason import Cybereason
import asyncio
import json

async def user_audit():
    async with Cybereason(<organization>, <username>, <password>) as client:
        # rotated=False to get only the latest logs
        logs = [log async for log in client.get_user_audit_logs(rotated=True)]
        with open('user_audit.json', 'w') as f:
            json.dump(logs, f, indent=4)

asyncio.run(user_audit())
```

---

Copyright &copy; 2021-2022 [Forensic & Security](https://forensic-security.com/)

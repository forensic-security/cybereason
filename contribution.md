# Contribution

```sh
git clone https://github.com/forensic-security/cybereason
cd cybereason
python3 -m venv .venv
. .venv/bin/activate
pip install .[dev]  # maybe [dev,socks]
```

To test your contributions, please follow these steps from the project root dir:

```sh
# linting
flake8

# static anlysis
mypy src/cybereason

# testing
export CYBEREASON_TENANT=<tenant>
export CYBEREASON_USERNAME=<username>
export CYBEREASON_PASSWORD=<password>
# export also CYBEREASON_PROXY if needed
pytest
```

> Please note that the purpose of most of the tests is to investigate and document
> the Cybereason's API and data model, so testing errors are more likely to require
> an update of either the models or the endpoints than a code change.

## Caveats
- `nest_asyncio`

   Needed to _unasync_ some properties (like in `SystemMixin.version`) through nested
   loop events. This feature was initially rejected by GvR but [there is a chance that
   it will be implemented][1]. Remove the dependency if this is the case.
  
- `socksio`

   Used due to a [bug in the `httpx`'s implementation of SOCKS5][2]. Change it when resolved.


[1]: https://bugs.python.org/issue22239
[2]: https://github.com/encode/httpx/discussions/2305

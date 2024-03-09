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
ruff check .

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

## Versioning
This library follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Please, follow this specification and tag the commit appropriately.

```sh
git tag -a vX.Y.Z -m "vX.Y.Z"
git push --follow-tags
```

## Caveats
- `socksio`

   Used due to a [bug in the `httpx`'s implementation of SOCKS5][2]. Change it when resolved.

- `ruff`

   Don't run `ruff format` until [docstrings with single quotes are allowed][3].

[1]: https://bugs.python.org/issue22239
[2]: https://github.com/encode/httpx/discussions/2305
[3]: https://github.com/astral-sh/ruff/issues/7615

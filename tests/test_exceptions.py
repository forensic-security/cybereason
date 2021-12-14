from cybereason.exceptions import authz, min_version
import pytest


class Test:
    version = 0, 1

    @authz('')
    @min_version(0, 0)
    async def asyncgen(self):
        yield True

    @min_version(0, 0)
    @authz('')
    async def asynccorofunc(self):
        return True


@pytest.mark.asyncio
async def test_decorators():
    test = Test()

    r = [i async for i in test.asyncgen()]
    assert r == [True]

    r = await test.asynccorofunc()
    assert r == True

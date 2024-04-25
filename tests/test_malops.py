from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from .conftest import aenumerate


@pytest_asyncio.fixture(scope='module')
async def malops(client, validate):
    '''Also tests get_malops.
    '''
    start = datetime.now(tz=timezone.utc) - timedelta(days=30)
    resp = await client.get_malops(start)
    validate(resp, 'malops')
    return resp


@pytest.mark.asyncio
async def test_get_malop_status(client, malops, validate):
    guids = [x['guid'] for x in malops[:50]]
    tasks = (client.get_malop_status(i) for i in guids)
    resp = await client.gather_limit(5, *tasks)
    for status in resp:
        validate(status, 'status')


@pytest.mark.asyncio
async def test_get_malops_v2(client, validate):
    malops = list()
    start = datetime.now(tz=timezone.utc) - timedelta(days=30)

    async for i, alert in aenumerate(client.get_malops_v2(start)):
        malops.append(alert)
        if i > 100:
            break

    validate(malops, 'malops_v2')


@pytest.mark.asyncio
async def test_get_malware(client, validate):
    malware = list()

    async for i, alert in aenumerate(client.get_malware_alerts()):
        malware.append(alert)
        if i > 100:
            break

    validate(malware, 'malware')


# region LABELS
LABEL = 'TEST_LABEL'


@pytest_asyncio.fixture(scope='module')
async def label_test(client):
    '''Also tests creation and deleting of labels.
    '''
    label = await client.add_malops_label(LABEL)
    assert label['labelText'] == LABEL
    yield label
    resp = await client.delete_malops_label(label['id'])
    assert resp is True


@pytest.mark.asyncio
async def test_get_labels(client, label_test):
    labels = await client.get_malops_labels()
    for label in labels:
        if label == label_test:
            break
    else:
        raise Exception(f'Label {LABEL!r} not found.')


@pytest.mark.asyncio
async def test_update_label(client):
    pass  # TODO
# endregion

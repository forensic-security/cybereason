import pytest
import pytest_asyncio


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

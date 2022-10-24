import pytest

from .conftest import SCHEMAS, MismatchingDataModel, NotEnoughData


# region LISTS
@pytest.mark.asyncio
async def test_get_product_classifications(client):
    resp = await client.get_product_classifications()

    try:
        assert resp[0].keys() == {'key', 'value'}
        assert resp[0]['key'].keys() == {'name'}
        assert resp[0]['value'].keys() == {'signer', 'type', 'title'}
    except (AssertionError, AttributeError):
        raise MismatchingDataModel
    except IndexError:
        raise NotEnoughData


@pytest.mark.datafiles(SCHEMAS / 'threat-intel.json')
@pytest.mark.asyncio
async def test_get_collections_details(datafiles, client):
    import json
    schema = json.loads(datafiles.read_text())
    resp = await client.get_collections_details()

    try:
        assert resp[0].keys() == {'key', 'value'}
        assert resp[0]['key'].keys() == {'name'}
        assert resp[0]['value'].keys() == {'data'}
    except (AssertionError, AttributeError):
        raise MismatchingDataModel
    except IndexError:
        raise NotEnoughData
# endregion

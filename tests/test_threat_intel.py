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


@pytest.mark.asyncio
async def test_get_collections_details(client, validate):
    resp = await client.get_collections_details()
    validate(resp, 'collections_details')
# endregion

import pytest


# region LISTS
@pytest.mark.asyncio
async def test_get_product_classifications(client, validate):
    resp = await client.get_product_classifications()
    validate(resp, 'product_classifications')


@pytest.mark.asyncio
async def test_get_collections_details(client, validate):
    resp = await client.get_collections_details()
    validate(resp, 'collections_details')


# TODO
# @pytest.mark.asyncio
# async def test_get_custom_reputations(client, validate):
#     resp = [x async for x in client.get_custom_reputations()]
#     validate(resp, 'reputations')
# endregion

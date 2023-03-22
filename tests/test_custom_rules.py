import pytest


@pytest.mark.asyncio
async def test_get_active_custom_rules(client, validate):
    resp = await client.get_active_custom_rules()
    validate(resp, 'custom_rules')

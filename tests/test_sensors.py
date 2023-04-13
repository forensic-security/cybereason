import pytest

from .conftest import aenumerate


@pytest.mark.asyncio
async def test_get_sensors(client, validate):
    sensors = [s async for s in client.get_sensors()]
    validate(sensors, 'sensors')


@pytest.mark.asyncio
async def test_get_malware_alerts(client, validate):
    alerts = list()

    async for i, alert in aenumerate(client.get_malware_alerts()):
        alerts.append(alert)
        if i > 100:
            break

    validate(alerts, 'malware_alerts')


@pytest.mark.asyncio
async def test_get_policies(client, validate):
    # TODO: validate `show_config=False`
    policies = [x async for x in client.get_policies(show_config=True)]
    validate(policies, 'policies')


@pytest.mark.asyncio
async def test_get_groups(client, validate):
    groups = await client.get_groups()
    validate(groups, 'groups')

import pytest
from .conftest import NotEnoughData


@pytest.mark.asyncio
async def test_get_sensors(event_loop, client, log):
    async def test():
        async for sensor in client.get_sensors():
            log.info('SENSOR %s', sensor)  # TODO
            break
        else:
            raise NotEnoughData

    event_loop.run_until_complete(test())


@pytest.mark.asyncio
async def test_get_malware_alters(client, log):
    async for alert in client.get_malware_alerts():
        log.info('ALERT %s', alert)  # TODO
        break
    else:
        raise NotEnoughData

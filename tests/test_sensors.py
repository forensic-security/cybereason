import pytest

from .conftest import MismatchingDataModel, NotEnoughData, aenumerate


@pytest.mark.asyncio
async def test_get_sensors(event_loop, client, log):
    async def test():
        async for sensor in client.get_sensors():
            try:
                assert sensor.keys() == {
                    'actionsInProgress', 'amModeOrigin', 'amStatus', 'antiExploitStatus',
                    'antiMalwareModeOrigin', 'antiMalwareStatus', 'archiveTimeMs',
                    'archivedOrUnarchiveComment', 'avDbLastUpdateTime', 'avDbVersion',
                    'collectionComponents', 'collectionStatus', 'collectiveUuid', 'compliance',
                    'consoleVersion', 'cpuUsage', 'criticalAsset', 'customTags', 'deliveryTime',
                    'department', 'deviceModel', 'deviceType', 'disconnected', 'disconnectionTime',
                    'documentProtectionMode', 'documentProtectionStatus', 'exitReason',
                    'externalIpAddress', 'firstSeenTime', 'fqdn', 'fullScanStatus', 'fwStatus',
                    'groupId', 'groupName', 'groupStickiness', 'groupStickinessLabel', 'guid',
                    'internalIpAddress', 'isolated', 'lastFullScheduleScanSuccessTime',
                    'lastPylumInfoMsgUpdateTime', 'lastPylumUpdateTimestampMs',
                    'lastQuickScheduleScanSuccessTime', 'lastStatusAction', 'lastUpgradeResult',
                    'lastUpgradeSteps', 'location', 'machineName', 'memoryUsage', 'offlineTimeMS',
                    'onlineTimeMS', 'organization', 'organizationalUnit', 'osType', 'osVersionType',
                    'outdated', 'pendingActions', 'policyId', 'policyName', 'powerShellStatus',
                    'preventionError', 'preventionStatus', 'privateServerIp', 'proxyAddress',
                    'purgeTimestamp', 'purgedSensors', 'pylumId', 'quickScanStatus',
                    'ransomwareStatus', 'remoteShellStatus', 'sensorArchivedByUser', 'sensorId',
                    'sensorLastUpdate', 'sensorPurgedByUser', 'serialNumber', 'serverId',
                    'serverIp', 'serverName', 'serviceStatus', 'siteId', 'siteName',
                    'staleTimeMS', 'staticAnalysisDetectMode', 'staticAnalysisDetectModeOrigin',
                    'staticAnalysisPreventMode', 'staticAnalysisPreventModeOrigin', 'status',
                    'statusTimeMS', 'upTime', 'usbStatus', 'version',
                }
            except AssertionError:
                raise MismatchingDataModel
            break
        else:
            raise NotEnoughData

    event_loop.run_until_complete(test())


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
    import json
    with open('policies.json', 'w', encoding='utf-8') as f:
        f.write(json.dumps(policies, indent=4, ensure_ascii=False))

    validate(policies, 'policies')

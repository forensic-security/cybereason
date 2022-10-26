import pytest

from .conftest import MismatchingDataModel, NotEnoughData


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

    async for alert in client.get_malware_alerts():
        alerts.append(alert)
        if len(alerts) > 100:
            break
    else:
        if not alerts:
            raise NotEnoughData

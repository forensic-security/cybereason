import pytest

from .conftest import MismatchingDataModel, NotEnoughData


def _test_custom_rule(obj):
    assert obj.keys() == {'parentId', 'root', 'malopActivityType'}


# FIXME: breaks on 22.1
# @pytest.mark.asyncio
# async def test_get_active_custom_rules(client):
#     resp = await client.get_active_custom_rules()
#
#     try:
#         assert resp[0].keys() == {
#             'id', 'name', 'rootCause', 'malopDetectionType', 'rule', 'description',
#             'groupingFeatures', 'enabled', 'userName', 'creationTime', 'updateTime',
#             'lastTriggerTime', 'autoRemediationActions', 'autoRemediationErrorMessage',
#         }
#         _test_custom_rule(resp[0]['rule'])
#     except (AssertionError, AttributeError):
#         raise MismatchingDataModel
#     except IndexError:
#         raise NotEnoughData

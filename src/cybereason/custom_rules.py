from typing import TYPE_CHECKING

from .exceptions import ResourceNotFoundError, authz
from ._typing import CybereasonProtocol

if TYPE_CHECKING:
    from typing import Any, Dict, List


class CustomRulesMixin(CybereasonProtocol):
    async def get_active_custom_rules(self) -> 'List[Dict[str, Any]]':
        '''Retrieve a list of all active custom detection rules.
        '''
        resp = await self.get('customRules/decisionFeature/live')
        # TODO: resp['limitExceed']: bool ?
        return resp['rules']

    async def get_disabled_custom_rules(self) -> 'List[Dict[str, Any]]':
        '''Returns a list of all custom rules currently disabled in your
        environment.
        '''
        return await self.get('customRules/decisionFeature/deleted')

    async def get_root_causes(self) -> 'List[str]':
        '''Returns a list of all Elements you can use for a root cause
        for a Malop generated from this custom rule.
        '''
        return await self.get('customRules/rootCauses')

    @authz('L3 Analyst')
    async def get_malop_detection_types(self) -> 'List[Dict[str, str]]':
        '''Returns a list of all available detection types you can use
        for custom detection rules.
        '''
        return await self.get('customRules/getMalopDetectionTypes')

    @authz('L3 Analyst')
    async def get_malop_activity_types(self) -> 'List[Dict[str, str]]':
        '''Returns a list of all available Malop activity types you can
        use for custom detection rules.
        '''
        return await self.get('customRules/getMalopActivityTypes')

    # TODO
    async def create_custom_rule(self, data):
        '''Creates a custom detection rule.

        .. warning::
            Custom detection rules should be created only after adequate
            research regarding precision and coverage has been completed.
            Creating a custom detection rule that is not specific enough
            can have detrimental impact on retention and overall
            performance of the environment.
        '''
        return await self.post('customRules/decisionFeature/create', data)

    # TODO
    async def update_custom_rule(self, data):
        '''Updates an existing custom detection rule.
        '''
        return await self.post('customRules/decisionFeature/update', data)

    async def get_custom_rule_history(self, rule_id) -> 'List[Dict[str, Any]]':
        resp = await self.get(f'customRules/history/{rule_id}')
        if not resp['history']:
            raise ResourceNotFoundError(rule_id)
        return resp['history']

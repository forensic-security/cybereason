from typing import TYPE_CHECKING

from .exceptions import ResourceNotFoundError, authz
from ._typing import CybereasonProtocol

if TYPE_CHECKING:
    from typing import Any, Dict, List, Optional


class CustomRulesMixin(CybereasonProtocol):
    # FIXME: breaks on 22.1
    async def get_active_custom_rules(self) -> 'List[Dict[str, Any]]':
        '''Retrieve a list of all active custom detection rules.
        '''
        resp = await self.get('v2/customRules/decisionFeature/live')
        # TODO: resp['limitExceed']: bool ?
        return resp['rules']

    async def get_disabled_custom_rules(self) -> 'List[Dict[str, Any]]':
        '''Returns a list of all custom rules currently disabled in your
        environment.
        '''
        return await self.get('v2/customRules/decisionFeature/deleted')

    async def get_root_causes(self) -> 'List[str]':
        '''Returns a list of all Elements you can use for a root cause
        for a Malop generated from this custom rule.
        '''
        return await self.get('v2/customRules/rootCauses')

    @authz('L3 Analyst')
    async def get_malop_detection_types(self) -> 'List[Dict[str, str]]':
        '''Returns a list of all available detection types you can use
        for custom detection rules.
        '''
        return await self.get('v2/customRules/getMalopDetectionTypes')

    @authz('L3 Analyst')
    async def get_malop_activity_types(self) -> 'List[Dict[str, str]]':
        '''Returns a list of all available Malop activity types you can
        use for custom detection rules.
        '''
        return await self.get('v2/customRules/getMalopActivityTypes')

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
        return await self.post('v2/customRules/decisionFeature/create', data)

    # TODO
    async def update_custom_rule(self, data):
        '''Updates an existing custom detection rule.
        '''
        return await self.post('v2/customRules/decisionFeature/update', data)

    async def get_custom_rule_history(self, rule_id: int) -> 'List[Dict[str, Any]]':
        resp = await self.get(f'v2/customRules/history/{rule_id}')
        if not resp['history']:
            raise ResourceNotFoundError(rule_id)
        return resp['history']


class IsolationRulesMixin(CybereasonProtocol):

    async def get_isolation_rules(self) -> 'List[Dict[str, Any]]':
        '''Retrieves a list of isolation rules.
        '''
        return await self.get('settings/isolation-rule')

    async def get_isolation_rule(self, id) -> 'Dict[str, Any]':
        rules = await self.get_isolation_rules()
        try:
            return [r for r in rules if r['ruleId'] == id][0]
        except IndexError:
            raise ResourceNotFoundError(id) from None

    async def create_isolation_rule(
        self,
        direction: str,
        blocking:  bool,
        ip:        str,  # TODO: validate
        port:      'Optional[int]' = None,
    ) -> 'Dict[str, Any]':
        '''
        Args:
            direction: The direction of the allowed communication.
                {'ALL', 'OUTGOING', 'INCOMING'}
            blocking: States whether communication with the given IP or
                port is allowed. If ``True`` communication is blocked.
            ip: The IP address of the machine to which the rule applies.
            port: The port by which Cybereason communicates with an
                isolated machine, according to the rule.
        '''
        rule = {
            'ruleId':          None,
            'port':            port or '',
            'ipAddressString': ip,
            'blocking':        blocking,
            'direction':       direction,
        }
        return await self.post('settings/isolation-rule', rule)

    async def update_isolation_rule(
        self,
        id:           str,
        *, direction: 'Optional[str]' = None,
        blocking:     'Optional[bool]' = None,
        ip:           'Optional[str]' = None,
        port:         'Optional[int]' = None,
    ) -> 'Dict[str, Any]':
        '''
        Args:
            id: rule ID.
            port: ``0`` means any port.
        '''
        rule = await self.get_isolation_rule(id)
        if direction is not None:
            rule['direction'] = direction
        if blocking is not None:
            rule['blocking'] = blocking
        if ip is not None:
            rule['ipAddressString'] = ip or ''
        if port is not None:
            rule['port'] = port

        return await self.put('settings/isolation-rule', rule)

    async def delete_isolation_rule(self, id: str) -> None:
        '''Deletes an isolation exception rule.
        '''
        rule = await self.get_isolation_rule(id)
        await self.post('settings/isolation-rule/delete', rule)

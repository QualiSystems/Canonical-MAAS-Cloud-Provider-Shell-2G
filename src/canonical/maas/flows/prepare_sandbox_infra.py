from http import HTTPStatus

from cloudshell.cp.core.models import DriverResponse, PrepareCloudInfra, PrepareCloudInfraResult, PrepareSubnet, \
    PrepareSubnetActionResult, CreateKeys, CreateKeysActionResult
from cloudshell.cp.core.utils import single
from maas.client.bones import CallError

from canonical.maas.flows import MaasDefaultSubnetFlow


class MaasPrepareSandboxInfraFlow(MaasDefaultSubnetFlow):
    def _get_or_create_fabric(self, name):
        """

        :param name:
        :return:
        """
        try:
            return self._maas_client.fabrics.get(name)
        except CallError as e:
            if e.status == HTTPStatus.NOT_FOUND:
                return self._maas_client.fabrics.create(name=name)
            raise

    def _get_or_create_subnet(self, name, cidr, gateway_ip, vlan, managed):
        """

        :param name:
        :param cidr:
        :param gateway_ip:
        :param vlan:
        :param managed:
        :return:
        """
        try:
            return self._maas_client.subnets.get(name)
        except CallError as e:
            if e.status == HTTPStatus.NOT_FOUND:
                return self._maas_client.subnets.create(cidr=cidr,
                                                        name=name,
                                                        vlan=vlan,
                                                        gateway_ip=gateway_ip or None,
                                                        managed=managed)
            raise

    def prepare(self, request, sandbox_id):
        """

        :param request:
        :param sandbox_id:
        :return:
        """
        fabric = self._get_or_create_fabric(name=self.get_default_fabric_name(sandbox_id))

        self._get_or_create_subnet(name=self.get_default_subnet_name(sandbox_id),
                                   cidr=self._resource_config.default_subnet,
                                   gateway_ip=self._resource_config.default_gateway,
                                   vlan=fabric.vlans[0],
                                   managed=self._resource_config.managed_allocation)

        actions = self._request_parser.convert_driver_request_to_actions(request)

        # ignore prepare infra actions
        prep_network_action = single(actions, lambda x: isinstance(x, PrepareCloudInfra))
        prep_network_action_result = PrepareCloudInfraResult(prep_network_action.actionId)

        prep_subnet_action = single(actions, lambda x: isinstance(x, PrepareSubnet))
        prep_subnet_action_result = PrepareSubnetActionResult(prep_subnet_action.actionId)

        # todo create the ssh key and return to cloudshell ?
        access_keys_action = single(actions, lambda x: isinstance(x, CreateKeys))
        access_keys_action_results = CreateKeysActionResult(access_keys_action.actionId)

        action_results = [prep_network_action_result, prep_subnet_action_result, access_keys_action_results]

        return DriverResponse(action_results).to_driver_response_json()

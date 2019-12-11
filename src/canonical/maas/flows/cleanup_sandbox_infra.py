from http import HTTPStatus

from cloudshell.cp.core.models import CleanupNetwork, CleanupNetworkResult, DriverResponse
from cloudshell.cp.core.utils import single
from maas.client.bones import CallError

from canonical.maas.flows import MaasDefaultSubnetFlow


class MaasCleanupSandboxInfraFlow(MaasDefaultSubnetFlow):
    def _delete_fabric(self, name):
        """

        :param name:
        :return:
        """
        try:
            fabric = self._maas_client.fabrics.get(name)
        except CallError as e:
            if e.status == HTTPStatus.NOT_FOUND:
                return
            raise

        fabric.delete()

    def _delete_subnet(self, name):
        """

        :param name:
        :return:
        """
        try:
            subnet = self._maas_client.subnets.get(name)
        except CallError as e:
            if e.status == HTTPStatus.NOT_FOUND:
                return
            raise

        subnet.delete()

    def cleanup(self, request, sandbox_id):
        """

        :param request:
        :param sandbox_id:
        :return:
        """
        self._delete_subnet(name=self.get_default_subnet_name(sandbox_id))
        self._delete_fabric(name=self.get_default_fabric_name(sandbox_id))

        actions = self._request_parser.convert_driver_request_to_actions(request)
        cleanup_action = single(actions, lambda x: isinstance(x, CleanupNetwork))

        action_result = CleanupNetworkResult(cleanup_action.actionId)

        return DriverResponse([action_result]).to_driver_response_json()

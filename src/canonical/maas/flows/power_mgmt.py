import json

from canonical.maas.flows import BaseMaasFlow


class MaasPowerManagementFlow(BaseMaasFlow):
    def _get_vm_uid(self, resource):
        """

        :param resource:
        :return:
        """
        deployed_app_dict = json.loads(resource.app_context.deployed_app_json)
        return deployed_app_dict['vmdetails']['uid']

    def power_on(self, resource):
        """

        :param resource:
        :return:
        """
        vm_uid = self._get_vm_uid(resource)
        machine = self._maas_client.machines.get(vm_uid)
        machine.power_on(wait=True)

    def power_off(self, resource):
        """

        :param resource:
        :return:
        """
        vm_uid = self._get_vm_uid(resource)
        machine = self._maas_client.machines.get(vm_uid)
        machine.power_off(wait=True)

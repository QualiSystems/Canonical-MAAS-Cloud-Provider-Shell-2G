from canonical.maas.flows import MaasDeployedVMFlow


class MaasPowerManagementFlow(MaasDeployedVMFlow):
    def power_on(self, resource):
        """

        :param resource:
        :return:
        """
        machine = self._get_machine(resource)
        machine.power_on(wait=True)

    def power_off(self, resource):
        """

        :param resource:
        :return:
        """
        machine = self._get_machine(resource)
        machine.power_off(wait=True)

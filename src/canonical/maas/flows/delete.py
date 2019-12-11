from canonical.maas.flows import MaasDeployedVMFlow


class MaasDeleteFlow(MaasDeployedVMFlow):
    def delete(self, resource):
        """

        :param resource:
        :return:
        """
        machine = self._get_machine(resource)
        machine.release()
        # delete link to default subnet
        machine.interfaces[0].delete()

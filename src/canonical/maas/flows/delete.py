from canonical.maas.flows import MaasDeployedVMFlow


class MaasDeleteFlow(MaasDeployedVMFlow):
    def delete(self, resource):
        """

        :param resource:
        :return:
        """
        machine = self._get_machine(resource)
        machine.release()
        # delete link to default fabric and subnet
        try:
            iface = machine.interfaces[0]
            iface.disconnect()
        except IndexError:
            pass

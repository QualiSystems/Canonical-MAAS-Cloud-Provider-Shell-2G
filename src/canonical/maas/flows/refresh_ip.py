from canonical.maas.flows import MaasDefaultSubnetFlow
from canonical.maas.flows import MaasDeployedVMFlow


class MaasRemoteRefreshIPFlow(MaasDeployedVMFlow, MaasDefaultSubnetFlow):
    def __init__(self, resource_config, cs_api, logger):
        """

        :param resource_config:
        :param cs_api:
        :param logger:
        """
        super().__init__(resource_config, logger)
        self._cs_api = cs_api

    def _find_ip_address(self, machine):
        """

        :param machine:
        :return:
        """
        for iface in machine.interfaces:
            for link in iface.links:
                if link.subnet.name == self.DEFAULT_SUBNET_NAME:
                    return link.ip_address

    def _get_ip_address(self, machine):
        """

        :param machine:
        :return:
        """
        ip_address = self._find_ip_address(machine)

        if not ip_address:
            raise Exception("Unable to retrieve IP Address")

        return ip_address

    def refresh_ip(self, resource):
        """

        :param resource:
        :return:
        """
        machine = self._get_machine(resource)
        ip_address = self._get_ip_address(machine)

        self._cs_api.UpdateResourceAddress(resourceFullPath=resource.name,
                                           resourceAddress=ip_address)

        return ip_address
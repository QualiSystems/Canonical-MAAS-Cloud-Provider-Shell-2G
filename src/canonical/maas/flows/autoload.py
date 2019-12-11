from cloudshell.shell.core.driver_context import AutoLoadDetails

from canonical.maas.flows import BaseMaasFlow


class MaasAutoloadFlow(BaseMaasFlow):
    def discover(self):
        """

        :return:
        """
        return AutoLoadDetails([], [])

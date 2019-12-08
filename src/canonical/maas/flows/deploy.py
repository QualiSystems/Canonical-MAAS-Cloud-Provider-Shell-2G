from cloudshell.cp.core.drive_request_parser import DriverRequestParser
from cloudshell.cp.core.models import DriverResponse, DeployApp, CleanupNetwork, DeployAppResult
from cloudshell.cp.core.utils import single

from maas.client.enum import NodeStatus

from canonical.maas.flows import BaseMaasFlow


class MaasDeployFlow(BaseMaasFlow):
    def __init__(self, resource_config, logger):
        """

        :param resource_config:
        :param logger:
        """
        super().__init__(resource_config, logger)
        self._request_parser = DriverRequestParser()

    def _get_free_machine(self, cpus, memory, disks, storage=None):
        """

        :param cpus:
        :param memory:
        :param disks:
        :param storage:
        :return:
        """
        available_machines = list(filter(lambda machine: all([machine.status == NodeStatus.READY,
                                                              cpus <= machine.cpus,
                                                              memory <= machine.memory / 1024,
                                                              disks <= len(machine.block_devices)]),
                                         self._maas_client.machines.list()))

        available_machines = sorted(available_machines, key=lambda machine: (machine.cpus,
                                                                             machine.memory,
                                                                             len(machine.block_devices)))

        if not available_machines:
            raise Exception(f"There are no free machine for the given params: "
                            f"CPU Cores: {cpus}, "
                            f"RAM GiB: {memory},"
                            f"Disks: {disks}, "
                            f"Storage GB: {storage}")

        return available_machines[0]


    def deploy(self, request):
        """

        :param request:
        :return:
        """
        actions = self._request_parser.convert_driver_request_to_actions(request)
        deploy_action = single(actions, lambda x: isinstance(x, DeployApp))
        attrs = deploy_action.actionParams.deployment.attributes

        machine = self._get_free_machine(cpus=int(attrs["Maas.Machine.CPU Cores"]),
                                         memory=float(attrs["Maas.Machine.RAM GiB"]),
                                         disks=int(attrs["Maas.Machine.Disks"]),
                                         storage=float(attrs["Maas.Machine.Storage GB"]))

        operating_system = attrs["Maas.Machine.Operation System"]
        machine.deploy(distro_series=operating_system, wait=True)

        deploy_result = DeployAppResult(deploy_action.actionId,
                                        vmUuid=machine.system_id,
                                        vmName=operating_system,
                                        vmDetailsData=None,
                                        deployedAppAdditionalData={})

        return DriverResponse([deploy_result]).to_driver_response_json()

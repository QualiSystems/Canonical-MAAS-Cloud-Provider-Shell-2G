from cloudshell.cp.core.models import DriverResponse, DeployApp, CleanupNetwork, DeployAppResult
from cloudshell.cp.core.utils import single
from maas.client.enum import NodeStatus, LinkMode

from canonical.maas.flows import MaasDefaultSubnetFlow


class MaasDeployFlow(MaasDefaultSubnetFlow):
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

    def _reconnect_machine_to_sandbox_subnet(self, machine, sandbox_id):
        """

        :param machine:
        :param sandbox_id:
        :return:
        """
        try:
            iface = machine.interfaces[0]
        except KeyError:
            raise Exception("Unable to connect machine to default subnet. No interface on machine")

        mac_address = iface.mac_address
        # delete old interface
        iface.delete()

        # get VLAN from the default subnet
        subnet_name = self.get_default_subnet_name(sandbox_id)
        subnet = self._maas_client.subnets.get(subnet_name)
        vlan = subnet.vlan

        # create new interface with saved mac_address
        iface = machine.interfaces.create(name=f"Quali_{machine.hostname}",
                                          mac_address=mac_address,
                                          vlan=vlan)
        iface.links.create(subnet=subnet,
                           mode=LinkMode.AUTO)

    def deploy(self, request, sandbox_id):
        """

        :param request:
        :param sandbox_id:
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
        # machine.deploy(distro_series=operating_system, wait=True)

        self._reconnect_machine_to_sandbox_subnet(machine=machine,
                                                  sandbox_id=sandbox_id)

        deploy_result = DeployAppResult(deploy_action.actionId,
                                        vmUuid=machine.system_id,
                                        vmName=operating_system,
                                        vmDetailsData=None,
                                        deployedAppAdditionalData={})

        return DriverResponse([deploy_result]).to_driver_response_json()

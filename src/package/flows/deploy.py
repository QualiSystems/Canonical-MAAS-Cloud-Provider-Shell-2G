from maas.client import login
from maas.client.enum import NodeStatus


class MaasDeployFlow:
    def __init__(self, resource_config):
        self._resource_config = resource_config
        self._maas_client = self._get_maas_client(resource_config)

    def _get_maas_client(self, resource_config):
        """

        :param resource_config:
        :return:
        """
        return login(
            f"{resource_config.api_scheme}://{resource_config.address}:{resource_config.api_port}/MAAS/",
            username=resource_config.api_user,
            password=resource_config.api_password,
            insecure=True,
        )

    def _get_free_machine(self, cpus, memory, disks, storage=None):
        """

        :param client:
        :param cpus:
        :param memory:
        :param disks:
        :param storage:
        :return:
        """
        # todo: sort possible machines for cpus/memory?
        for machine in self._maas_client.machines.list():
            if all([machine.status == NodeStatus.READY,
                    cpus <= machine.cpus,
                    memory <= machine.memory / 1024,
                    disks <= len(machine.block_devices)]):
                return machine

        raise Exception(f"There are no free machine for the given params: "
                        f"CPU Cores: {cpus}, "
                        f"RAM GiB: {memory},"
                        f"Disks: {disks}, "
                        f"Storage GB: {storage}")

    def _deploy_machine(self, os_system, cpus, memory, disks, storage):
        """

        :param os_system:
        :param cpus:
        :param memory:
        :param disks:
        :param storage:
        :return:
        """
        machine = self._get_free_machine(cpus=cpus,
                                         memory=memory,
                                         disks=disks,
                                         storage=storage)

        machine.deploy(distro_series=os_system, wait=True)

        return machine.system_id

    def deploy(self, os_system, cpus, memory, disks, storage):
        """

        :param os_system:
        :param cpus:
        :param memory:
        :param disks:
        :param storage:
        :return:
        """
        machine = self._get_free_machine(cpus=cpus,
                                         memory=memory,
                                         disks=disks,
                                         storage=storage)

        machine.deploy(distro_series=os_system, wait=True)

        return machine.system_id

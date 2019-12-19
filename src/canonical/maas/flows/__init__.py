import json

from cloudshell.cp.core.drive_request_parser import DriverRequestParser
from maas.client import login


class BaseMaasFlow:
    def __init__(self, resource_config, logger):
        """

        :param resource_config:
        :param logger:
        """
        self._resource_config = resource_config
        self._logger = logger
        self._maas_client = self._get_maas_client(resource_config)

    def _get_maas_client(self, resource_config):
        """

        :param resource_config:
        :return:
        """
        self._logger.info("Initializing MAAS API client...")

        return login(
            f"{resource_config.api_scheme}://{resource_config.address}:{resource_config.api_port}/MAAS/",
            username=resource_config.api_user,
            password=resource_config.api_password,
            insecure=True,
        )


class MaasDeployedVMFlow(BaseMaasFlow):
    def _get_vm_uid(self, resource):
        """

        :param resource:
        :return:
        """
        deployed_app_dict = json.loads(resource.app_context.deployed_app_json)
        return deployed_app_dict['vmdetails']['uid']

    def _get_machine(self, resource):
        """

        :param resource:
        :return:
        """
        vm_uid = self._get_vm_uid(resource)
        return self._maas_client.machines.get(vm_uid)


class MaasDefaultSubnetFlow(BaseMaasFlow):
    DEFAULT_FABRIC_NAME = "Quali_Fabric"
    DEFAULT_SUBNET_NAME = "Quali_Subnet"


class MaasRequestBasedFlow(BaseMaasFlow):
    def __init__(self, resource_config, logger):
        """

        :param resource_config:
        :param logger:
        """
        super().__init__(resource_config, logger)
        self._request_parser = DriverRequestParser()

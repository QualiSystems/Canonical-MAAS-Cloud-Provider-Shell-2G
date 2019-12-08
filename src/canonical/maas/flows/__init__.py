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

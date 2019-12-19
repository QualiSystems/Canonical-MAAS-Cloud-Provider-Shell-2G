from cloudshell.shell.standards.core.resource_config_entities import ResourceAttrRO

from canonical.maas.standards.resource_config_generic_models import GenericApiConfig


class BooleanResourceAttrRO(ResourceAttrRO):
    def __get__(self, instance, owner):
        """

        :param GenericResourceConfig instance:
        :rtype: str
        """
        if instance is None:
            return self

        attr = instance.attributes.get(self.get_key(instance), self.default)
        return attr.lower() == "true"


class MaasResourceConfig(GenericApiConfig):
    default_subnet = ResourceAttrRO(
        "Default Subnet", ResourceAttrRO.NAMESPACE.SHELL_NAME
    )

    default_gateway = ResourceAttrRO(
        "Default Gateway IP", ResourceAttrRO.NAMESPACE.SHELL_NAME
    )

    managed_allocation = BooleanResourceAttrRO(
        "Managed Allocation", ResourceAttrRO.NAMESPACE.SHELL_NAME, default="True"
    )

    ssh_keypair_path = ResourceAttrRO(
        "SSH Keypair Path", ResourceAttrRO.NAMESPACE.SHELL_NAME,
    )



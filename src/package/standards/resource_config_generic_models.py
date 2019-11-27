from cloudshell.shell.standards.core.resource_config_entities import (
    GenericResourceConfig,
    PasswordAttrRO,
    ResourceAttrRO,
)

from package.standards import attribute_names


class GenericApiConfig(GenericResourceConfig):
    api_user = ResourceAttrRO(
        attribute_names.API_USER, ResourceAttrRO.NAMESPACE.SHELL_NAME
    )
    api_password = PasswordAttrRO(
        attribute_names.API_PASSWORD, PasswordAttrRO.NAMESPACE.SHELL_NAME
    )
    api_scheme = ResourceAttrRO(
        attribute_names.API_SCHEME, ResourceAttrRO.NAMESPACE.SHELL_NAME
    )
    api_port = ResourceAttrRO(
        attribute_names.API_PORT, ResourceAttrRO.NAMESPACE.SHELL_NAME
    )

from http import HTTPStatus
import os

from cloudshell.cp.core.models import DriverResponse, PrepareCloudInfra, PrepareCloudInfraResult, PrepareSubnet, \
    PrepareSubnetActionResult, CreateKeys, CreateKeysActionResult
from cloudshell.cp.core.utils import single
from maas.client.bones import CallError
import paramiko

from canonical.maas.flows import MaasDefaultSubnetFlow, MaasRequestBasedFlow


class MaasPrepareSandboxInfraFlow(MaasRequestBasedFlow, MaasDefaultSubnetFlow):
    SSH_PRIVATE_KEY_FILE_NAME = "maas_id_rsa.ppk"
    SSH_PUBLIC_KEY_FILE_NAME = "maas_id_rsa.ppubk"

    @property
    def private_ssh_key_path(self):
        return os.path.join(self._resource_config.ssh_keypair_path, self.SSH_PRIVATE_KEY_FILE_NAME)

    @property
    def public_shh_key_path(self):
        return os.path.join(self._resource_config.ssh_keypair_path, self.SSH_PUBLIC_KEY_FILE_NAME)

    def _get_or_create_fabric(self, name):
        """

        :param name:
        :return:
        """
        try:
            return self._maas_client.fabrics.get(name)
        except CallError as e:
            if e.status == HTTPStatus.NOT_FOUND:
                return self._maas_client.fabrics.create(name=name)
            raise

    def _get_or_create_subnet(self, name, cidr, gateway_ip, vlan, managed):
        """

        :param name:
        :param cidr:
        :param gateway_ip:
        :param vlan:
        :param managed:
        :return:
        """
        try:
            return self._maas_client.subnets.get(name)
        except CallError as e:
            if e.status == HTTPStatus.NOT_FOUND:
                return self._maas_client.subnets.create(cidr=cidr,
                                                        name=name,
                                                        vlan=vlan,
                                                        gateway_ip=gateway_ip or None,
                                                        managed=managed)
            raise

    def _generate_ssh_key_pair(self, bits=1024):
        """

        :param bits:
        :return:
        """
        key = paramiko.RSAKey.generate(bits)
        public_key = f"{key.get_name()} {key.get_base64()}"

        with open(self.private_ssh_key_path, "w+") as f:
            key.write_private_key(f)

        with open(self.public_shh_key_path, "w+") as f:
            f.write(public_key)

        return public_key

    def _ssh_keys_exists(self):
        """

        :rtype: bool
        """
        return all([os.path.exists(self.private_ssh_key_path),
                    os.path.exists(self.public_shh_key_path)])

    def _get_ssh_public_key(self):
        """

        :return:
        """
        with open(self.public_shh_key_path, "r") as f:
            return f.read()

    def prepare(self, request):
        """

        :param request:
        :return:
        """
        fabric = self._get_or_create_fabric(name=self.DEFAULT_FABRIC_NAME)

        self._get_or_create_subnet(name=self.DEFAULT_SUBNET_NAME,
                                   cidr=self._resource_config.default_subnet,
                                   gateway_ip=self._resource_config.default_gateway,
                                   vlan=fabric.vlans[0],
                                   managed=self._resource_config.managed_allocation)

        actions = self._request_parser.convert_driver_request_to_actions(request)
        # ignore prepare infra actions
        prep_network_action = single(actions, lambda x: isinstance(x, PrepareCloudInfra))
        prep_network_action_result = PrepareCloudInfraResult(prep_network_action.actionId)

        prep_subnet_action = single(actions, lambda x: isinstance(x, PrepareSubnet))
        prep_subnet_action_result = PrepareSubnetActionResult(prep_subnet_action.actionId)

        if self._ssh_keys_exists():
            public_key = self._get_ssh_public_key()
        else:
            public_key = self._generate_ssh_key_pair()
            # send to MAAS only public key
            self._maas_client.ssh_keys.create(key=public_key)

        access_keys_action = single(actions, lambda x: isinstance(x, CreateKeys))
        access_keys_action_results = CreateKeysActionResult(actionId=access_keys_action.actionId,
                                                            accessKey=public_key)

        action_results = [prep_network_action_result, prep_subnet_action_result, access_keys_action_results]

        return DriverResponse(action_results).to_driver_response_json()

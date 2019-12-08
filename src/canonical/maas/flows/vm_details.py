import json

from cloudshell.cp.core.models import VmDetailsData
from cloudshell.cp.core.models import VmDetailsNetworkInterface
from cloudshell.cp.core.models import VmDetailsProperty

from canonical.maas.flows import BaseMaasFlow


class MaasGetVMDetailsFlow(BaseMaasFlow):
    def _get_vm_data(self, vm_uid, vm_name):
        """

        :param str vm_uid:
        :param str vm_name:
        :return:
        """
        # todo: what data to set here ???
        # data = [VmDetailsProperty(key='CPUS', value="4")]
        data = []
        vm_network_data = []

        machine = self._maas_client.machines.get(vm_uid)

        for idx, ip_address in enumerate(machine.ip_addresses, start=1):
            # network_data = [
            #     VmDetailsProperty(key='Name', value='test name'),
            # ]

            interface = VmDetailsNetworkInterface(interfaceId=idx,
                                                  networkId=hash(ip_address),
                                                  isPredefined=True,
                                                  networkData=[],
                                                  privateIpAddress=ip_address)
            vm_network_data.append(interface)

            # network_data = [
            #     VmDetailsProperty(key='MAC Address', value=nic['mac_address']),
            # ]
            #
            # current_interface = VmDetailsNetworkInterface(interfaceId=i,
            #                                               networkId=nic['network_uuid'],
            #                                               isPredefined=True,
            #                                               networkData=network_data)
            # i += 1
            # vm_network_data.append(current_interface)
            #
        vm_details_data = VmDetailsData(vmInstanceData=data,
                                        vmNetworkData=vm_network_data,
                                        appName=vm_name)

        return vm_details_data

    def get_vms_details(self, requests):
        """

        :param requests:
        :return:
        """
        results = []
        json_requests = json.loads(requests)

        for request in json_requests["items"]:
            vm_name = request["deployedAppJson"]["name"]
            vm_uid = request["deployedAppJson"]["vmdetails"]["uid"]
            result = self._get_vm_data(vm_uid=vm_uid, vm_name=vm_name)
            results.append(result)

        result_json = json.dumps(results, default=lambda o: o.__dict__,
                                 sort_keys=True,
                                 separators=(',', ':'))

        return result_json

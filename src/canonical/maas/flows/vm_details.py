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
        machine = self._maas_client.machines.get(vm_uid)
        vm_network_data = []

        data = [VmDetailsProperty(key="Architecture", value=machine.architecture),
                VmDetailsProperty(key='HWE Kernel', value=machine.hwe_kernel),
                VmDetailsProperty(key="CPU Cores", value=machine.cpus),
                VmDetailsProperty(key="RAM GiB", value=machine.memory//1024),
                VmDetailsProperty(key="Disks", value=len(machine.block_devices)),
                VmDetailsProperty(key="Distro Series", value=machine.distro_series),
                VmDetailsProperty(key="Operation System", value=machine.osystem)]

        for iface in machine.interfaces:
            network_data = [
                VmDetailsProperty(key='MAC Address', value=iface.mac_address),
            ]

            for link in iface.links:
                iface_id = hash(f"{iface.id }_{link.id}")
                interface = VmDetailsNetworkInterface(interfaceId=iface_id,
                                                      networkId=iface_id,
                                                      isPredefined=True,
                                                      networkData=network_data,
                                                      privateIpAddress=link.ip_address)
                vm_network_data.append(interface)

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

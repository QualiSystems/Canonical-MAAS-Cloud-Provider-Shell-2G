import asyncio

from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface
from cloudshell.shell.core.driver_context import InitCommandContext, AutoLoadCommandContext, AutoLoadDetails, \
    CancellationContext, ResourceRemoteCommandContext
from cloudshell.shell.core.driver_utils import GlobalLock
from cloudshell.shell.core.session.cloudshell_session import CloudShellSessionContext
from cloudshell.shell.core.session.logging_session import LoggingSessionContext

from canonical.maas.resource_config import MaasResourceConfig
from canonical.maas.flows.autoload import MaasAutoloadFlow
from canonical.maas.flows.delete import MaasDeleteFlow
from canonical.maas.flows.deploy import MaasDeployFlow
from canonical.maas.flows.cleanup_sandbox_infra import MaasCleanupSandboxInfraFlow
from canonical.maas.flows.power_mgmt import MaasPowerManagementFlow
from canonical.maas.flows.prepare_sandbox_infra import MaasPrepareSandboxInfraFlow
from canonical.maas.flows.refresh_ip import MaasRemoteRefreshIPFlow
from canonical.maas.flows.vm_details import MaasGetVMDetailsFlow


# maas client built with asyncio which by default doesn't allow creation of new event loop in threads
class AnyThreadEventLoopPolicy(asyncio.DefaultEventLoopPolicy):
    """Event loop policy that allows loop creation on any thread"""
    def get_event_loop(self):
        try:
            return super().get_event_loop()
        except (RuntimeError, AssertionError):
            loop = self.new_event_loop()
            self.set_event_loop(loop)
            return loop


asyncio.set_event_loop_policy(AnyThreadEventLoopPolicy())


class MaasDriver (ResourceDriverInterface):
    SHELL_NAME = "Maas"

    def __init__(self):
        """
        ctor must be without arguments, it is created with reflection at run time
        """
        pass

    def initialize(self, context):
        """
        Called every time a new instance of the driver is created

        This method can be left unimplemented but this is a good place to load and cache the driver configuration,
        initiate sessions etc.
        Whatever you choose, do not remove it.

        :param InitCommandContext context: the context the command runs on
        """
        pass

    @GlobalLock.lock
    def get_inventory(self, context):
        """
        Called when the cloud provider resource is created
        in the inventory.

        Method validates the values of the cloud provider attributes, entered by the user as part of the cloud provider resource creation.
        In addition, this would be the place to assign values programmatically to optional attributes that were not given a value by the user.

        If one of the validations failed, the method should raise an exception

        :param AutoLoadCommandContext context: the context the command runs on
        :return Attribute and sub-resource information for the Shell resource you can return an AutoLoadDetails object
        :rtype: AutoLoadDetails
        """
        with LoggingSessionContext(context) as logger:
            logger.info("Starting Autoload command...")
            api = CloudShellSessionContext(context).get_api()
            resource_config = MaasResourceConfig.from_context(shell_name=self.SHELL_NAME,
                                                              context=context,
                                                              api=api)

            autoload_flow = MaasAutoloadFlow(resource_config=resource_config,
                                             logger=logger)

            return autoload_flow.discover()

    def Deploy(self, context, request, cancellation_context=None):
        """
        Called when reserving a sandbox during setup, a call for each app in the sandbox.

        Method creates the compute resource in the cloud provider - VM instance or container.

        If App deployment fails, return a "success false" action result.

        :param ResourceCommandContext context:
        :param str request: A JSON string with the list of requested deployment actions
        :param CancellationContext cancellation_context:
        :return:
        :rtype: str
        """
        with LoggingSessionContext(context) as logger:
            logger.info("Starting Deploy command...")
            api = CloudShellSessionContext(context).get_api()
            resource_config = MaasResourceConfig.from_context(shell_name=self.SHELL_NAME,
                                                              context=context,
                                                              api=api)

            deploy_flow = MaasDeployFlow(resource_config=resource_config,
                                         logger=logger)

            return deploy_flow.deploy(request=request)

    def PowerOn(self, context, ports):
        """
        Called when reserving a sandbox during setup, a call for each app in the sandbox can also be run manually by the sandbox end-user from the deployed App's commands pane

        Method spins up the VM

        If the operation fails, method should raise an exception.

        :param ResourceRemoteCommandContext context:
        :param ports:
        """
        with LoggingSessionContext(context) as logger:
            logger.info("Starting Power On command...")
            api = CloudShellSessionContext(context).get_api()
            resource_config = MaasResourceConfig.from_context(shell_name=self.SHELL_NAME,
                                                              context=context,
                                                              api=api)

            power_flow = MaasPowerManagementFlow(resource_config=resource_config,
                                                 logger=logger)

            return power_flow.power_on(resource=context.remote_endpoints[0])

    def remote_refresh_ip(self, context, ports, cancellation_context):
        """

        Called when reserving a sandbox during setup, a call for each app in the sandbox can also be run manually by the sandbox end-user from the deployed App's commands pane

        Method retrieves the VM's updated IP address from the cloud provider and sets it on the deployed App resource
        Both private and public IPs are retrieved, as appropriate.

        If the operation fails, method should raise an exception.

        :param ResourceRemoteCommandContext context:
        :param ports:
        :param CancellationContext cancellation_context:
        :return:
        """
        with LoggingSessionContext(context) as logger:
            logger.info("Starting Remote Refresh IP command...")
            api = CloudShellSessionContext(context).get_api()
            resource_config = MaasResourceConfig.from_context(shell_name=self.SHELL_NAME,
                                                              context=context,
                                                              api=api)

            refresh_ip_flow = MaasRemoteRefreshIPFlow(resource_config=resource_config,
                                                      cs_api=api,
                                                      logger=logger)

            return refresh_ip_flow.refresh_ip(resource=context.remote_endpoints[0])

    def GetVmDetails(self, context, requests, cancellation_context):
        """
        Called when reserving a sandbox during setup, a call for each app in the sandbox can also be run manually by the sandbox
        end-user from the deployed App's VM Details pane

        Method queries cloud provider for instance operating system, specifications and networking information and
        returns that as a json serialized driver response containing a list of VmDetailsData.

        If the operation fails, method should raise an exception.

        :param ResourceCommandContext context:
        :param str requests:
        :param CancellationContext cancellation_context:
        :return:
        """
        with LoggingSessionContext(context) as logger:
            logger.info("Starting Deploy command...")
            api = CloudShellSessionContext(context).get_api()
            resource_config = MaasResourceConfig.from_context(shell_name=self.SHELL_NAME,
                                                              context=context,
                                                              api=api)

            vm_details_flow = MaasGetVMDetailsFlow(resource_config=resource_config, logger=logger)
            return vm_details_flow.get_vms_details(requests=requests)

    def PowerCycle(self, context, ports, delay):
        """ please leave it as is """
        pass

    def PowerOff(self, context, ports):
        """
        Called during sandbox's teardown can also be run manually by the sandbox end-user from the deployed App's commands pane

        Method shuts down (or powers off) the VM instance.

        If the operation fails, method should raise an exception.

        :param ResourceRemoteCommandContext context:
        :param ports:
        """
        pass

    def DeleteInstance(self, context, ports):
        """
        Called during sandbox's teardown or when removing a deployed App from the sandbox

        Method deletes the VM from the cloud provider.

        If the operation fails, method should raise an exception.

        :param ResourceRemoteCommandContext context:
        :param ports:
        """
        with LoggingSessionContext(context) as logger:
            logger.info("Starting Delete instance command...")
            api = CloudShellSessionContext(context).get_api()
            resource_config = MaasResourceConfig.from_context(shell_name=self.SHELL_NAME,
                                                              context=context,
                                                              api=api)

            delete_flow = MaasDeleteFlow(resource_config=resource_config, logger=logger)
            return delete_flow.delete(resource=context.remote_endpoints[0])

    def ApplyConnectivityChanges(self, context, request):
        """
        Called during the orchestration setup and also called in a live sandbox when
        and instance is connected or disconnected from a VLAN
        service or from another instance (P2P connection).

        Method connects/disconnect VMs to VLANs based on requested actions (SetVlan, RemoveVlan)
        It's recommended to follow the "get or create" pattern when implementing this method.

        If operation fails, return a "success false" action result.

        :param ResourceCommandContext context: The context object for the command with resource and reservation info
        :param str request: A JSON string with the list of requested connectivity changes
        :return: a json object with the list of connectivity changes which were carried out by the driver
        :rtype: str
        """
        pass

    def PrepareSandboxInfra(self, context, request, cancellation_context):
        """
        Called in the beginning of the orchestration flow (preparation stage), even before Deploy is called.

        Prepares all of the required infrastructure needed for a sandbox operating with L3 connectivity.
        For example, creating networking infrastructure like VPC, subnets or routing tables in AWS, storage entities such as S3 buckets, or
        keyPair objects for authentication.
        In general, any other entities needed on the sandbox level should be created here.

        Note:
        PrepareSandboxInfra can be called multiple times in a sandbox.
        Setup can be called multiple times in the sandbox, and every time setup is called, the PrepareSandboxInfra method will be called again.
        Implementation should support this use case and take under consideration that the cloud resource might already exist.
        It's recommended to follow the "get or create" pattern when implementing this method.

        When an error is raised or method returns action result with success false
        Cloudshell will fail sandbox creation, so bear that in mind when doing so.

        :param ResourceCommandContext context:
        :param str request:
        :param CancellationContext cancellation_context:
        :return:
        :rtype: str
        """
        with LoggingSessionContext(context) as logger:
            logger.info("Starting Prepare Sandbox Infra command...")
            api = CloudShellSessionContext(context).get_api()
            resource_config = MaasResourceConfig.from_context(shell_name=self.SHELL_NAME,
                                                              context=context,
                                                              api=api)

            prepare_sandbox_flow = MaasPrepareSandboxInfraFlow(resource_config=resource_config, logger=logger)
            return prepare_sandbox_flow.prepare(request=request)

    def CleanupSandboxInfra(self, context, request):
        """
        Called at the end of reservation teardown

        Cleans all entities (beside VMs) created for sandbox, usually entities created in the
        PrepareSandboxInfra command.

        Basically all created entities for the sandbox will be deleted by calling the methods: DeleteInstance, CleanupSandboxInfra

        If a failure occurs, return a "success false" action result.

        :param ResourceCommandContext context:
        :param str request:
        :return:
        :rtype: str
        """
        with LoggingSessionContext(context) as logger:
            logger.info("Starting Cleanup Sandbox Infra command...")
            api = CloudShellSessionContext(context).get_api()
            resource_config = MaasResourceConfig.from_context(shell_name=self.SHELL_NAME,
                                                              context=context,
                                                              api=api)

            cleanup_sandbox_flow = MaasCleanupSandboxInfraFlow(resource_config=resource_config, logger=logger)
            return cleanup_sandbox_flow.cleanup(request=request)

    def SetAppSecurityGroups(self, context, request):
        """
        Called via cloudshell API call

        Programmatically set which ports will be open on each of the apps in the sandbox, and from
        where they can be accessed. This is an optional command that may be implemented.
        Normally, all outbound traffic from a deployed app should be allowed.
        For inbound traffic, we may use this method to specify the allowed traffic.
        An app may have several networking interfaces in the sandbox. For each such interface, this command allows to set
        which ports may be opened, the protocol and the source CIDR

        If operation fails, return a "success false" action result.

        :param ResourceCommandContext context:
        :param str request:
        :return:
        :rtype: str
        """
        pass

    def cleanup(self):
        """
        Destroy the driver session, this function is called every time a driver instance is destroyed
        This is a good place to close any open sessions, finish writing to log files, etc.
        """
        pass


if __name__ == "__main__":
    import mock
    from cloudshell.shell.core.driver_context import ResourceCommandContext, ResourceContextDetails, ReservationContextDetails

    address = "192.168.26.24"
    user = "admin"
    password = "admin"
    port = 5240

    context = ResourceCommandContext(*(None,) * 4)
    context.resource = ResourceContextDetails(*(None,) * 13)
    context.resource.name = "MAAS"
    context.resource.fullname = "Canonical MAAS"
    context.resource.address = address
    context.resource.family = "CS_CloudProvider"
    context.reservation = ReservationContextDetails(*(None,) * 7)
    context.reservation.reservation_id = '0cc17f8c-75ba-495f-aeb5-df5f0f9a0e97'
    context.resource.attributes = {}

    for attr, value in [("User", user),
                        ("Password", password),
                        ("Scheme", "http"),
                        # ("Managed Allocation", "True"),
                        ("Port", port)]:

        context.resource.attributes["{}.{}".format(MaasDriver.SHELL_NAME, attr)] = value
        context.connectivity = mock.MagicMock()
        context.connectivity.server_address = "192.168.85.27"

    dr = MaasDriver()
    dr.initialize(context)

    from maas.client import login

    client = login(
        f"http://192.168.26.24:5240/MAAS/",
        username="admin",
        password="admin",
        insecure=True,
    )

    for res in dr.get_inventory(context).resources:
        print(res.__dict__)

    dr.Deploy(context, mock.MagicMock())

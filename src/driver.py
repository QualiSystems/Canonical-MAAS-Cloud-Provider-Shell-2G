from cloudshell.cp.core.cancellation_manager import CancellationContextManager
from cloudshell.cp.core.request_actions import (
    CleanupSandboxInfraRequestActions,
    DeployedVMActions,
    DeployVMRequestActions,
    GetVMDetailsRequestActions,
    PrepareSandboxInfraRequestActions,
)
from cloudshell.cp.core.reservation_info import ReservationInfo
from cloudshell.cp.maas.api.client import MaasAPIClient
from cloudshell.cp.maas.flows.autoload import MaasAutoloadFlow
from cloudshell.cp.maas.flows.cleanup_sandbox_infra import MaasCleanupSandboxInfraFlow
from cloudshell.cp.maas.flows.delete import MaasDeleteFlow
from cloudshell.cp.maas.flows.deploy import MaasDeployFlow
from cloudshell.cp.maas.flows.power_mgmt import MaasPowerManagementFlow
from cloudshell.cp.maas.flows.prepare_sandbox_infra import MaasPrepareSandboxInfraFlow
from cloudshell.cp.maas.flows.refresh_ip import MaasRemoteRefreshIPFlow
from cloudshell.cp.maas.flows.vm_details import MaasGetVMDetailsFlow
from cloudshell.cp.maas.models.deploy_app import MaasMachineDeployApp
from cloudshell.cp.maas.resource_config import MaasResourceConfig
from cloudshell.cp.maas.utils.asyncio import event_loop_policy
from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface
from cloudshell.shell.core.session.cloudshell_session import CloudShellSessionContext
from cloudshell.shell.core.session.logging_session import LoggingSessionContext


class MaasDriver(ResourceDriverInterface):
    def __init__(self):
        """Ctor must be without arguments, it is created with reflection at run time."""
        pass

    def initialize(self, context):
        """Called every time a new instance of the driver is created.

        This method can be left unimplemented but this is a good place to load and cache
        the driver configuration, initiate sessions etc. Whatever you choose,
        do not remove it.
        :param InitCommandContext context: the context the command runs on
        """
        event_loop_policy.set_asyncio_any_thread_event_loop_policy()

    def get_inventory(self, context):
        """Called when the cloud provider resource is created in the inventory.

        Method validates the values of the cloud provider attributes, entered
        by the user as part  of the cloud provider resource creation.
        In addition, this would be the place to assign values programmatically
        to optional attributes that were not given a value by the user. If one
        of the validations failed, the method should raise an exception
        :param AutoLoadCommandContext context: the context the command runs on
        :return Attribute and sub-resource information for the Shell resource you
        can return an AutoLoadDetails object
        :rtype: AutoLoadDetails
        """
        with LoggingSessionContext(context) as logger:
            logger.info("Starting Autoload command...")
            api = CloudShellSessionContext(context).get_api()
            resource_config = MaasResourceConfig.from_context(context=context, api=api)

            maas_client = MaasAPIClient(
                address=resource_config.address,
                user=resource_config.api_user,
                password=resource_config.api_password,
                port=resource_config.api_port,
                scheme=resource_config.api_scheme,
                logger=logger,
            )

            autoload_flow = MaasAutoloadFlow(
                resource_config=resource_config, maas_client=maas_client, logger=logger
            )

            return autoload_flow.discover()

    def Deploy(self, context, request, cancellation_context=None):
        """Called when reserving a sandbox during setup, a call for each app in the sandbox.

        Method creates the compute resource in the cloud provider -
        VM instance or container. If App deployment fails, return a
        "success false" action result.
        :param ResourceCommandContext context:
        :param str request: A JSON string with the list of requested deployment actions
        :param CancellationContext cancellation_context:
        :return:
        :rtype: str
        """
        with LoggingSessionContext(context) as logger:
            logger.info("Starting Deploy command...")
            logger.info(f"Request: {request}")
            api = CloudShellSessionContext(context).get_api()
            resource_config = MaasResourceConfig.from_context(context=context, api=api)
            cancellation_manager = CancellationContextManager(cancellation_context)

            maas_client = MaasAPIClient(
                address=resource_config.address,
                user=resource_config.api_user,
                password=resource_config.api_password,
                port=resource_config.api_port,
                scheme=resource_config.api_scheme,
                logger=logger,
            )

            DeployVMRequestActions.register_deployment_path(MaasMachineDeployApp)
            request_actions = DeployVMRequestActions.from_request(
                request=request, cs_api=api
            )

            deploy_flow = MaasDeployFlow(
                resource_config=resource_config,
                maas_client=maas_client,
                cancellation_manager=cancellation_manager,
                logger=logger,
            )

            return deploy_flow.deploy(request_actions=request_actions)

    def PowerOn(self, context, ports):
        """Method spins up the VM.

        Called when reserving a sandbox during setup, a call for each app in
        the sandbox can also be run manually by the sandbox end-user from the
        deployed App's commands pane. If the operation fails, method should raise
        an exception.
        :param ResourceRemoteCommandContext context:
        :param ports:
        """
        with LoggingSessionContext(context) as logger:
            logger.info("Starting Power On command...")
            api = CloudShellSessionContext(context).get_api()

            resource_config = MaasResourceConfig.from_context(context=context, api=api)

            maas_client = MaasAPIClient(
                address=resource_config.address,
                user=resource_config.api_user,
                password=resource_config.api_password,
                port=resource_config.api_port,
                scheme=resource_config.api_scheme,
                logger=logger,
            )

            resource = context.remote_endpoints[0]
            deployed_vm_actions = DeployedVMActions.from_remote_resource(
                resource=resource, cs_api=api
            )

            power_flow = MaasPowerManagementFlow(
                resource_config=resource_config,
                maas_client=maas_client,
                logger=logger,
            )

            return power_flow.power_on(deployed_app=deployed_vm_actions.deployed_app)

    def PowerOff(self, context, ports):
        """Method shuts down (or powers off) the VM instance.

        Called during sandbox's teardown can also be run manually by the
        sandbox end-user from the deployed App's commands pane.
        If the operation fails, method should raise an exception.
        :param ResourceRemoteCommandContext context:
        :param ports:
        """
        with LoggingSessionContext(context) as logger:
            logger.info("Starting Power Off command...")
            api = CloudShellSessionContext(context).get_api()

            resource_config = MaasResourceConfig.from_context(context=context, api=api)

            maas_client = MaasAPIClient(
                address=resource_config.address,
                user=resource_config.api_user,
                password=resource_config.api_password,
                port=resource_config.api_port,
                scheme=resource_config.api_scheme,
                logger=logger,
            )

            resource = context.remote_endpoints[0]
            deployed_vm_actions = DeployedVMActions.from_remote_resource(
                resource=resource, cs_api=api
            )

            power_flow = MaasPowerManagementFlow(
                resource_config=resource_config,
                maas_client=maas_client,
                logger=logger,
            )

            return power_flow.power_off(deployed_app=deployed_vm_actions.deployed_app)

    def PowerCycle(self, context, ports, delay):
        pass

    def remote_refresh_ip(self, context, ports, cancellation_context):
        """Method updates the VM's IP address from the cloud provider.

        Called when reserving a sandbox during setup, a call for each app
        in the sandbox can also be run manually by the sandbox end-user from
        the deployed App's commands pane. Method retrieves the VM's updated
        IP address from the cloud provider and sets it on the deployed App
        resource. Both private and public IPs are retrieved, as appropriate.
        If the operation fails, method should raise an exception.
        :param ResourceRemoteCommandContext context:
        :param ports:
        :param CancellationContext cancellation_context:
        :return:
        """
        with LoggingSessionContext(context) as logger:
            logger.info("Starting Remote Refresh IP command...")
            api = CloudShellSessionContext(context).get_api()

            resource_config = MaasResourceConfig.from_context(context=context, api=api)

            cancellation_manager = CancellationContextManager(cancellation_context)

            maas_client = MaasAPIClient(
                address=resource_config.address,
                user=resource_config.api_user,
                password=resource_config.api_password,
                port=resource_config.api_port,
                scheme=resource_config.api_scheme,
                logger=logger,
            )

            resource = context.remote_endpoints[0]
            deployed_vm_actions = DeployedVMActions.from_remote_resource(
                resource=resource, cs_api=api
            )

            refresh_ip_flow = MaasRemoteRefreshIPFlow(
                resource_config=resource_config,
                maas_client=maas_client,
                cancellation_manager=cancellation_manager,
                cs_api=api,
                logger=logger,
            )

            return refresh_ip_flow.refresh_ip(
                deployed_app=deployed_vm_actions.deployed_app
            )

    def GetVmDetails(self, context, requests, cancellation_context):
        """Get VM Details.

        Called when reserving a sandbox during setup, a call for each app
        in the sandbox can also be run manually by the sandbox end-user from
        the deployed App's VM Details pane. Method queries cloud provider
        for instance operating system, specifications and networking information
        and returns that as a json serialized driver response containing a list
        of VmDetailsData. If the operation fails, method should raise an exception.
        :param ResourceCommandContext context:
        :param str requests:
        :param CancellationContext cancellation_context:
        :return:
        """
        with LoggingSessionContext(context) as logger:
            logger.info("Starting Deploy command...")
            api = CloudShellSessionContext(context).get_api()

            resource_config = MaasResourceConfig.from_context(
                context=context,
                api=api,
            )

            request_actions = GetVMDetailsRequestActions.from_request(
                request=requests, cs_api=api
            )
            cancellation_manager = CancellationContextManager(cancellation_context)

            maas_client = MaasAPIClient(
                address=resource_config.address,
                user=resource_config.api_user,
                password=resource_config.api_password,
                port=resource_config.api_port,
                scheme=resource_config.api_scheme,
                logger=logger,
            )

            vm_details_flow = MaasGetVMDetailsFlow(
                resource_config=resource_config,
                maas_client=maas_client,
                cancellation_manager=cancellation_manager,
                logger=logger,
            )
            return vm_details_flow.get_vm_details(request_actions=request_actions)

    def DeleteInstance(self, context, ports):
        """Deletes the VM from the cloud provider.

        Called during sandbox's teardown or when removing a deployed App
        from the sandbox. If the operation fails, method should raise an exception.
        :param ResourceRemoteCommandContext context:
        :param ports:
        """
        with LoggingSessionContext(context) as logger:
            logger.info("Starting Delete instance command...")
            api = CloudShellSessionContext(context).get_api()
            resource_config = MaasResourceConfig.from_context(
                context=context,
                api=api,
            )

            resource = context.remote_endpoints[0]
            deployed_vm_actions = DeployedVMActions.from_remote_resource(
                resource=resource, cs_api=api
            )

            maas_client = MaasAPIClient(
                address=resource_config.address,
                user=resource_config.api_user,
                password=resource_config.api_password,
                port=resource_config.api_port,
                scheme=resource_config.api_scheme,
                logger=logger,
            )

            delete_flow = MaasDeleteFlow(
                resource_config=resource_config,
                logger=logger,
                maas_client=maas_client,
            )

            return delete_flow.delete_instance(
                deployed_app=deployed_vm_actions.deployed_app
            )

    def ApplyConnectivityChanges(self, context, request):
        """Method connects/disconnect VMs to VLANs.

        Called during the orchestration setup and also called in a live sandbox when
        and instance is connected or disconnected from a VLAN service or from
        another instance (P2P connection). Method connects/disconnect VMs to VLANs
        based on requested actions (SetVlan, RemoveVlan)  It's recommended to follow
        the "get or create" pattern when implementing this method.
        If operation fails, return a "success false" action result.
        :param ResourceCommandContext context: The context object for the command
        with resource and reservation info
        :param str request: A JSON string with the list of requested
        connectivity changes
        :return: a json object with the list of connectivity changes
        which were carried out by the driver
        :rtype: str
        """
        pass

    def PrepareSandboxInfra(self, context, request, cancellation_context):
        """Prepares all of the required infrastructure needed for a sandbox operating.

        Called in the beginning of the orchestration flow (preparation stage), even
        before Deploy is called. Prepares all of the required infrastructure needed
        for a sandbox operating with L3 connectivity. For example, creating networking
        infrastructure like VPC, subnets or routing tables in AWS, storage entities
        such as S3 buckets, or keyPair objects for authentication. In general,
        any other entities needed on the sandbox level should be created here.
        Note:
        PrepareSandboxInfra can be called multiple times in a sandbox.
        Setup can be called multiple times in the sandbox, and every time setup
        is called, the PrepareSandboxInfra method will be called again. Implementation
        should support this use case and take under consideration that the cloud
        resource might already exist. It's recommended to follow the "get or create"
        pattern when implementing this method. When an error is raised or method
        returns action result with success false. Cloudshell will fail sandbox creation,
        so bear that in mind when doing so.
        :param ResourceCommandContext context:
        :param str request:
        :param CancellationContext cancellation_context:
        :return:
        :rtype: str
        """
        with LoggingSessionContext(context) as logger:
            logger.info("Starting Prepare Sandbox Infra command...")
            logger.info(f"Request: {request}")
            api = CloudShellSessionContext(context).get_api()
            resource_config = MaasResourceConfig.from_context(
                context=context,
                api=api,
            )

            request_actions = PrepareSandboxInfraRequestActions.from_request(request)
            reservation_info = ReservationInfo.from_resource_context(context)
            cancellation_manager = CancellationContextManager(cancellation_context)

            maas_client = MaasAPIClient(
                address=resource_config.address,
                user=resource_config.api_user,
                password=resource_config.api_password,
                port=resource_config.api_port,
                scheme=resource_config.api_scheme,
                logger=logger,
            )

            prepare_sandbox_flow = MaasPrepareSandboxInfraFlow(
                resource_config=resource_config,
                reservation_info=reservation_info,
                cancellation_manager=cancellation_manager,
                maas_client=maas_client,
                logger=logger,
            )

            return prepare_sandbox_flow.prepare(request_actions=request_actions)

    def CleanupSandboxInfra(self, context, request):
        """Cleans all entities (beside VMs) created for sandbox.

        Called at the end of reservation teardown. Cleans all entities (beside VMs)
        created for sandbox, usually entities created in the PrepareSandboxInfra
        command. Basically all created entities for the sandbox  will be deleted
        by calling  the methods: DeleteInstance, CleanupSandboxInfra. If a failure
        occurs, return a "success false" action result.
        :param ResourceCommandContext context:
        :param str request:
        :return:
        :rtype: str
        """
        with LoggingSessionContext(context) as logger:
            logger.info("Starting Cleanup Sandbox Infra command...")
            api = CloudShellSessionContext(context).get_api()
            resource_config = MaasResourceConfig.from_context(
                context=context,
                api=api,
            )

            request_actions = CleanupSandboxInfraRequestActions.from_request(request)
            reservation_info = ReservationInfo.from_resource_context(context)

            maas_client = MaasAPIClient(
                address=resource_config.address,
                user=resource_config.api_user,
                password=resource_config.api_password,
                port=resource_config.api_port,
                scheme=resource_config.api_scheme,
                logger=logger,
            )

            cleanup_sandbox_flow = MaasCleanupSandboxInfraFlow(
                resource_config=resource_config,
                reservation_info=reservation_info,
                maas_client=maas_client,
                logger=logger,
            )
            return cleanup_sandbox_flow.cleanup(request_actions=request_actions)

    def SetAppSecurityGroups(self, context, request):
        """Set which ports will be open on each of the apps.

        Called via cloudshell API call. Programmatically set which ports will be open
        on each of the apps in the sandbox, and from where they can be accessed.
        This is an optional command that may be implemented. Normally, all outbound
        traffic from a deployed app should be allowed. For inbound traffic, we may use
        this method to specify the allowed traffic. An app may have several networking
        interfaces in the sandbox. For each such interface, this command allows to set
        which ports may be opened, the protocol and the source CIDR.  If operation
        fails, return a "success false" action result.
        :param ResourceCommandContext context:
        :param str request:
        :return:
        :rtype: str
        """
        pass

    def cleanup(self):
        """Destroy the driver session.

        This function is called every time a driver instance is destroyed. This is
        a good place to close any open sessions, finish writing to log files, etc.
        """
        pass

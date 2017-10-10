# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from __future__ import print_function
import base64
import binascii
import datetime
import errno
import json
import os
import os.path
import platform
import re
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
import webbrowser
import yaml

import dateutil.parser
from dateutil.relativedelta import relativedelta
from six.moves.urllib.error import URLError  # pylint: disable=import-error
from six.moves.urllib.request import urlopen  # pylint: disable=import-error

from msrestazure.azure_exceptions import CloudError

import azure.cli.core.azlogging as azlogging
from azure.cli.command_modules.aks._actions import _is_valid_ssh_rsa_public_key
from azure.cli.core._environment import get_config_dir
from azure.cli.core._profile import Profile
from azure.cli.core.application import APPLICATION
from azure.cli.core.commands.client_factory import get_mgmt_service_client
from azure.cli.core.profiles import ResourceType
from azure.cli.core.util import CLIError
from azure.cli.core.util import shell_safe_json_parse
from azure.graphrbac.models import ApplicationCreateParameters
from azure.graphrbac.models import GetObjectsParameters
from azure.graphrbac.models import KeyCredential
from azure.graphrbac.models import PasswordCredential
from azure.graphrbac.models import ServicePrincipalCreateParameters
from azure.mgmt.authorization.models import RoleAssignmentProperties
from azure.mgmt.containerservice.models import ContainerServiceAgentPoolProfile
from azure.mgmt.containerservice.models import ContainerServiceLinuxProfile
from azure.mgmt.containerservice.models import ContainerServiceServicePrincipalProfile
from azure.mgmt.containerservice.models import ContainerServiceSshConfiguration
from azure.mgmt.containerservice.models import ContainerServiceSshPublicKey
from azure.mgmt.containerservice.models import ContainerServiceStorageProfileTypes
from azure.mgmt.containerservice.models import ManagedCluster
from azure.mgmt.containerservice.models import ManagedClusterProperties

from ._client_factory import _auth_client_factory
from ._client_factory import _graph_client_factory


logger = azlogging.get_az_logger(__name__)


def which(binary):
    pathVar = os.getenv('PATH')
    if platform.system() == 'Windows':
        binary = binary + '.exe'
        parts = pathVar.split(';')
    else:
        parts = pathVar.split(':')

    for part in parts:
        bin_path = os.path.join(part, binary)
        if os.path.exists(bin_path) and os.path.isfile(bin_path) and os.access(bin_path, os.X_OK):
            return bin_path

    return None


def _resource_client_factory():
    return get_mgmt_service_client(ResourceType.MGMT_RESOURCE_RESOURCES)


def cf_providers():
    return _resource_client_factory().providers


def register_providers():
    providers = cf_providers()

    namespaces = ['Microsoft.Network', 'Microsoft.Compute', 'Microsoft.Storage']
    for namespace in namespaces:
        state = providers.get(resource_provider_namespace=namespace)
        if state.registration_state != 'Registered':  # pylint: disable=no-member
            logger.info('registering %s', namespace)
            providers.register(resource_provider_namespace=namespace)
        else:
            logger.info('%s is already registered', namespace)


def wait_then_open(url):
    """
    Waits for a bit then opens a URL.  Useful for waiting for a proxy to come up, and then open the URL.
    """
    for _ in range(1, 10):
        try:
            urlopen(url, context=_ssl_context())
        except URLError:
            time.sleep(1)
        break
    webbrowser.open_new_tab(url)


def wait_then_open_async(url):
    """
    Spawns a thread that waits for a bit then opens a URL.
    """
    t = threading.Thread(target=wait_then_open, args=({url}))
    t.daemon = True
    t.start()


def _ssl_context():
    if sys.version_info < (3, 4):
        return ssl.SSLContext(ssl.PROTOCOL_TLSv1)

    return ssl.create_default_context()


def _urlretrieve(url, filename):
    req = urlopen(url, context=_ssl_context())
    with open(filename, 'wb') as f:
        f.write(req.read())


def aks_install_cli(client_version='latest', install_location=None):
    """Download the kubectl command line tool."""

    if client_version == 'latest':
        context = _ssl_context()
        version = urlopen('https://storage.googleapis.com/kubernetes-release/release/stable.txt',
                          context=context).read()
        client_version = version.decode('UTF-8').strip()

    file_url = ''
    system = platform.system()
    base_url = 'https://storage.googleapis.com/kubernetes-release/release/{}/bin/{}/amd64/{}'
    if system == 'Windows':
        file_url = base_url.format(client_version, 'windows', 'kubectl.exe')
    elif system == 'Linux':
        # TODO: Support ARM CPU here
        file_url = base_url.format(client_version, 'linux', 'kubectl')
    elif system == 'Darwin':
        file_url = base_url.format(client_version, 'darwin', 'kubectl')
    else:
        raise CLIError('Proxy server ({}) does not exist on the cluster.'.format(system))

    logger.warning('Downloading client to %s from %s', install_location, file_url)
    try:
        _urlretrieve(file_url, install_location)
        os.chmod(install_location,
                 os.stat(install_location).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except IOError as ex:
        raise CLIError('Connection error while attempting to download client ({})'.format(ex))


def _validate_service_principal(client, sp_id):
    # discard the result, we're trusting this to throw if it can't find something
    try:
        show_service_principal(client.service_principals, sp_id)
    except:  # pylint: disable=bare-except
        raise CLIError(
            'Failed to validate service principal, if this persists try deleting $HOME/.azure/acsServicePrincipal.json')


def _build_service_principal(client, name, url, client_secret):
    # use get_progress_controller
    hook = APPLICATION.get_progress_controller(True)
    hook.add(messsage='Creating service principal', value=0, total_val=1.0)
    logger.info('Creating service principal')
    result = create_application(client.applications, name, url, [url], password=client_secret)
    service_principal = result.app_id  # pylint: disable=no-member
    for x in range(0, 10):
        hook.add(message='Creating service principal', value=0.1 * x, total_val=1.0)
        try:
            create_service_principal(service_principal, client=client)
            break
        # TODO figure out what exception AAD throws here sometimes.
        except Exception as ex:  # pylint: disable=broad-except
            logger.info(ex)
            time.sleep(2 + 2 * x)
    else:
        return False
    hook.add(message='Finished service principal creation', value=1.0, total_val=1.0)
    logger.info('Finished service principal creation')
    return service_principal


def _add_role_assignment(role, service_principal, delay=2):
    # AAD can have delays in propagating data, so sleep and retry
    hook = APPLICATION.get_progress_controller(True)
    hook.add(message='Waiting for AAD role to propagate', value=0, total_val=1.0)
    logger.info('Waiting for AAD role to propagate')
    for x in range(0, 10):
        hook.add(message='Waiting for AAD role to propagate', value=0.1 * x, total_val=1.0)
        try:
            # TODO: break this out into a shared utility library
            create_role_assignment(role, service_principal)
            # Sleep for a while to get role assignment propagated
            time.sleep(delay + delay * x)
            break
        except CloudError as ex:
            if ex.message == 'The role assignment already exists.':
                break
            logger.info(ex.message)
        except:  # pylint: disable=bare-except
            pass
        time.sleep(delay + delay * x)
    else:
        return False
    hook.add(message='AAD role propagation done', value=1.0, total_val=1.0)
    logger.info('AAD role propagation done')
    return True


def _get_subscription_id():
    _, sub_id, _ = Profile().get_login_credentials(subscription_id=None)
    return sub_id


def _get_default_dns_prefix(name, resource_group_name, subscription_id):
    # Use subscription id to provide uniqueness and prevent DNS name clashes
    name_part = re.sub('[^A-Za-z0-9-]', '', name)[0:10]
    if not name_part[0].isalpha():
        name_part = (str('a') + name_part)[0:10]
    resource_group_part = re.sub('[^A-Za-z0-9-]', '', resource_group_name)[0:16]
    return '{}-{}-{}'.format(name_part, resource_group_part, subscription_id[0:6])


def _ensure_service_principal(service_principal=None,
                              client_secret=None,
                              subscription_id=None,
                              dns_name_prefix=None,
                              location=None,
                              name=None):
    # TODO: This really needs to be unit tested.
    client = _graph_client_factory()
    if not service_principal:
        # --service-principal not specified, try to load it from local disk
        principalObj = load_acs_service_principal(subscription_id)
        if principalObj:
            service_principal = principalObj.get('service_principal')
            client_secret = principalObj.get('client_secret')
            _validate_service_principal(client, service_principal)
        else:
            # Nothing to load, make one.
            if not client_secret:
                client_secret = binascii.b2a_hex(os.urandom(10)).decode('utf-8')
            salt = binascii.b2a_hex(os.urandom(3)).decode('utf-8')
            url = 'http://{}.{}.{}.cloudapp.azure.com'.format(salt, dns_name_prefix, location)

            service_principal = _build_service_principal(client, name, url, client_secret)
            if not service_principal:
                raise CLIError('Could not create a service principal with the right permissions. '
                               'Are you an Owner on this project?')
            logger.info('Created a service principal: %s', service_principal)
            store_acs_service_principal(subscription_id, client_secret, service_principal)
        # Either way, update the role assignment, this fixes things if we fail part-way through
        if not _add_role_assignment('Contributor', service_principal):
            raise CLIError('Could not create a service principal with the right permissions. '
                           'Are you an Owner on this project?')
    else:
        # --service-principal specfied, validate --client-secret was too
        if not client_secret:
            raise CLIError('--client-secret is required if --service-principal is specified')
        _validate_service_principal(client, service_principal)


def store_acs_service_principal(subscription_id, client_secret, service_principal,
                                config_path=os.path.join(get_config_dir(),
                                                         'acsServicePrincipal.json')):
    obj = {}
    if client_secret:
        obj['client_secret'] = client_secret
    if service_principal:
        obj['service_principal'] = service_principal

    fullConfig = load_acs_service_principals(config_path=config_path)
    if not fullConfig:
        fullConfig = {}
    fullConfig[subscription_id] = obj

    with os.fdopen(os.open(config_path, os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o600),
                   'w+') as spFile:
        json.dump(fullConfig, spFile)


def load_acs_service_principal(subscription_id, config_path=os.path.join(get_config_dir(),
                                                                         'acsServicePrincipal.json')):
    config = load_acs_service_principals(config_path)
    if not config:
        return None
    return config.get(subscription_id)


def load_acs_service_principals(config_path):
    if not os.path.exists(config_path):
        return None
    fd = os.open(config_path, os.O_RDONLY)
    try:
        with os.fdopen(fd) as f:
            return shell_safe_json_parse(f.read())
    except:  # pylint: disable=bare-except
        return None


def _handle_merge(existing, addition, key):
    if addition[key]:
        if existing[key] is None:
            existing[key] = addition[key]
            return

        for i in addition[key]:
            if i not in existing[key]:
                existing[key].append(i)


def merge_kubernetes_configurations(existing_file, addition_file):
    try:
        with open(existing_file) as stream:
            existing = yaml.safe_load(stream)
    except (IOError, OSError) as ex:
        if getattr(ex, 'errno', 0) == errno.ENOENT:
            raise CLIError('{} does not exist'.format(existing_file))
        else:
            raise
    except yaml.parser.ParserError as ex:
        raise CLIError('Error parsing {} ({})'.format(existing_file, str(ex)))

    try:
        with open(addition_file) as stream:
            addition = yaml.safe_load(stream)
    except (IOError, OSError) as ex:
        if getattr(ex, 'errno', 0) == errno.ENOENT:
            raise CLIError('{} does not exist'.format(existing_file))
        else:
            raise
    except yaml.parser.ParserError as ex:
        raise CLIError('Error parsing {} ({})'.format(addition_file, str(ex)))

    if addition is None:
        raise CLIError('failed to load additional configuration from {}'.format(addition_file))

    if existing is None:
        existing = addition
    else:
        _handle_merge(existing, addition, 'clusters')
        _handle_merge(existing, addition, 'users')
        _handle_merge(existing, addition, 'contexts')
        existing['current-context'] = addition['current-context']

    with open(existing_file, 'w+') as stream:
        yaml.dump(existing, stream, default_flow_style=True)

    current_context = addition.get('current-context', 'UNKNOWN')
    msg = 'Merged "{}" as current context in {}'.format(current_context, existing_file)
    print(msg)


def show_service_principal(client, identifier):
    object_id = _resolve_service_principal(client, identifier)
    return client.get(object_id)


def _resolve_service_principal(client, identifier):
    # todo: confirm with graph team that a service principal name must be unique
    result = list(client.list(filter="servicePrincipalNames/any(c:c eq '{}')".format(identifier)))
    if result:
        return result[0].object_id
    try:
        uuid.UUID(identifier)
        return identifier  # assume an object id
    except ValueError:
        raise CLIError("service principal '{}' doesn't exist".format(identifier))


def create_application(client, display_name, homepage, identifier_uris,
                       available_to_other_tenants=False, password=None, reply_urls=None,
                       key_value=None, key_type=None, key_usage=None, start_date=None,
                       end_date=None):
    password_creds, key_creds = _build_application_creds(password, key_value, key_type,
                                                         key_usage, start_date, end_date)

    app_create_param = ApplicationCreateParameters(available_to_other_tenants,
                                                   display_name,
                                                   identifier_uris,
                                                   homepage=homepage,
                                                   reply_urls=reply_urls,
                                                   key_credentials=key_creds,
                                                   password_credentials=password_creds)
    return client.create(app_create_param)


def _build_application_creds(password=None, key_value=None, key_type=None,
                             key_usage=None, start_date=None, end_date=None):
    if password and key_value:
        raise CLIError('specify either --password or --key-value, but not both.')

    if not start_date:
        start_date = datetime.datetime.utcnow()
    elif isinstance(start_date, str):
        start_date = dateutil.parser.parse(start_date)

    if not end_date:
        end_date = start_date + relativedelta(years=1)
    elif isinstance(end_date, str):
        end_date = dateutil.parser.parse(end_date)

    key_type = key_type or 'AsymmetricX509Cert'
    key_usage = key_usage or 'Verify'

    password_creds = None
    key_creds = None
    if password:
        password_creds = [PasswordCredential(start_date, end_date, str(uuid.uuid4()), password)]
    elif key_value:
        key_creds = [KeyCredential(start_date, end_date, key_value, str(uuid.uuid4()), key_usage, key_type)]

    return (password_creds, key_creds)


def create_service_principal(identifier, resolve_app=True, client=None):
    if client is None:
        client = _graph_client_factory()

    if resolve_app:
        try:
            uuid.UUID(identifier)
            result = list(client.applications.list(filter="appId eq '{}'".format(identifier)))
        except ValueError:
            result = list(client.applications.list(
                filter="identifierUris/any(s:s eq '{}')".format(identifier)))

        if not result:  # assume we get an object id
            result = [client.applications.get(identifier)]
        app_id = result[0].app_id
    else:
        app_id = identifier

    return client.service_principals.create(ServicePrincipalCreateParameters(app_id, True))


def create_role_assignment(role, assignee, resource_group_name=None, scope=None):
    return _create_role_assignment(role, assignee, resource_group_name, scope)


def _create_role_assignment(role, assignee, resource_group_name=None, scope=None,
                            resolve_assignee=True):
    factory = _auth_client_factory(scope)
    assignments_client = factory.role_assignments
    definitions_client = factory.role_definitions

    scope = _build_role_scope(resource_group_name, scope,
                              assignments_client.config.subscription_id)

    role_id = _resolve_role_id(role, scope, definitions_client)
    object_id = _resolve_object_id(assignee) if resolve_assignee else assignee
    properties = RoleAssignmentProperties(role_id, object_id)
    assignment_name = uuid.uuid4()
    custom_headers = None
    return assignments_client.create(scope, assignment_name, properties,
                                     custom_headers=custom_headers)


def _build_role_scope(resource_group_name, scope, subscription_id):
    subscription_scope = '/subscriptions/' + subscription_id
    if scope:
        if resource_group_name:
            err = 'Resource group "{}" is redundant because scope is supplied'
            raise CLIError(err.format(resource_group_name))
    elif resource_group_name:
        scope = subscription_scope + '/resourceGroups/' + resource_group_name
    else:
        scope = subscription_scope
    return scope


def _resolve_role_id(role, scope, definitions_client):
    role_id = None
    try:
        uuid.UUID(role)
        role_id = role
    except ValueError:
        pass
    if not role_id:  # retrieve role id
        role_defs = list(definitions_client.list(scope, "roleName eq '{}'".format(role)))
        if not role_defs:
            raise CLIError("Role '{}' doesn't exist.".format(role))
        elif len(role_defs) > 1:
            ids = [r.id for r in role_defs]
            err = "More than one role matches the given name '{}'. Please pick a value from '{}'"
            raise CLIError(err.format(role, ids))
        role_id = role_defs[0].id
    return role_id


def _resolve_object_id(assignee):
    client = _graph_client_factory()
    result = None
    if assignee.find('@') >= 0:  # looks like a user principal name
        result = list(client.users.list(filter="userPrincipalName eq '{}'".format(assignee)))
    if not result:
        result = list(client.service_principals.list(
            filter="servicePrincipalNames/any(c:c eq '{}')".format(assignee)))
    if not result:  # assume an object id, let us verify it
        result = _get_object_stubs(client, [assignee])

    # 2+ matches should never happen, so we only check 'no match' here
    if not result:
        raise CLIError("No matches in graph database for '{}'".format(assignee))

    return result[0].object_id


def _get_object_stubs(graph_client, assignees):
    params = GetObjectsParameters(include_directory_object_references=True,
                                  object_ids=assignees)
    return list(graph_client.objects.get_objects_by_object_ids(params))


def _remove_nulls(managed_clusters):
    """
    Remove some often-empty fields from a list of ManagedClusters, so the JSON representation
    doesn't contain distracting null fields.

    This works around a quirk of the SDK for python behavior. These fields are not sent
    by the server, but get recreated by the CLI's own "to_dict" serialization.
    """
    attrs = ['tags']
    ap_attrs = ['dns_prefix', 'fqdn', 'os_disk_size_gb', 'ports', 'vnet_subnet_id']
    sp_attrs = ['key_vault_secret_ref', 'secret']
    for managed_cluster in managed_clusters:
        for attr in attrs:
            try:
                if getattr(managed_cluster, attr) is None:
                    delattr(managed_cluster, attr)
            except AttributeError:
                pass
        props = managed_cluster.properties
        for ap_profile in props.agent_pool_profiles:
            for attr in ap_attrs:
                try:
                    if getattr(ap_profile, attr) is None:
                        delattr(ap_profile, attr)
                except AttributeError:
                    pass
        for attr in sp_attrs:
            try:
                if getattr(props.service_principal_profile, attr) is None:
                    delattr(props.service_principal_profile, attr)
            except AttributeError:
                pass
    return managed_clusters


def aks_list(client, resource_group_name=None):
    """List managed Kubernetes clusters."""
    if resource_group_name:
        managed_clusters = client.list_by_resource_group(resource_group_name)
    else:
        managed_clusters = client.list()
    return _remove_nulls(list(managed_clusters))


def aks_show(client, resource_group_name, name):
    """Show a managed Kubernetes cluster."""
    mc = client.get(resource_group_name, name)
    return _remove_nulls([mc, ])[0]


def aks_browse(client, resource_group_name, name, disable_browser=False):
    """
    Open a web browser to the dashboard for a managed Kubernetes cluster.

    :param name: Name of the Azure managed cluster.
    :type name: String
    :param resource_group_name: Name of Azure managed cluster's resource group.
    :type resource_group_name: String
    :param disable_browser: If true, don't launch a web browser after estabilishing the
     kubectl proxy
    :type disable_browser: bool
    """
    if not which('kubectl'):
        raise CLIError('Can not find kubectl executable in PATH')

    with tempfile.NamedTemporaryFile(mode='w+t') as kube_config:
        browse_path = kube_config.name
        # TODO: need to add an --admin option?
        aks_get_credentials(client, resource_group_name, name, admin=False, path=browse_path)
        logger.warning('Proxy running on 127.0.0.1:8001/ui')
        logger.warning('Press CTRL+C to close the tunnel...')
        if not disable_browser:
            wait_then_open_async('http://127.0.0.1:8001/ui')
        subprocess.call(["kubectl", "--kubeconfig", browse_path, "proxy"])


def aks_create(client, resource_group_name, name, ssh_key_value,  # pylint: disable=too-many-locals
               dns_name_prefix=None,
               location=None,
               admin_username="azureuser",
               kubernetes_version="1.6.11",
               agent_vm_size="Standard_D2_v2",
               agent_osdisk_size=0,
               agent_count=3,
               service_principal=None, client_secret=None,
               tags=None,
               generate_ssh_keys=False,  # pylint: disable=unused-argument
               no_wait=False):
    """Create a managed Kubernetes cluster.
    :param resource_group_name: The name of the resource group. The name
     is case insensitive.
    :type resource_group_name: str
    :param dns_name_prefix: Sets the Domain name prefix for the cluster.
     The concatenation of the domain name and the regionalized DNS zone
     make up the fully qualified domain name associated with the public
     IP address.
    :type dns_name_prefix: str
    :param location: Location for VM resources.
    :type location: str
    :param name: Resource name for the managed cluster.
    :type name: str
    :param ssh_key_value: Configure all linux machines with the SSH RSA
     public key string.  Your key should include three parts, for example
    'ssh-rsa AAAAB...snip...UcyupgH azureuser@linuxvm
    :type ssh_key_value: str
    :param admin_username: User name for the Linux Virtual Machines.
    :type admin_username: str
    :param kubernetes_version: The version of Kubernetes to use for creating
     the cluster, such as '1.7.7' or '1.8.1'.
    :type kubernetes_version: str
    :param agent_count: the default number of agents for the agent pools.
    :type agent_count: int
    :param agent_vm_size: The size of the Virtual Machine.
    :type agent_vm_size: str
    :param agent_osdisk_size: The osDisk size in GB of agent pool Virtual Machine
    :type agent_osdisk_size: int
    :param service_principal: The service principal used for cluster authentication
     to Azure APIs. If not specified, it is created for you and stored in the
     ${HOME}/.azure directory.
    :type service_principal: str
    :param client_secret: The secret associated with the service principal. If
     --service-principal is specified, then secret should also be specified. If
     --service-principal is not specified, the secret is auto-generated for you
     and stored in ${HOME}/.azure/ directory.
    :param tags: Tags object.
    :type tags: object
    :param no_wait: Start creating but return immediately instead of waiting
     until the managed cluster is created.
    :type no_wait: bool
    """
    try:
        if not ssh_key_value or not _is_valid_ssh_rsa_public_key(ssh_key_value):
            raise ValueError()
    except:
        shortened_key = '{} ... {}'.format(ssh_key_value[:30], ssh_key_value[-30:]).strip()
        logger.error('Provided ssh key ({}) is invalid or non-existent'.format(shortened_key))
        raise

    subscription_id = _get_subscription_id()
    if not dns_name_prefix:
        dns_name_prefix = _get_default_dns_prefix(name, resource_group_name, subscription_id)

    register_providers()
    groups = _resource_client_factory().resource_groups
    # Just do the get, we don't need the result, it will error out if the group doesn't exist.
    rg = groups.get(resource_group_name)
    if location is None:
        location = rg.location  # pylint:disable=no-member

    ssh_config = ContainerServiceSshConfiguration(
        [ContainerServiceSshPublicKey(key_data=ssh_key_value)])
    agent_pool_profile = ContainerServiceAgentPoolProfile(
        name,
        count=int(agent_count),
        vm_size=agent_vm_size,
        dns_prefix=dns_name_prefix,
        os_type="Linux",
        storage_profile=ContainerServiceStorageProfileTypes.managed_disks
    )
    if agent_osdisk_size:
        agent_pool_profile.os_disk_size_gb = int(agent_osdisk_size)

    linux_profile = ContainerServiceLinuxProfile(admin_username, ssh=ssh_config)
    _ensure_service_principal(service_principal=service_principal, client_secret=client_secret,
                              subscription_id=subscription_id, dns_name_prefix=dns_name_prefix,
                              location=location, name=name)
    principalObj = load_acs_service_principal(subscription_id)
    if not client_secret:
        client_secret = principalObj.get("client_secret")
    if not service_principal:
        service_principal = principalObj.get("service_principal")
    service_principal_profile = ContainerServiceServicePrincipalProfile(
        client_id=service_principal, secret=client_secret, key_vault_secret_ref=None)

    props = ManagedClusterProperties(
        dns_prefix=dns_name_prefix,
        kubernetes_version=kubernetes_version,
        agent_pool_profiles=[agent_pool_profile, ],
        linux_profile=linux_profile,
        service_principal_profile=service_principal_profile)
    mc = ManagedCluster(location=location, tags=tags, properties=props)

    # print payload for debugging
    logger.debug(json.dumps(mc.serialize(), indent=2, sort_keys=True))

    response = client.create_or_update(
        resource_group_name=resource_group_name,
        resource_name=name,
        parameters=mc,
        raw=no_wait)
    if no_wait:
        raw = response.response
        if raw.status_code in (200, 201):
            logger.warn("\nCreate request for {} successfully received.".format(name))
        else:
            msg = "Create request for {} returned {}: {}.".format(
                name, raw.status_code, raw.reason)
            raise CLIError(msg)
    else:
        return response


def aks_delete(client, resource_group_name, name, no_wait=False):
    """Delete a managed Kubernetes cluster.
    :param resource_group_name: The name of the resource group. The name
     is case insensitive.
    :type resource_group_name: str
    :param name: Resource name for the managed cluster.
    :type name: str
    :param no_wait: Start deleting but return immediately instead of waiting
     until the managed cluster is deleted.
    :type no_wait: bool
    """
    response = client.delete(resource_group_name, name, raw=no_wait)
    if no_wait:
        raw = response.response
        if raw.status_code == 202:
            logger.warn("Delete request for {} successfully received.".format(name))
        else:
            msg = "Delete request for {} returned {}: {}.".format(
                name, raw.status_code, raw.reason)
            raise CLIError(msg)
    else:
        return response


def aks_get_credentials(client, resource_group_name, name, admin=False,
                        path=os.path.join(os.path.expanduser('~'), '.kube', 'config')):
    """Get access credentials for a managed Kubernetes cluster.
    :param path: A kubectl config file to create or update. Use "-" to print YAML
     to stdout instead
    :type path: str
    :param admin: Get the "clusterAdmin" kubectl config instead of the default "clusterUser"
    :type admin: bool
    """
    mc = aks_show(client, resource_group_name, name)
    access_profiles = mc.properties.access_profiles
    if not access_profiles:
        msg = "No Kubernetes access profiles found. Cluster provisioning state is \"{}\"."
        raise CLIError(msg.format(mc.properties.provisioning_state))
    else:
        access_profiles = access_profiles.as_dict()
        access_profile = access_profiles.get('cluster_admin' if admin else 'cluster_user')
        encoded_kubeconfig = access_profile.get('kube_config')
        kubeconfig = base64.b64decode(encoded_kubeconfig).decode(encoding='UTF-8')

        # Special case for printing to stdout
        if path == "-":
            print(kubeconfig)
            return

        # ensure that at least an empty ~/.kube/config exists
        directory = os.path.dirname(path)
        if not os.path.exists(directory):
            try:
                os.makedirs(directory)
            except OSError as ex:
                if ex.errno != errno.EEXIST:
                    raise
        if not os.path.exists(path):
            with open(path, 'w+t'):
                pass

        # merge the new kubeconfig into the existing one
        with tempfile.NamedTemporaryFile(mode='w+t') as additional_file:
            additional_file.write(kubeconfig)
            additional_file.flush()
            try:
                merge_kubernetes_configurations(path, additional_file.name)
            except yaml.YAMLError as ex:
                logger.warning('Failed to merge credentials to kube config file: %s', ex)


def aks_scale(client, resource_group_name, name, agent_count):
    """Change the number of agent nodes in a managed Kubernetes cluster.
    :param resource_group_name: The name of the resource group. The name
     is case insensitive.
    :type resource_group_name: str
    :param name: Resource name for the managed cluster.
    :type name: str
    :param agent_count: The desired number of agent nodes.
    :type agent_count: int
    """
    instance = client.get(resource_group_name, name)
    instance.properties.agent_pool_profiles[0].count = int(agent_count)  # pylint: disable=no-member

    # null out the service principal because otherwise validation complains
    instance.properties.service_principal_profile = None

    return client.create_or_update(resource_group_name, name, instance)


def aks_upgrade(client, resource_group_name, name, kubernetes_version):
    """Upgrade a managed Kubernetes cluster to a newer version.
    :param resource_group_name: The name of the resource group. The name
     is case insensitive.
    :type resource_group_name: str
    :param name: Resource name for the managed cluster.
    :type name: str
    :param kubernetes_version: The version of Kubernetes to upgrade the cluster to,
    such as '1.7.7' or '1.8.1'.
    :type kubernetes_version: str
    """
    instance = client.get(resource_group_name, name)
    instance.properties.kubernetes_release = None
    instance.properties.kubernetes_version = kubernetes_version

    # null out the service principal because otherwise validation complains
    instance.properties.service_principal_profile = None

    return client.create_or_update(resource_group_name, name, instance)


def aks_get_versions(client, resource_group_name, name):
    """Get versions available for upgrading a managed Kubernetes cluster.
    :param resource_group_name: The name of the resource group. The name
     is case insensitive.
    :type resource_group_name: str
    :param name: Resource name for the managed cluster.
    :type name: str
    """
    return client.get_upgrade_profile(resource_group_name, name)

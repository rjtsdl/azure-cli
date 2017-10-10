# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import os
import platform

from argcomplete.completers import FilesCompleter

from azure.cli.core.commands import CliArgumentType
from azure.cli.core.commands import register_cli_argument
from azure.cli.core.commands import register_extra_cli_argument
from azure.cli.core.commands.parameters import file_type
from azure.cli.core.commands.parameters import get_one_of_subscription_locations
from azure.cli.core.commands.parameters import resource_group_name_type
from azure.cli.core.commands.parameters import tags_type
from azure.cli.command_modules.aks._validators import validate_create_parameters
from azure.cli.command_modules.aks._validators import validate_k8s_version
from azure.cli.command_modules.aks._validators import validate_linux_host_name
from azure.cli.command_modules.aks._validators import validate_ssh_key


def _compute_client_factory(**_):
    from azure.cli.core.profiles import ResourceType
    from azure.cli.core.commands.client_factory import get_mgmt_service_client
    return get_mgmt_service_client(ResourceType.MGMT_COMPUTE)


def get_vm_sizes(location):
    return list(_compute_client_factory().virtual_machine_sizes.list(location))


def get_vm_size_completion_list(prefix, action, parsed_args, **kwargs):  # pylint: disable=unused-argument
    try:
        location = parsed_args.location
    except AttributeError:
        location = get_one_of_subscription_locations()
    result = get_vm_sizes(location)
    return [r.name for r in result]


def _get_default_install_location(exe_name):
    system = platform.system()
    if system == 'Windows':
        program_files = os.environ.get('ProgramFiles')
        if not program_files:
            return None
        install_location = '{}\\{}.exe'.format(program_files, exe_name)
    elif system == 'Linux' or system == 'Darwin':
        install_location = '/usr/local/bin/{}'.format(exe_name)
    else:
        install_location = None
    return install_location


name_arg_type = CliArgumentType(options_list=('--name', '-n'), metavar='NAME')
k8s_release_arg_type = CliArgumentType(options_list=('--kubernetes-version', '-k'), metavar='KUBERNETES_VERSION')

# Managed Clusters flags configuration
register_cli_argument('aks', 'name', arg_type=name_arg_type)
register_cli_argument('aks', 'resource_group', arg_type=resource_group_name_type)
register_cli_argument('aks', 'tags', tags_type)

register_cli_argument('aks create', 'ssh_key_value', required=False,
                      help='SSH key file value or key file path.', type=file_type,
                      default=os.path.join('~', '.ssh', 'id_rsa.pub'), completer=FilesCompleter(),
                      validator=validate_ssh_key)
register_cli_argument('aks create', 'name', arg_type=name_arg_type, validator=validate_linux_host_name)
register_extra_cli_argument('aks create', 'generate_ssh_keys', action='store_true',
                            help='Generate SSH public and private key files if missing',
                            validator=validate_create_parameters)
register_cli_argument('aks create', 'kubernetes_version', arg_type=k8s_release_arg_type,
                      validator=validate_k8s_version)
register_cli_argument('aks create', 'admin_username', options_list=('--admin-username', '-u'))
register_cli_argument('aks create', 'agent_vm_size', options_list=('--agent-vm-size', '-s'),
                      completer=get_vm_size_completion_list)
register_cli_argument('aks create', 'agent_count', options_list=('--agent-count', '-c'))
register_cli_argument('aks create', 'dns_name_prefix', options_list=('--dns-name-prefix', '-p'))
register_cli_argument('aks get-credentials', 'path', options_list=('--file', '-f',),
                      default=os.path.join(os.path.expanduser('~'), '.kube', 'config'),
                      type=file_type, completer=FilesCompleter())
register_cli_argument('aks get-credentials', 'admin', options_list=('--admin', '-a'), default=False)
register_cli_argument('aks scale', 'agent_count', options_list=('--agent-count', '-c'))
register_cli_argument('aks upgrade', 'kubernetes_version', arg_type=k8s_release_arg_type,
                      validator=validate_k8s_version)
register_cli_argument('aks upgrade', 'name', arg_type=name_arg_type, validator=validate_linux_host_name)
register_cli_argument('aks wait', 'resource_name', options_list=('--name', '-n'))
register_cli_argument('aks install-cli', 'install_location', options_list=('--install-location',),
                      default=_get_default_install_location('kubectl'))

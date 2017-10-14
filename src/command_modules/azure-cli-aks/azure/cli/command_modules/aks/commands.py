# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from collections import OrderedDict

from azure.cli.core.commands import cli_command
from azure.cli.core.commands.arm import cli_generic_wait_command
from azure.cli.core.profiles import PROFILE_TYPE
from azure.cli.core.profiles import supported_api_version

from ._client_factory import _aks_client_factory


def aks_list_table_format(results):
    """"Format a list of managed clusters as summary results for display with "-o table"."""
    return [aks_show_table_format(r) for r in results]


def aks_show_table_format(result):
    """Format a managed cluster as summary results for display with "-o table"."""
    # move some nested properties up to top-level values
    properties = result.get('properties', {})
    promoted = ['kubernetesVersion', 'provisioningState', 'fqdn']
    result.update({k: properties.get(k) for k in promoted})

    columns = ['name', 'location', 'resourceGroup'] + promoted
    # put results in an ordered dict so the headers are predictable
    return OrderedDict({k: result.get(k) for k in columns})


if not supported_api_version(PROFILE_TYPE, max_api='2017-08-31-profile'):
    cli_command(__name__, 'aks browse',
                'azure.cli.command_modules.aks.custom#aks_browse', _aks_client_factory)
    cli_command(__name__, 'aks create',
                'azure.cli.command_modules.aks.custom#aks_create', _aks_client_factory)
    cli_command(__name__, 'aks delete',
                'azure.cli.command_modules.aks.custom#aks_delete', _aks_client_factory)
    cli_command(__name__, 'aks get-credentials',
                'azure.cli.command_modules.aks.custom#aks_get_credentials', _aks_client_factory)
    cli_command(__name__, 'aks get-versions',
                'azure.cli.command_modules.aks.custom#aks_get_versions', _aks_client_factory)
    cli_command(__name__, 'aks install-cli',
                'azure.cli.command_modules.aks.custom#aks_install_cli')
    cli_command(__name__, 'aks list',
                'azure.cli.command_modules.aks.custom#aks_list', _aks_client_factory,
                table_transformer=aks_list_table_format)
    cli_command(__name__, 'aks scale',
                'azure.cli.command_modules.aks.custom#aks_scale', _aks_client_factory)
    cli_command(__name__, 'aks show',
                'azure.cli.command_modules.aks.custom#aks_show', _aks_client_factory,
                table_transformer=aks_show_table_format)
    cli_command(__name__, 'aks upgrade',
                'azure.cli.command_modules.aks.custom#aks_upgrade', _aks_client_factory)
    cli_generic_wait_command(__name__, 'aks wait',
                             'azure.mgmt.containerservice.operations.managed_clusters_operations' +
                             '#ManagedClustersOperations.get',
                             _aks_client_factory)

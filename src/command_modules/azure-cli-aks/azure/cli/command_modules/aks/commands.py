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
    """Move some important nested properties up to the top level for --output=table format."""
    table_results = []

    for result in results:
        table_results.append(aks_show_table_format(result))
    return table_results


def aks_show_table_format(result):
    """Move some important nested properties up to the top level for --output=table format."""
    # move kubernetesVersion and provisioningState up to primary values
    properties = result.get('properties', {})
    result['kubernetesVersion'] = properties.get('kubernetesVersion')
    result['provisioningState'] = properties.get('provisioningState')
    result['fqdn'] = properties.get('fqdn')
    # translate results into an ordered dictionary so the headers are predictably ordered
    table_result = OrderedDict()
    for item in ['name', 'location', 'resourceGroup',
                 'kubernetesVersion', 'provisioningState', 'fqdn']:
        table_result[item] = result.get(item)
    return table_result


if not supported_api_version(PROFILE_TYPE, max_api='2017-08-31-profile'):
    # managed clusters commands
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

# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
import tempfile

from azure.cli.testsdk import (ScenarioTest, ResourceGroupPreparer, JMESPathCheck)


class AzureKubernetesServiceScenarioTest(ScenarioTest):
    @ResourceGroupPreparer()
    def test_aks_create_default_service(self, resource_group, resource_group_location):
        # the simplest aks create scenario
        loc = resource_group_location
        ssh_pubkey_file = self.generate_ssh_keys()
        acs_name = self.create_random_name('cliakstest', 16)
        dns_prefix = self.create_random_name('cliasdns', 16)

        # create
        ssh_pubkey_file = ssh_pubkey_file.replace('\\', '\\\\')
        create_cmd = 'aks create -g {} -n {} --dns-name-prefix {} --ssh-key-value {}'
        self.cmd(create_cmd.format(resource_group, acs_name, dns_prefix, ssh_pubkey_file), checks=[
            JMESPathCheck('properties.outputs.fqdn.value', '{}.hcp.{}.azmk8s.io'.format(dns_prefix, loc))
        ])

        # show
        self.cmd('aks show -g {} -n {}'.format(resource_group, acs_name), checks=[
            JMESPathCheck('type', 'Microsoft.ContainerService/ManagedClusters'),
            JMESPathCheck('name', acs_name),
            JMESPathCheck('resourceGroup', resource_group),
            JMESPathCheck('properties.agentPoolProfiles[0].count', 3),
            JMESPathCheck('properties.agentPoolProfiles[0].vmSize', 'Standard_D2_v2'),
            JMESPathCheck('properties.dnsPrefix', dns_prefix)
        ])

        # scale-up
        self.cmd('aks scale -g {} -n {} --agent-count 5'.format(resource_group, acs_name), checks=[
            JMESPathCheck('properties.agentPoolProfiles[0].count', 5)
        ])

        # show again
        self.cmd('aks show -g {} -n {}'.format(resource_group, acs_name), checks=[
            JMESPathCheck('agentPoolProfiles[0].count', 5)
        ])

    @ResourceGroupPreparer()
    def test_aks_create_with_upgrade(self, resource_group, resource_group_location):
        # test create a lower version cluster, then followed by a upgrade command
        pass

    @classmethod
    def generate_ssh_keys(cls):
        TEST_SSH_KEY_PUB = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCbIg1guRHbI0lV11wWDt1r2cUdcNd27CJsg+SfgC7miZeubtwUhbsPdhMQsfDyhOWHq1+ZL0M+nJZV63d/1dhmhtgyOqejUwrPlzKhydsbrsdUor+JmNJDdW01v7BXHyuymT8G4s09jCasNOwiufbP/qp72ruu0bIA1nySsvlf9pCQAuFkAnVnf/rFhUlOkhtRpwcq8SUNY2zRHR/EKb/4NWY1JzR4sa3q2fWIJdrrX0DvLoa5g9bIEd4Df79ba7v+yiUBOS0zT2ll+z4g9izHK3EO5d8hL4jYxcjKs+wcslSYRWrascfscLgMlMGh0CdKeNTDjHpGPncaf3Z+FwwwjWeuiNBxv7bJo13/8B/098KlVDl4GZqsoBCEjPyJfV6hO0y/LkRGkk7oHWKgeWAfKtfLItRp00eZ4fcJNK9kCaSMmEugoZWcI7NGbZXzqFWqbpRI7NcDP9+WIQ+i9U5vqWsqd/zng4kbuAJ6UuKqIzB0upYrLShfQE3SAck8oaLhJqqq56VfDuASNpJKidV+zq27HfSBmbXnkR/5AK337dc3MXKJypoK/QPMLKUAP5XLPbs+NddJQV7EZXd29DLgp+fRIg3edpKdO7ZErWhv7d+3Kws+e1Y+ypmR2WIVSwVyBEUfgv2C8Ts9gnTF4pNcEY/S2aBicz5Ew2+jdyGNQQ== test@example.com\n"  # pylint: disable=line-too-long
        _, pathname = tempfile.mkstemp()
        with open(pathname, 'w') as key_file:
            key_file.write(TEST_SSH_KEY_PUB)
        return pathname

# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from azure.cli.testsdk import (ScenarioTest, ResourceGroupPreparer)

class AzureKubernetesServiceScenarioTest(ScenarioTest):
    @ResourceGroupPreparer()
    def test_aks_create_happy_path(self, resource_group, resource_group_location):
        # the simplest aks create scenario
        pass
    
    @ResourceGroupPreparer()
    def test_aks_create_with_scale(self, resoure_group, resource_group_location):
        # test create then follow by a scale command
        pass

    @ResourceGroupPreparer()
    def test_aks_create_with_upgrade(self, resource_group, resource_group_location):
        # test create a lower version cluster, then followed by a upgrade command
        pass

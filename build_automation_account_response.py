#!/usr/bin/env python3
"""Generates azuredeploy-automation-account-response.json.

Deploys the Azure Automation Account infrastructure that
ErgoSOC-AU-Email-BlockSenderAndQuarantine's optional AutoExecuteBlock mode
calls into: an Automation Account, the ExchangeOnlineManagement PowerShell
module, and an (empty) PowerShell 7.2 runbook resource named to match
runbooks/Set-ErgoSOC-TenantBlockListItem.ps1.

ARM can declare the runbook resource, but reliably inlining multi-line
PowerShell as JSON is fragile and not how this is actually done in
practice -- so this template creates the empty runbook, and the actual
script content is published in a one-time CLI step documented in
README-RESPONSE.md (az automation runbook replace-content + publish),
same pattern as the "authorise the API connection" one-time step every
other playbook in this repo already needs.

The Automation Account is assigned the SAME user-assigned managed
identity used by the rest of this repo's playbooks (reused, not a
dedicated one -- a deliberate choice: it keeps things simple at the cost
of that one identity spanning Entra ID, Defender for Endpoint, ARM, and
(once you grant it the Exchange Online role below) Exchange Online too).
The runbook authenticates to Exchange Online AS that identity via
Connect-ExchangeOnline -ManagedIdentity -- no certificate, no separate
app registration, no private key to generate or store. You still have to
register the UAMI as an Exchange Online service principal and grant it a
scoped role there; that's Exchange Online's own RBAC system and has
nothing to do with Azure RBAC or Graph app roles, so it can't be
ARM-templated either -- see README-RESPONSE.md for the one-time EXO
PowerShell steps.
"""
import pathlib

from response_common import write_template

HERE = pathlib.Path(__file__).resolve().parent


def build_template():
    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "metadata": {
            "title": "ErgoSOC-AU response infrastructure: Automation Account for Exchange Online actions",
            "description": "Deploys an Azure Automation Account (assigned the same UAMI as the rest of this repo's playbooks), the ExchangeOnlineManagement module, and an empty PowerShell 7.2 runbook that ErgoSOC-AU-Email-BlockSenderAndQuarantine's AutoExecuteBlock mode calls to actually write to the Tenant Allow/Block List. Publish the runbook's content (runbooks/Set-ErgoSOC-TenantBlockListItem.ps1) and register the UAMI as an Exchange Online service principal per README-RESPONSE.md before turning AutoExecuteBlock on.",
            "prerequisites": "The same existing user-assigned managed identity used elsewhere in this repo.",
            "postDeployment": [
                "Publish the runbook content: az automation runbook replace-content + az automation runbook publish (see README-RESPONSE.md).",
                "Register the UAMI as an Exchange Online service principal and grant it a role scoped to the Tenant Allow/Block List (EXO PowerShell, one-time, run by an admin -- see README-RESPONSE.md).",
                "Grant the same UAMI the Automation Job Operator Azure RBAC role scoped to this Automation Account, so the email playbook can start runbook jobs.",
            ],
            "lastUpdateTime": "2026-09-02",
            "tags": ["Response", "Email", "Automation Account", "Exchange Online"],
            "support": {"tier": "community"},
        },
        "parameters": {
            "UserAssignedManagedIdentityResourceId": {
                "type": "string", "minLength": 1,
                "metadata": {"description": "Required. Full resource ID of the existing user-assigned managed identity to assign to the Automation Account (the same one used by the rest of this repo's playbooks, unless you've deliberately created a dedicated one)."},
            },
            "AutomationAccountName": {
                "type": "string", "defaultValue": "ErgoSOC-AU-ResponseAutomation",
                "metadata": {"description": "Name of the Azure Automation Account to create."},
            },
            "RunbookName": {
                "type": "string", "defaultValue": "Set-ErgoSOC-TenantBlockListItem",
                "metadata": {"description": "Name of the runbook resource. Must match the file name (minus .ps1) you publish into it."},
            },
        },
        "resources": [
            {
                "type": "Microsoft.Automation/automationAccounts",
                "apiVersion": "2023-11-01",
                "name": "[parameters('AutomationAccountName')]",
                "location": "[resourceGroup().location]",
                "identity": {
                    "type": "UserAssigned",
                    "userAssignedIdentities": {"[parameters('UserAssignedManagedIdentityResourceId')]": {}},
                },
                "properties": {"sku": {"name": "Basic"}},
            },
            {
                "type": "Microsoft.Automation/automationAccounts/powershell72Modules",
                "apiVersion": "2023-11-01",
                "name": "[concat(parameters('AutomationAccountName'), '/ExchangeOnlineManagement')]",
                "dependsOn": ["[resourceId('Microsoft.Automation/automationAccounts', parameters('AutomationAccountName'))]"],
                "properties": {
                    "contentLink": {"uri": "https://www.powershellgallery.com/api/v2/package/ExchangeOnlineManagement"},
                },
            },
            {
                "type": "Microsoft.Automation/automationAccounts/runbooks",
                "apiVersion": "2023-11-01",
                "name": "[concat(parameters('AutomationAccountName'), '/', parameters('RunbookName'))]",
                "location": "[resourceGroup().location]",
                "dependsOn": [
                    "[resourceId('Microsoft.Automation/automationAccounts', parameters('AutomationAccountName'))]",
                    "[resourceId('Microsoft.Automation/automationAccounts/powershell72Modules', parameters('AutomationAccountName'), 'ExchangeOnlineManagement')]",
                ],
                "properties": {
                    "runbookType": "PowerShell72",
                    "logProgress": False,
                    "logVerbose": False,
                    "description": "Adds a Sender/Domain entry to the Tenant Allow/Block List. Content published separately -- see README-RESPONSE.md.",
                },
            },
        ],
        "outputs": {
            "AutomationAccountResourceId": {
                "type": "string",
                "value": "[resourceId('Microsoft.Automation/automationAccounts', parameters('AutomationAccountName'))]",
            },
            "RunbookName": {"type": "string", "value": "[parameters('RunbookName')]"},
            "ManagedIdentityClientId": {
                "type": "string",
                "value": "[reference(parameters('UserAssignedManagedIdentityResourceId'), '2018-11-30').clientId]",
                "metadata": {"description": "The UAMI's client (application) ID -- pass this as ExoManagedIdentityClientId when deploying the email playbook, and use it in New-ServicePrincipal -AppId when registering it in Exchange Online."},
            },
        },
    }


if __name__ == "__main__":
    write_template(build_template(), "azuredeploy-automation-account-response.json", HERE)

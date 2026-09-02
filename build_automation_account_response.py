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

This template does NOT create the Entra app registration or certificate
the runbook needs for Exchange Online app-only auth -- that's a
credential-bearing step that has no business being ARM-templated (a
private key must never end up in a template or in git). See
README-RESPONSE.md for those steps.
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
            "description": "Deploys an Azure Automation Account, the ExchangeOnlineManagement module, and an empty PowerShell 7.2 runbook that ErgoSOC-AU-Email-BlockSenderAndQuarantine's AutoExecuteBlock mode calls to actually write to the Tenant Allow/Block List. Publish the runbook's content (runbooks/Set-ErgoSOC-TenantBlockListItem.ps1) and set up the app-only Exchange Online auth per README-RESPONSE.md before turning AutoExecuteBlock on.",
            "lastUpdateTime": "2026-09-02",
            "tags": ["Response", "Email", "Automation Account", "Exchange Online"],
            "support": {"tier": "community"},
        },
        "parameters": {
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
        },
    }


if __name__ == "__main__":
    write_template(build_template(), "azuredeploy-automation-account-response.json", HERE)

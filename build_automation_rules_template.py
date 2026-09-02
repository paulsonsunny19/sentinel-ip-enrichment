#!/usr/bin/env python3
"""Generates azuredeploy-automation-rules.json.

Deploys six Microsoft Sentinel automation rules, one per entity type, each
running the matching enrichment playbook only when the incident actually
carries that entity type. This is an optional companion to the six
enrichment playbooks in this repo (azuredeploy.json, azuredeploy-device.json,
azuredeploy-url.json, azuredeploy-filehash.json, azuredeploy-email.json,
azuredeploy-account.json) -- every playbook already self-gates on its own
entity list, so a single "run always" automation rule attached to all six
also works. Splitting into six entity-conditional rules just avoids a
playbook run that can only ever no-op, and keeps the incident's run history
readable.

Condition property names are the values Microsoft Sentinel's automation
rule engine actually supports (AutomationRulePropertyConditionSupportedProperty
in the Microsoft.SecurityInsights RP) -- confirmed against the Azure SDK for
Go's generated constants, not guessed from the Portal's field labels. Two
notes worth calling out:
  - File hash entities only expose FileHashValue as a condition property;
    there is no separate FileHashAlgorithm condition, so that's the only
    property used for the file-hash rule.
  - Mail message entities have no NetworkMessageId condition property.
    MailMessageRecipient is used instead as the existence check (every mail
    message entity has at least one recipient).

Each rule uses operator "Contains" with an empty string as its only
propertyValue -- Sentinel's automation-rule operator set has no dedicated
"exists" operator (Equals/NotEquals/Contains/NotContains/StartsWith/
NotStartsWith/EndsWith/NotEndsWith only), so an empty-value Contains is the
standard existence-check idiom: it matches any incident that has at least
one entity carrying that property, regardless of its actual value.
"""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# (key, display label, default playbook name, condition property, rule order)
RULES = [
    ("IP", "IP address", "Enrich-IP-IncidentComment", "IPAddress", 1),
    ("Device", "host", "Enrich-Device-IncidentComment", "HostName", 2),
    ("Url", "URL", "Enrich-URL-IncidentComment", "Url", 3),
    ("FileHash", "file hash", "Enrich-FileHash-IncidentComment", "FileHashValue", 4),
    ("Email", "mail message", "Enrich-Email-IncidentComment", "MailMessageRecipient", 5),
    ("Account", "account", "Enrich-Account-IncidentComment", "AccountAadUserId", 6),
]

API_VERSION = "2023-02-01-preview"


def build_template():
    parameters = {
        "WorkspaceName": {
            "type": "string",
            "metadata": {
                "description": "Name of the existing Sentinel-enabled Log Analytics workspace to create the automation rules in. Must be the same workspace Sentinel is enabled on."
            },
        }
    }
    resources = []
    outputs = {}

    for key, label, default_playbook, prop, order in RULES:
        playbook_param = f"{key}PlaybookName"
        enable_param = f"Enable{key}Rule"
        var_ruleid = f"{key}RuleId"

        parameters[playbook_param] = {
            "type": "string",
            "defaultValue": default_playbook,
            "metadata": {
                "description": f"Name of the deployed {label} enrichment Logic App this rule should run. Must match that playbook's own PlaybookName parameter."
            },
        }
        parameters[enable_param] = {
            "type": "bool",
            "defaultValue": True,
            "metadata": {
                "description": f"Deploy the automation rule that runs the {label} enrichment playbook. Set to false if you haven't deployed that playbook."
            },
        }

        resources.append(
            {
                "type": "Microsoft.OperationalInsights/workspaces/providers/automationRules",
                "apiVersion": API_VERSION,
                "name": f"[concat(parameters('WorkspaceName'), '/Microsoft.SecurityInsights/', variables('{var_ruleid}'))]",
                "condition": f"[parameters('{enable_param}')]",
                "properties": {
                    "displayName": f"Run {label} enrichment when incident has an {label} entity"
                    if label[0] in "aeiouAEIOU"
                    else f"Run {label} enrichment when incident has a {label} entity",
                    "order": order,
                    "triggeringLogic": {
                        "isEnabled": True,
                        "triggersOn": "Incidents",
                        "triggersWhen": "Created",
                        "conditions": [
                            {
                                "conditionType": "Property",
                                "conditionProperties": {
                                    "propertyName": prop,
                                    "operator": "Contains",
                                    "propertyValues": [""],
                                },
                            }
                        ],
                    },
                    "actions": [
                        {
                            "order": 1,
                            "actionType": "RunPlaybook",
                            "actionConfiguration": {
                                "logicAppResourceId": f"[resourceId('Microsoft.Logic/workflows', parameters('{playbook_param}'))]",
                                "tenantId": "[subscription().tenantId]",
                            },
                        }
                    ],
                },
            }
        )
        outputs[f"{key}AutomationRuleId"] = {
            "type": "string",
            "value": f"[resourceId('Microsoft.OperationalInsights/workspaces/providers/automationRules', parameters('WorkspaceName'), 'Microsoft.SecurityInsights', variables('{var_ruleid}'))]",
        }

    variables = {
        f"{key}RuleId": f"[guid(resourceGroup().id, parameters('WorkspaceName'), '{key}-entity-enrichment-automation-rule')]"
        for key, *_ in RULES
    }

    template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": parameters,
        "variables": variables,
        "resources": resources,
        "outputs": outputs,
    }
    return template


def main():
    template = build_template()
    out_path = HERE / "azuredeploy-automation-rules.json"
    out_path.write_text(json.dumps(template, indent=2) + "\n")
    print(f"Wrote {out_path} ({len(template['resources'])} automation rules)")


if __name__ == "__main__":
    main()

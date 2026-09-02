#!/usr/bin/env python3
"""Generates azuredeploy-response-filehash-block.json.

Response (not enrichment) playbook: for each FileHash entity on the
incident, submits a tenant-wide block indicator via Microsoft Graph's
threat indicator API (POST /security/tiIndicators) targeted at Microsoft
Defender ATP, so Defender for Endpoint enforces the block across managed
devices.

Not wired to any automation rule -- see response_common.py's module
docstring and README-RESPONSE.md.

Requires Microsoft Graph application permission
ThreatIndicators.ReadWrite.OwnedBy on the UAMI.
"""
import pathlib

from response_common import (
    GRAPH_AUTH,
    TD,
    TH,
    after,
    base_outputs,
    base_parameters,
    http_call,
    result_expr,
    sentinel_connection_resource,
    workflow_resource,
    write_template,
)

HERE = pathlib.Path(__file__).resolve().parent
SENTINEL_CONN = "@parameters('$connections')['azuresentinel']['connectionId']"

HEADER = (
    "<div style=\"font-family:Segoe UI,Arial,sans-serif;font-size:13px;color:#605e5c;"
    "margin-bottom:10px\">ErgoSOC-AU response playbook &mdash; block file hash indicator "
    "&middot; run @{utcNow()} UTC</div>"
)

HASH_ROW = (
    f"<table style='border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:12px;width:100%'>"
    f"<tr><th style='{TH}'>Hash</th><td style='{TD}' colspan=\"3\"><code>@{{outputs('Compose_Clean_Hash')}}</code></td></tr>"
    f"<tr><th style='{TH}'>Algorithm</th><td style='{TD}'>@{{outputs('Compose_Hash_Algorithm')}}</td>"
    f"<th style='{TH}'>Approval</th><td style='{TD}'>manual playbook run by an analyst</td></tr>"
    f"<tr><th style='{TH}'>Block indicator (Microsoft Defender ATP)</th><td style='{TD}' colspan=\"3\">@{{variables('BlockResult')}}</td></tr>"
    f"</table>"
)


def build_definition():
    return {
        "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "$connections": {"defaultValue": {}, "type": "Object"},
            "AzureTenantId": {"type": "String"},
            "IndicatorExpirationDays": {"type": "Int", "defaultValue": 180},
        },
        "triggers": {
            "Microsoft_Sentinel_incident": {
                "type": "ApiConnectionWebhook",
                "inputs": {
                    "body": {"callback_url": "@{listCallbackUrl()}"},
                    "host": {"connection": {"name": SENTINEL_CONN}},
                    "path": "/incident-creation",
                },
            }
        },
        "actions": {
            "Entities_-_Get_File_Hashes": {
                "runAfter": {}, "type": "ApiConnection",
                "inputs": {
                    "host": {"connection": {"name": SENTINEL_CONN}},
                    "method": "post",
                    "body": "@triggerBody()?['object']?['properties']?['relatedEntities']",
                    "path": "/entities/filehash",
                },
            },
            "For_each_FileHash_entity": {
                "foreach": "@coalesce(body('Entities_-_Get_File_Hashes')?['FileHashes'], json('[]'))",
                "runAfter": after("Entities_-_Get_File_Hashes"),
                "type": "Foreach",
                "runtimeConfiguration": {"concurrency": {"repetitions": 1}},
                "actions": {
                    "Reset_BlockResult": {
                        "runAfter": {}, "type": "SetVariable",
                        "inputs": {"name": "BlockResult", "value": ""},
                    },
                    "Compose_Clean_Hash": {
                        "runAfter": after("Reset_BlockResult"), "type": "Compose",
                        "inputs": (
                            "@trim(string(coalesce(items('For_each_FileHash_entity')?['HashValue'], "
                            "items('For_each_FileHash_entity')?['hashValue'], "
                            "items('For_each_FileHash_entity')?['Value'], "
                            "items('For_each_FileHash_entity')?['value'], '')))"
                        ),
                    },
                    "Compose_Hash_Algorithm": {
                        "runAfter": after("Compose_Clean_Hash"), "type": "Compose",
                        "inputs": (
                            "@toLower(string(coalesce(items('For_each_FileHash_entity')?['Algorithm'], "
                            "items('For_each_FileHash_entity')?['algorithm'], "
                            "if(equals(length(outputs('Compose_Clean_Hash')), 64), 'SHA256', "
                            "if(equals(length(outputs('Compose_Clean_Hash')), 40), 'SHA1', "
                            "if(equals(length(outputs('Compose_Clean_Hash')), 32), 'MD5', 'Unknown'))))))"
                        ),
                    },
                    "Condition_Has_Hash": {
                        "runAfter": after("Compose_Hash_Algorithm"), "type": "If",
                        "expression": {
                            "and": [
                                {"not": {"equals": ["@outputs('Compose_Clean_Hash')", ""]}},
                                {"not": {"equals": ["@outputs('Compose_Hash_Algorithm')", "unknown"]}},
                            ]
                        },
                        "actions": {
                            "HTTP_SubmitIndicator": http_call(
                                "https://graph.microsoft.com/v1.0/security/tiIndicators",
                                method="POST", auth=GRAPH_AUTH,
                                body={
                                    "action": "block",
                                    "targetProduct": "Microsoft Defender ATP",
                                    "threatType": "WatchList",
                                    "tlpLevel": "amber",
                                    "azureTenantId": "@{parameters('AzureTenantId')}",
                                    "expirationDateTime": "@{addDays(utcNow(), parameters('IndicatorExpirationDays'))}",
                                    "fileHashType": "@{outputs('Compose_Hash_Algorithm')}",
                                    "fileHashValue": "@{outputs('Compose_Clean_Hash')}",
                                    "description": "Blocked by ErgoSOC-AU response playbook (manual analyst run) via Microsoft Sentinel incident.",
                                },
                            ),
                            "Set_BlockResult": {
                                "runAfter": after("HTTP_SubmitIndicator", states=("Succeeded", "Failed", "Skipped", "TimedOut")),
                                "type": "SetVariable",
                                "inputs": {"name": "BlockResult", "value": result_expr("HTTP_SubmitIndicator", [200, 201])},
                            },
                        },
                        "else": {
                            "actions": {
                                "Set_BlockResult_NoHash": {
                                    "runAfter": {}, "type": "SetVariable",
                                    "inputs": {"name": "BlockResult", "value": "skipped - hash value or algorithm could not be determined for this entity"},
                                },
                            }
                        },
                    },
                    "Compose_Entity_Comment": {
                        "runAfter": after("Condition_Has_Hash"), "type": "Compose",
                        "inputs": HEADER + HASH_ROW,
                    },
                    "Compose_Entity_Comment_Safe": {
                        "runAfter": after("Compose_Entity_Comment"), "type": "Compose",
                        "inputs": (
                            "@if(greater(length(outputs('Compose_Entity_Comment')), 28000), "
                            "concat(substring(outputs('Compose_Entity_Comment'), 0, 28000), "
                            "'<p><i>... output truncated at 28,000 characters to stay under Sentinel''s "
                            "30,000-character comment limit; see the Logic App run history for the full "
                            "result.</i></p>'), "
                            "outputs('Compose_Entity_Comment'))"
                        ),
                    },
                    "Add_comment_to_incident_V3": {
                        "runAfter": after("Compose_Entity_Comment_Safe"), "type": "ApiConnection",
                        "inputs": {
                            "host": {"connection": {"name": SENTINEL_CONN}},
                            "method": "post",
                            "body": {
                                "incidentArmId": "@triggerBody()?['object']?['id']",
                                "message": "<p>@{outputs('Compose_Entity_Comment_Safe')}</p>",
                            },
                            "path": "/Incidents/Comment",
                        },
                    },
                },
            },
        },
        "outputs": {},
    }


def build_template():
    definition = build_definition()
    inits = {
        "Init_BlockResult": {
            "runAfter": {}, "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "BlockResult", "type": "string", "value": ""}]},
        },
    }
    definition["actions"] = {**inits, **definition["actions"]}
    definition["actions"]["Entities_-_Get_File_Hashes"]["runAfter"] = after("Init_BlockResult")

    template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "metadata": {
            "title": "Response: block file hash indicator tenant-wide for FileHash entities",
            "description": "For each FileHash entity on a Microsoft Sentinel incident, submits a tenant-wide block indicator via Microsoft Graph's threat indicator API, targeted at Microsoft Defender ATP so Defender for Endpoint enforces it across managed devices. Not wired to an automation rule -- an analyst manually running the playbook from the incident is the approval gate.",
            "prerequisites": "One existing user-assigned managed identity, granted the Microsoft Graph application permission ThreatIndicators.ReadWrite.OwnedBy.",
            "postDeployment": [
                "Grant the user-assigned managed identity Microsoft Sentinel Responder on the resource group holding the workspace.",
                "Grant the managed identity the ThreatIndicators.ReadWrite.OwnedBy Microsoft Graph application permission via an app-role assignment, then allow time for token propagation.",
                "Authorise the Microsoft Sentinel API connection.",
                "Do NOT attach this playbook to an automation rule unless your team has explicitly decided it should run without human approval. Run it manually from the incident's Actions menu instead.",
            ],
            "lastUpdateTime": "2026-09-02",
            "entities": ["FileHash"],
            "tags": ["Response", "FileHash", "Defender for Endpoint", "Indicators"],
            "support": {"tier": "community"},
        },
        "parameters": {
            **base_parameters("ErgoSOC-AU-FileHash-BlockIndicator"),
            "AzureTenantId": {
                "type": "string", "defaultValue": "[subscription().tenantId]",
                "metadata": {"description": "Azure AD tenant ID, required by the tiIndicators API. Defaults to the deploying subscription's tenant."},
            },
            "IndicatorExpirationDays": {
                "type": "int", "defaultValue": 180, "minValue": 1, "maxValue": 365,
                "metadata": {"description": "How many days out from submission the block indicator expires."},
            },
        },
        "variables": {
            "SentinelConnectionName": "[concat('MicrosoftSentinel-', parameters('PlaybookName'))]",
        },
        "resources": [
            sentinel_connection_resource(),
            workflow_resource(
                definition,
                "ErgoSOC-AU-FileHash-BlockIndicator",
                extra_deploy_parameters={
                    "AzureTenantId": {"value": "[parameters('AzureTenantId')]"},
                    "IndicatorExpirationDays": {"value": "[parameters('IndicatorExpirationDays')]"},
                },
            ),
        ],
        "outputs": base_outputs(),
    }
    return template


if __name__ == "__main__":
    write_template(build_template(), "azuredeploy-response-filehash-block.json", HERE)

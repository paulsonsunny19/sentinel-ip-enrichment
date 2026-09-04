#!/usr/bin/env python3
"""Generates azuredeploy-response-filehash-block.json.

Response (not enrichment) playbook: for each FileHash entity on the
incident, submits a tenant-wide block indicator via Defender for
Endpoint's own "Submit or Update Indicator" API
(POST https://api.security.microsoft.com/api/indicators), so Defender
for Endpoint enforces the block across managed devices.

THIRD REVISION OF THIS PLAYBOOK'S API CHOICE -- worth reading if you're
wondering why. The first version called Microsoft Graph's
v1.0/security/tiIndicators (404 -- never existed at v1.0, beta-only).
The second switched to beta/security/tiIndicators (400 -- that whole
"ISG" Graph API line was deprecated in April 2026; Microsoft's own
deprecation notice points at Sentinel's native
Microsoft.SecurityInsights/threatIntelligenceIndicators ARM resource,
but that one is for TI *matching/alerting* in Sentinel's own analytics
rules, not for actively blocking anything on a device -- a real
capability gap versus what this playbook is meant to do). This version
uses Defender for Endpoint's own classic indicators API instead: it's a
separate product surface from the deprecated Graph layer (not affected
by that deprecation), it's what actually enforces a block on managed
devices, and it reuses the exact same MDE_AUTH audience already proven
working by the device response playbook's isolate/scan/restrict calls.

Not wired to any automation rule -- see response_common.py's module
docstring and README-RESPONSE.md.

Requires the WindowsDefenderATP (NOT Microsoft Graph) application
permission Ti.ReadWrite.All on the UAMI.
"""
import pathlib

from response_common import (
    INDICATOR_EXPIRATION_EXPR,
    MDE_AUTH,
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
    f"<tr><th style='{TH}'>Block indicator (Defender for Endpoint)</th><td style='{TD}' colspan=\"3\">@{{variables('BlockResult')}}</td></tr>"
    f"</table>"
)


def build_definition():
    return {
        "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "$connections": {"defaultValue": {}, "type": "Object"},
            "Action": {"type": "String", "defaultValue": "Block"},
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
                            "@coalesce(items('For_each_FileHash_entity')?['Algorithm'], "
                            "items('For_each_FileHash_entity')?['algorithm'], "
                            "if(equals(length(outputs('Compose_Clean_Hash')), 64), 'SHA256', "
                            "if(equals(length(outputs('Compose_Clean_Hash')), 40), 'SHA1', "
                            "if(equals(length(outputs('Compose_Clean_Hash')), 32), 'MD5', 'Unknown'))))"
                        ),
                    },
                    "Compose_Indicator_Type": {
                        "runAfter": after("Compose_Hash_Algorithm"), "type": "Compose",
                        "inputs": (
                            "@if(equals(toUpper(outputs('Compose_Hash_Algorithm')), 'SHA256'), 'FileSha256', "
                            "if(equals(toUpper(outputs('Compose_Hash_Algorithm')), 'SHA1'), 'FileSha1', "
                            "if(equals(toUpper(outputs('Compose_Hash_Algorithm')), 'MD5'), 'FileMd5', '')))"
                        ),
                    },
                    "Condition_Has_Hash": {
                        "runAfter": after("Compose_Indicator_Type"), "type": "If",
                        "expression": {
                            "and": [
                                {"not": {"equals": ["@outputs('Compose_Clean_Hash')", ""]}},
                                {"not": {"equals": ["@outputs('Compose_Indicator_Type')", ""]}},
                            ]
                        },
                        "actions": {
                            "HTTP_SubmitIndicator": http_call(
                                "https://api.security.microsoft.com/api/indicators",
                                method="POST", auth=MDE_AUTH,
                                body={
                                    "indicatorValue": "@{outputs('Compose_Clean_Hash')}",
                                    "indicatorType": "@{outputs('Compose_Indicator_Type')}",
                                    "action": "@{parameters('Action')}",
                                    "title": "@{concat('ErgoSOC-AU block: ', outputs('Compose_Clean_Hash'))}",
                                    "description": "Blocked by ErgoSOC-AU response playbook (manual analyst run) via Microsoft Sentinel incident.",
                                    "severity": "High",
                                    "expirationTime": INDICATOR_EXPIRATION_EXPR,
                                },
                            ),
                            "Set_BlockResult": {
                                "runAfter": after("HTTP_SubmitIndicator", states=("Succeeded", "Failed", "Skipped", "TimedOut")),
                                "type": "SetVariable",
                                "inputs": {"name": "BlockResult", "value": result_expr("HTTP_SubmitIndicator", [200])},
                            },
                        },
                        "else": {
                            "actions": {
                                "Set_BlockResult_NoHash": {
                                    "runAfter": {}, "type": "SetVariable",
                                    "inputs": {"name": "BlockResult", "value": "skipped - hash value or algorithm could not be determined for this entity (only SHA256/SHA1/MD5 supported)"},
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
            "description": "For each FileHash entity on a Microsoft Sentinel incident, submits a tenant-wide block indicator via Defender for Endpoint's own indicators API, so Defender for Endpoint enforces it across managed devices. Supports SHA256/SHA1/MD5. Not wired to an automation rule -- an analyst manually running the playbook from the incident is the approval gate.",
            "prerequisites": "One existing user-assigned managed identity, granted the WindowsDefenderATP (not Microsoft Graph) application permission Ti.ReadWrite.All.",
            "postDeployment": [
                "Grant the user-assigned managed identity Microsoft Sentinel Responder on the resource group holding the workspace.",
                "Grant the managed identity the Ti.ReadWrite.All application permission on the WindowsDefenderATP API (app ID fc780465-2017-40d4-a0c5-307022471b92 -- not Microsoft Graph) via an app-role assignment, then allow time for token propagation.",
                "Authorise the Microsoft Sentinel API connection.",
                "Do NOT attach this playbook to an automation rule unless your team has explicitly decided it should run without human approval. Run it manually from the incident's Actions menu instead.",
            ],
            "lastUpdateTime": "2026-09-04",
            "entities": ["FileHash"],
            "tags": ["Response", "FileHash", "Defender for Endpoint", "Indicators"],
            "support": {"tier": "community"},
        },
        "parameters": {
            **base_parameters("ErgoSOC-AU-FileHash-BlockIndicator"),
            "Action": {
                "type": "string", "defaultValue": "Block",
                "allowedValues": ["Alert", "Warn", "Block", "Audit", "BlockAndRemediate", "AlertAndBlock", "Allowed"],
                "metadata": {"description": "Defender for Endpoint indicator action. Block prevents execution/access with no alert; AlertAndBlock also raises a Defender alert; BlockAndRemediate additionally remediates existing instances."},
            },
            "IndicatorExpirationDays": {
                "type": "int", "defaultValue": 180, "minValue": 0, "maxValue": 365,
                "metadata": {"description": "How many days out from submission the block indicator expires. Set to 0 for effectively never (submits a 2099 expiration)."},
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
                    "Action": {"value": "[parameters('Action')]"},
                    "IndicatorExpirationDays": {"value": "[parameters('IndicatorExpirationDays')]"},
                },
            ),
        ],
        "outputs": base_outputs(),
    }
    return template


if __name__ == "__main__":
    write_template(build_template(), "azuredeploy-response-filehash-block.json", HERE)

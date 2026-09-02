#!/usr/bin/env python3
"""Generates azuredeploy-response-device-contain.json.

Response (not enrichment) playbook: for each Host entity on the incident,
isolates the device from the network and/or kicks off a Defender
antivirus scan on it. Each action has its own on/off parameter, both
default true.

The Defender machine ID (a GUID distinct from the Sentinel Host entity)
is resolved via a Microsoft Graph Advanced Hunting query against
DeviceInfo -- the same mechanism the device enrichment playbook already
uses to correlate a Host entity to Defender, just projecting DeviceId
instead of the full inventory row.

Not wired to any automation rule -- see response_common.py's module
docstring and README-RESPONSE.md.

Requires TWO separate app-role grants on the UAMI, against two different
resources:
  - Microsoft Graph application permission AdvancedQuery.Read.All (to
    resolve the Defender machine ID via runHuntingQuery).
  - "WindowsDefenderATP" (Microsoft Defender for Endpoint) application
    permissions Machine.Isolate and Machine.Scan -- these are NOT
    Microsoft Graph permissions; they're app roles on the separate
    WindowsDefenderATP API and must be granted against that enterprise
    application, not Microsoft Graph.
"""
import pathlib

from response_common import (
    GRAPH_AUTH,
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

KQL_HOST = (
    "@{replace(toLower(string(coalesce(items('For_each_host_entity')?['HostName'], "
    "items('For_each_host_entity')?['NetBiosName'], ''))), decodeUriComponent('%27'), '')}"
)

DEVICE_ID_KQL = f"""let host = '{KQL_HOST}';
DeviceInfo
| where TimeGenerated > ago(30d)
| where tolower(DeviceName) has host
| summarize arg_max(Timestamp, DeviceId)
| project DeviceId
| take 1"""

HEADER = (
    "<div style=\"font-family:Segoe UI,Arial,sans-serif;font-size:13px;color:#605e5c;"
    "margin-bottom:10px\">ErgoSOC-AU response playbook &mdash; device containment "
    "(isolate / AV scan) &middot; run @{utcNow()} UTC</div>"
)

DEVICE_ROW = (
    f"<table style='border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:12px;width:100%'>"
    f"<tr><th style='{TH}'>Host</th><td style='{TD}' colspan=\"3\">{KQL_HOST}</td></tr>"
    f"<tr><th style='{TH}'>Resolved Defender machine ID</th><td style='{TD}'>"
    f"@{{if(equals(variables('MachineId'), ''), 'NOT RESOLVED -- no action taken', variables('MachineId'))}}</td>"
    f"<th style='{TH}'>Approval</th><td style='{TD}'>manual playbook run by an analyst</td></tr>"
    f"<tr><th style='{TH}'>Isolate device (full)</th><td style='{TD}'>@{{variables('IsolateResult')}}</td>"
    f"<th style='{TH}'>Run antivirus scan (quick)</th><td style='{TD}'>@{{variables('ScanResult')}}</td></tr>"
    f"</table>"
)


def build_definition():
    return {
        "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "$connections": {"defaultValue": {}, "type": "Object"},
            "IsolateDevice": {"type": "Bool", "defaultValue": True},
            "RunAntiVirusScan": {"type": "Bool", "defaultValue": True},
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
            "Entities_-_Get_Hosts": {
                "runAfter": {}, "type": "ApiConnection",
                "inputs": {
                    "host": {"connection": {"name": SENTINEL_CONN}},
                    "method": "post",
                    "body": "@triggerBody()?['object']?['properties']?['relatedEntities']",
                    "path": "/entities/host",
                },
            },
            "For_each_host_entity": {
                "foreach": "@coalesce(body('Entities_-_Get_Hosts')?['Hosts'], json('[]'))",
                "runAfter": after("Entities_-_Get_Hosts"),
                "type": "Foreach",
                "runtimeConfiguration": {"concurrency": {"repetitions": 1}},
                "actions": {
                    "Reset_MachineId": {
                        "runAfter": {}, "type": "SetVariable",
                        "inputs": {"name": "MachineId", "value": ""},
                    },
                    "Reset_IsolateResult": {
                        "runAfter": after("Reset_MachineId"), "type": "SetVariable",
                        "inputs": {
                            "name": "IsolateResult",
                            "value": "@if(equals(parameters('IsolateDevice'), true), 'skipped - could not resolve Defender machine ID for this host', 'disabled by deployment setting')",
                        },
                    },
                    "Reset_ScanResult": {
                        "runAfter": after("Reset_IsolateResult"), "type": "SetVariable",
                        "inputs": {
                            "name": "ScanResult",
                            "value": "@if(equals(parameters('RunAntiVirusScan'), true), 'skipped - could not resolve Defender machine ID for this host', 'disabled by deployment setting')",
                        },
                    },
                    "HTTP_Resolve_Machine_Id": {
                        **http_call(
                            "https://graph.microsoft.com/v1.0/security/runHuntingQuery",
                            method="POST", auth=GRAPH_AUTH,
                            body={"Query": DEVICE_ID_KQL, "Timespan": "P30D"},
                        ),
                        "runAfter": after("Reset_ScanResult"),
                    },
                    "Set_MachineId": {
                        "runAfter": after("HTTP_Resolve_Machine_Id", states=("Succeeded", "Failed", "Skipped", "TimedOut")),
                        "type": "SetVariable",
                        "inputs": {
                            "name": "MachineId",
                            "value": (
                                "@if(equals(outputs('HTTP_Resolve_Machine_Id')?['statusCode'], 200), "
                                "string(coalesce(first(coalesce(body('HTTP_Resolve_Machine_Id')?['results'], json('[]')))?['DeviceId'], '')), '')"
                            ),
                        },
                    },
                    "Condition_Has_Machine_Id": {
                        "runAfter": after("Set_MachineId"), "type": "If",
                        "expression": {"not": {"equals": ["@variables('MachineId')", ""]}},
                        "actions": {
                            "Condition_IsolateDevice": {
                                "runAfter": {}, "type": "If",
                                "expression": {"equals": ["@parameters('IsolateDevice')", True]},
                                "actions": {
                                    "HTTP_IsolateDevice": http_call(
                                        "@{concat('https://api.securitycenter.microsoft.com/api/machines/', "
                                        "variables('MachineId'), '/isolate')}",
                                        method="POST", auth=MDE_AUTH,
                                        body={
                                            "Comment": "Isolated by ErgoSOC-AU response playbook (manual analyst run) via Microsoft Sentinel incident.",
                                            "IsolationType": "Full",
                                        },
                                    ),
                                    "Set_IsolateResult": {
                                        "runAfter": after("HTTP_IsolateDevice", states=("Succeeded", "Failed", "Skipped", "TimedOut")),
                                        "type": "SetVariable",
                                        "inputs": {"name": "IsolateResult", "value": result_expr("HTTP_IsolateDevice", [200, 201])},
                                    },
                                },
                                "else": {"actions": {}},
                            },
                            "Condition_RunAntiVirusScan": {
                                "runAfter": after("Condition_IsolateDevice"), "type": "If",
                                "expression": {"equals": ["@parameters('RunAntiVirusScan')", True]},
                                "actions": {
                                    "HTTP_RunAntiVirusScan": http_call(
                                        "@{concat('https://api.securitycenter.microsoft.com/api/machines/', "
                                        "variables('MachineId'), '/runAntiVirusScan')}",
                                        method="POST", auth=MDE_AUTH,
                                        body={
                                            "Comment": "Quick scan requested by ErgoSOC-AU response playbook (manual analyst run) via Microsoft Sentinel incident.",
                                            "ScanType": "Quick",
                                        },
                                    ),
                                    "Set_ScanResult": {
                                        "runAfter": after("HTTP_RunAntiVirusScan", states=("Succeeded", "Failed", "Skipped", "TimedOut")),
                                        "type": "SetVariable",
                                        "inputs": {"name": "ScanResult", "value": result_expr("HTTP_RunAntiVirusScan", [200, 201])},
                                    },
                                },
                                "else": {"actions": {}},
                            },
                        },
                        "else": {"actions": {}},
                    },
                    "Compose_Entity_Comment": {
                        "runAfter": after("Condition_Has_Machine_Id"), "type": "Compose",
                        "inputs": HEADER + DEVICE_ROW,
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
        "Init_MachineId": {
            "runAfter": {}, "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "MachineId", "type": "string", "value": ""}]},
        },
        "Init_IsolateResult": {
            "runAfter": after("Init_MachineId"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "IsolateResult", "type": "string", "value": "disabled by deployment setting"}]},
        },
        "Init_ScanResult": {
            "runAfter": after("Init_IsolateResult"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "ScanResult", "type": "string", "value": "disabled by deployment setting"}]},
        },
    }
    definition["actions"] = {**inits, **definition["actions"]}
    definition["actions"]["Entities_-_Get_Hosts"]["runAfter"] = after("Init_ScanResult")

    template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "metadata": {
            "title": "Response: isolate device and/or run antivirus scan for Host entities",
            "description": "For each Host entity on a Microsoft Sentinel incident, resolves the Defender machine ID via Advanced Hunting and isolates the device from the network and/or starts a quick antivirus scan. Each action has its own on/off parameter. Not wired to an automation rule -- an analyst manually running the playbook from the incident is the approval gate.",
            "prerequisites": "One existing user-assigned managed identity, granted Microsoft Graph application permission AdvancedQuery.Read.All AND the WindowsDefenderATP application permissions Machine.Isolate and Machine.Scan (a separate app registration from Microsoft Graph -- see README-RESPONSE.md).",
            "postDeployment": [
                "Grant the user-assigned managed identity Microsoft Sentinel Responder on the resource group holding the workspace.",
                "Grant the managed identity the AdvancedQuery.Read.All Microsoft Graph application permission via an app-role assignment.",
                "Separately grant the managed identity the Machine.Isolate and Machine.Scan application permissions on the WindowsDefenderATP API (not Microsoft Graph) -- see README-RESPONSE.md for the exact az CLI commands.",
                "Authorise the Microsoft Sentinel API connection.",
                "Do NOT attach this playbook to an automation rule unless your team has explicitly decided it should run without human approval. Run it manually from the incident's Actions menu instead.",
            ],
            "lastUpdateTime": "2026-09-02",
            "entities": ["Host"],
            "tags": ["Response", "Device", "Defender for Endpoint", "Containment"],
            "support": {"tier": "community"},
        },
        "parameters": {
            **base_parameters("ErgoSOC-AU-Device-IsolateAndScan"),
            "IsolateDevice": {
                "type": "bool", "defaultValue": True,
                "metadata": {"description": "Fully isolate the device from the network (Defender for Endpoint machine isolate action)."},
            },
            "RunAntiVirusScan": {
                "type": "bool", "defaultValue": True,
                "metadata": {"description": "Start a quick antivirus scan on the device (Defender for Endpoint machine runAntiVirusScan action)."},
            },
        },
        "variables": {
            "SentinelConnectionName": "[concat('MicrosoftSentinel-', parameters('PlaybookName'))]",
        },
        "resources": [
            sentinel_connection_resource(),
            workflow_resource(
                definition,
                "ErgoSOC-AU-Device-IsolateAndScan",
                extra_deploy_parameters={
                    "IsolateDevice": {"value": "[parameters('IsolateDevice')]"},
                    "RunAntiVirusScan": {"value": "[parameters('RunAntiVirusScan')]"},
                },
            ),
        ],
        "outputs": base_outputs(),
    }
    return template


if __name__ == "__main__":
    write_template(build_template(), "azuredeploy-response-device-contain.json", HERE)

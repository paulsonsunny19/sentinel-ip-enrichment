#!/usr/bin/env python3
"""Generates azuredeploy-response-indicator-block.json.

Response (not enrichment) playbook: for each IP and/or URL entity on the
incident, submits a tenant-wide block indicator via Defender for
Endpoint's own "Submit or Update Indicator" API
(POST https://api.security.microsoft.com/api/indicators), so Defender
for Endpoint enforces the block across managed devices. One combined
playbook rather than two separate ones since both entity types use the
same indicators mechanism, just a different indicatorType -- each has
its own on/off parameter (BlockIP, BlockUrl) if you only want one half
deployed active.

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

One nice side effect of the switch: this API's indicatorType "IpAddress"
covers both IPv4 and IPv6 in one submission, so the separate
IPv4/IPv6-detection branch the earlier Graph-based version needed is
gone -- one HTTP call per IP entity now, not two possible branches.

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

HEADER_IP = (
    "<div style=\"font-family:Segoe UI,Arial,sans-serif;font-size:13px;color:#605e5c;"
    "margin-bottom:10px\">ErgoSOC-AU response playbook &mdash; block IP indicator "
    "&middot; run @{utcNow()} UTC</div>"
)
HEADER_URL = (
    "<div style=\"font-family:Segoe UI,Arial,sans-serif;font-size:13px;color:#605e5c;"
    "margin-bottom:10px\">ErgoSOC-AU response playbook &mdash; block URL indicator "
    "&middot; run @{utcNow()} UTC</div>"
)

IP_ROW = (
    f"<table style='border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:12px;width:100%'>"
    f"<tr><th style='{TH}'>IP address</th><td style='{TD}' colspan=\"3\">@{{items('For_each_IP_entity')?['Address']}}</td></tr>"
    f"<tr><th style='{TH}'>Approval</th><td style='{TD}' colspan=\"3\">manual playbook run by an analyst</td></tr>"
    f"<tr><th style='{TH}'>Block indicator (Defender for Endpoint)</th><td style='{TD}' colspan=\"3\">@{{variables('IpBlockResult')}}</td></tr>"
    f"</table>"
)
URL_ROW = (
    f"<table style='border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:12px;width:100%'>"
    f"<tr><th style='{TH}'>URL</th><td style='{TD}' colspan=\"3\">@{{outputs('Compose_Clean_Url')}}</td></tr>"
    f"<tr><th style='{TH}'>Approval</th><td style='{TD}' colspan=\"3\">manual playbook run by an analyst</td></tr>"
    f"<tr><th style='{TH}'>Block indicator (Defender for Endpoint)</th><td style='{TD}' colspan=\"3\">@{{variables('UrlBlockResult')}}</td></tr>"
    f"</table>"
)


def indicator_body(indicator_type, value_expr, title_prefix):
    return {
        "indicatorValue": f"@{{{value_expr}}}",
        "indicatorType": indicator_type,
        "action": "@{parameters('Action')}",
        "title": (
            f"@{{concat('{title_prefix}(Incident #', "
            "string(triggerBody()?['object']?['properties']?['incidentNumber']), "
            f"'): ', {value_expr})}}"
        ),
        "description": "Blocked by ErgoSOC-AU response playbook (manual analyst run) via Microsoft Sentinel incident.",
        "severity": "High",
        "expirationTime": INDICATOR_EXPIRATION_EXPR,
    }


def comment_actions(suffix, html_expr, run_after_name, connection_name_expr=SENTINEL_CONN):
    """suffix keeps these action names unique from any other comment_actions()
    call site in the same workflow -- this file has two independent Foreach
    loops (IP and URL), and Logic Apps requires action names to be unique
    across the whole workflow, not just within their own loop."""
    compose_name = f"Compose_Entity_Comment_{suffix}"
    safe_name = f"Compose_Entity_Comment_Safe_{suffix}"
    add_name = f"Add_comment_to_incident_{suffix}"
    return {
        compose_name: {
            "runAfter": after(run_after_name), "type": "Compose",
            "inputs": html_expr,
        },
        safe_name: {
            "runAfter": after(compose_name), "type": "Compose",
            "inputs": (
                f"@if(greater(length(outputs('{compose_name}')), 28000), "
                f"concat(substring(outputs('{compose_name}'), 0, 28000), "
                "'<p><i>... output truncated at 28,000 characters to stay under Sentinel''s "
                "30,000-character comment limit; see the Logic App run history for the full "
                "result.</i></p>'), "
                f"outputs('{compose_name}'))"
            ),
        },
        add_name: {
            "runAfter": after(safe_name), "type": "ApiConnection",
            "inputs": {
                "host": {"connection": {"name": connection_name_expr}},
                "method": "post",
                "body": {
                    "incidentArmId": "@triggerBody()?['object']?['id']",
                    "message": f"<p>@{{outputs('{safe_name}')}}</p>",
                },
                "path": "/Incidents/Comment",
            },
        },
    }


def build_ip_section():
    return {
        "Entities_-_Get_IPs": {
            "runAfter": {}, "type": "ApiConnection",
            "inputs": {
                "host": {"connection": {"name": SENTINEL_CONN}},
                "method": "post",
                "body": "@triggerBody()?['object']?['properties']?['relatedEntities']",
                "path": "/entities/ip",
            },
        },
        "For_each_IP_entity": {
            "foreach": "@coalesce(body('Entities_-_Get_IPs')?['IPs'], json('[]'))",
            "runAfter": after("Entities_-_Get_IPs"),
            "type": "Foreach",
            "runtimeConfiguration": {"concurrency": {"repetitions": 1}},
            "actions": {
                "Reset_IpBlockResult": {
                    "runAfter": {}, "type": "SetVariable",
                    "inputs": {"name": "IpBlockResult", "value": ""},
                },
                "HTTP_SubmitIpIndicator": {
                    **http_call(
                        "https://api.security.microsoft.com/api/indicators",
                        method="POST", auth=MDE_AUTH,
                        body=indicator_body("IpAddress", "items('For_each_IP_entity')?['Address']", "ErgoSOC-AU block "),
                    ),
                    "runAfter": after("Reset_IpBlockResult"),
                },
                "Set_IpBlockResult": {
                    "runAfter": after("HTTP_SubmitIpIndicator", states=("Succeeded", "Failed", "Skipped", "TimedOut")),
                    "type": "SetVariable",
                    "inputs": {"name": "IpBlockResult", "value": result_expr("HTTP_SubmitIpIndicator", [200])},
                },
                **comment_actions("IP", HEADER_IP + IP_ROW, "Set_IpBlockResult"),
            },
        },
    }


def build_url_section():
    return {
        "Entities_-_Get_URLs": {
            "runAfter": {}, "type": "ApiConnection",
            "inputs": {
                "host": {"connection": {"name": SENTINEL_CONN}},
                "method": "post",
                "body": "@triggerBody()?['object']?['properties']?['relatedEntities']",
                "path": "/entities/url",
            },
        },
        "For_each_URL_entity": {
            "foreach": "@coalesce(body('Entities_-_Get_URLs')?['URLs'], json('[]'))",
            "runAfter": after("Entities_-_Get_URLs"),
            "type": "Foreach",
            "runtimeConfiguration": {"concurrency": {"repetitions": 1}},
            "actions": {
                "Reset_UrlBlockResult": {
                    "runAfter": {}, "type": "SetVariable",
                    "inputs": {"name": "UrlBlockResult", "value": ""},
                },
                "Compose_Clean_Url": {
                    "runAfter": after("Reset_UrlBlockResult"), "type": "Compose",
                    "inputs": (
                        "@trim(string(coalesce(items('For_each_URL_entity')?['Url'], "
                        "items('For_each_URL_entity')?['url'], '')))"
                    ),
                },
                "HTTP_SubmitUrlIndicator": {
                    **http_call(
                        "https://api.security.microsoft.com/api/indicators",
                        method="POST", auth=MDE_AUTH,
                        body=indicator_body("Url", "outputs('Compose_Clean_Url')", "ErgoSOC-AU block "),
                    ),
                    "runAfter": after("Compose_Clean_Url"),
                },
                "Set_UrlBlockResult": {
                    "runAfter": after("HTTP_SubmitUrlIndicator", states=("Succeeded", "Failed", "Skipped", "TimedOut")),
                    "type": "SetVariable",
                    "inputs": {"name": "UrlBlockResult", "value": result_expr("HTTP_SubmitUrlIndicator", [200])},
                },
                **comment_actions("URL", HEADER_URL + URL_ROW, "Set_UrlBlockResult"),
            },
        },
    }


def build_definition():
    return {
        "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "$connections": {"defaultValue": {}, "type": "Object"},
            "BlockIP": {"type": "Bool", "defaultValue": True},
            "BlockUrl": {"type": "Bool", "defaultValue": True},
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
            "Condition_BlockIP_enabled": {
                "runAfter": {}, "type": "If",
                "expression": {"equals": ["@parameters('BlockIP')", True]},
                "actions": build_ip_section(),
                "else": {"actions": {}},
            },
            "Condition_BlockUrl_enabled": {
                "runAfter": after("Condition_BlockIP_enabled"), "type": "If",
                "expression": {"equals": ["@parameters('BlockUrl')", True]},
                "actions": build_url_section(),
                "else": {"actions": {}},
            },
        },
        "outputs": {},
    }


def build_template():
    definition = build_definition()
    inits = {
        "Init_IpBlockResult": {
            "runAfter": {}, "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "IpBlockResult", "type": "string", "value": ""}]},
        },
        "Init_UrlBlockResult": {
            "runAfter": after("Init_IpBlockResult"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "UrlBlockResult", "type": "string", "value": ""}]},
        },
    }
    definition["actions"] = {**inits, **definition["actions"]}
    definition["actions"]["Condition_BlockIP_enabled"]["runAfter"] = after("Init_UrlBlockResult")

    template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "metadata": {
            "title": "Response: block IP and/or URL indicator tenant-wide",
            "description": "For each IP and/or URL entity on a Microsoft Sentinel incident, submits a tenant-wide block indicator via Defender for Endpoint's own indicators API, so Defender for Endpoint enforces it. Each entity type has its own on/off parameter. Not wired to an automation rule -- an analyst manually running the playbook from the incident is the approval gate.",
            "prerequisites": "One existing user-assigned managed identity, granted the WindowsDefenderATP (not Microsoft Graph) application permission Ti.ReadWrite.All.",
            "postDeployment": [
                "Grant the user-assigned managed identity Microsoft Sentinel Responder on the resource group holding the workspace.",
                "Grant the managed identity the Ti.ReadWrite.All application permission on the WindowsDefenderATP API (app ID fc780465-2017-40d4-a0c5-307022471b92 -- not Microsoft Graph) via an app-role assignment, then allow time for token propagation.",
                "Authorise the Microsoft Sentinel API connection.",
                "Do NOT attach this playbook to an automation rule unless your team has explicitly decided it should run without human approval. Run it manually from the incident's Actions menu instead.",
            ],
            "lastUpdateTime": "2026-09-04",
            "entities": ["IP", "URL"],
            "tags": ["Response", "IP", "URL", "Defender for Endpoint", "Indicators"],
            "support": {"tier": "community"},
        },
        "parameters": {
            **base_parameters("ErgoSOC-AU-Indicator-Block"),
            "BlockIP": {
                "type": "bool", "defaultValue": True,
                "metadata": {"description": "Submit a block indicator for each IP entity on the incident."},
            },
            "BlockUrl": {
                "type": "bool", "defaultValue": True,
                "metadata": {"description": "Submit a block indicator for each URL entity on the incident."},
            },
            "Action": {
                "type": "string", "defaultValue": "Block",
                "allowedValues": ["Alert", "Warn", "Block", "Audit", "BlockAndRemediate", "AlertAndBlock", "Allowed"],
                "metadata": {"description": "Defender for Endpoint indicator action, applied to both IP and URL submissions. Block prevents access with no alert; AlertAndBlock also raises a Defender alert."},
            },
            "IndicatorExpirationDays": {
                "type": "int", "defaultValue": 180, "minValue": 0, "maxValue": 365,
                "metadata": {"description": "How many days out from submission each block indicator expires. Set to 0 for effectively never (submits a 2099 expiration)."},
            },
        },
        "variables": {
            "SentinelConnectionName": "[concat('MicrosoftSentinel-', parameters('PlaybookName'))]",
        },
        "resources": [
            sentinel_connection_resource(),
            workflow_resource(
                definition,
                "ErgoSOC-AU-Indicator-Block",
                extra_deploy_parameters={
                    "BlockIP": {"value": "[parameters('BlockIP')]"},
                    "BlockUrl": {"value": "[parameters('BlockUrl')]"},
                    "Action": {"value": "[parameters('Action')]"},
                    "IndicatorExpirationDays": {"value": "[parameters('IndicatorExpirationDays')]"},
                },
            ),
        ],
        "outputs": base_outputs(),
    }
    return template


if __name__ == "__main__":
    write_template(build_template(), "azuredeploy-response-indicator-block.json", HERE)

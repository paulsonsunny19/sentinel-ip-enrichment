#!/usr/bin/env python3
"""Generates azuredeploy-response-indicator-block-ip-entity.json.

IP half of ErgoSOC-AU-Indicator-Block (azuredeploy-response-indicator-
block.json), split out onto Microsoft Sentinel's "entity" trigger
(Preview) instead of the incident trigger. Run manually by selecting a
single IP entity inside an incident's overview blade -- Actions -> Run
playbook. The URL half is not converted (entity triggers currently only
support Account and IP entity types -- see this session's own research);
azuredeploy-response-indicator-block.json (incident trigger, both IP and
URL) remains the only way to block a URL entity.

UNVERIFIED, UNLIKE THE ACCOUNT PLAYBOOKS -- READ BEFORE DEPLOYING:
Account entity_trigger("Account") is confirmed against a real, complete
reference sample this session inspected directly. No equivalent IP
reference sample has been seen. This file's two IP-specific guesses are
built by direct analogy with confirmed facts, not independent
verification:
  - The trigger path's entity type string, entity_trigger("IP") ->
    "/entity/@{encodeURIComponent('IP')}". "Account" is Sentinel's own
    AccountEntity 'kind' value carried in relatedEntities on the incident
    trigger, and reference material found by this session's earlier
    WebSearch describes entity-trigger support for "Account and IP"
    without giving the IP entity's exact casing. "IP" (both letters
    capitalised) is this session's best-confidence guess; Sentinel's
    other entity Kind values seen elsewhere in this repo's own incident-
    trigger JSON are also plain, unhyphenated capitalised words (Account,
    Host, URL), which is why this isn't a blind guess -- but it has not
    been confirmed the way Account was. If deployment or the trigger's
    own dynamic-content/Code-view shows a different casing (e.g. "Ip"),
    that's the real answer -- tell Claude and it'll be a one-line fix.
  - The entity property holding the IP address itself,
    triggerBody()?['Entity']?['properties']?['Address'] (with an
    ?['address'] lower-case fallback, matching this repo's existing
    defensive-fallback style elsewhere) -- inferred from the incident
    trigger's own IP entity shape (items('For_each_IP_entity')?['Address']
    in azuredeploy-response-indicator-block.json), on the assumption
    entity property names are shared between the two trigger types (as
    they were for Account: AccountName/UPNSuffix/DisplayName all matched
    across both). Not independently confirmed for IP specifically.

Test this one and report back what actually happens -- both guesses are
easy fixes if wrong, but they are guesses.

Requires the WindowsDefenderATP (NOT Microsoft Graph) application
permission Ti.ReadWrite.All on the UAMI -- see build_response_indicator_
block.py's own docstring for the three-revision history of why this API
was chosen over Microsoft Graph's (deprecated) tiIndicators.
"""
import pathlib

from response_common import (
    ENTITY_PROPERTY_EXPR_RAW,
    INCIDENT_ARM_ID_EXPR,
    INCIDENT_ARM_ID_EXPR_RAW,
    INDICATOR_EXPIRATION_EXPR,
    MDE_AUTH,
    SENTINEL_CONN,
    TD,
    TH,
    after,
    base_outputs,
    base_parameters,
    entity_trigger,
    http_call,
    result_expr,
    sentinel_connection_resource,
    workflow_resource,
    write_template,
)

HERE = pathlib.Path(__file__).resolve().parent

HEADER = (
    "<div style=\"font-family:Segoe UI,Arial,sans-serif;font-size:13px;color:#605e5c;"
    "margin-bottom:10px\">ErgoSOC-AU response playbook &mdash; block IP indicator "
    "&middot; entity trigger &middot; run @{utcNow()} UTC</div>"
)

IP_ROW = (
    f"<table style='border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:12px;width:100%'>"
    f"<tr><th style='{TH}'>IP address</th><td style='{TD}' colspan=\"3\">@{{outputs('Compose_Ip_Address')}}</td></tr>"
    f"<tr><th style='{TH}'>Approval</th><td style='{TD}' colspan=\"3\">manual playbook run by an analyst (entity trigger)</td></tr>"
    f"<tr><th style='{TH}'>Block indicator (Defender for Endpoint)</th><td style='{TD}' colspan=\"3\">@{{variables('IpBlockResult')}}</td></tr>"
    f"</table>"
)


def indicator_body(value_expr):
    return {
        "indicatorValue": f"@{{{value_expr}}}",
        "indicatorType": "IpAddress",
        "action": "@{parameters('Action')}",
        "title": f"@{{concat('ErgoSOC-AU block (entity trigger): ', {value_expr})}}",
        "description": "Blocked by ErgoSOC-AU response playbook (manual analyst run, entity trigger) via Microsoft Sentinel.",
        "severity": "High",
        "expirationTime": INDICATOR_EXPIRATION_EXPR,
    }


def build_definition():
    return {
        "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "$connections": {"defaultValue": {}, "type": "Object"},
            "Action": {"type": "String", "defaultValue": "Block"},
            "IndicatorExpirationDays": {"type": "Int", "defaultValue": 180},
            "TeamsWebhookUrl": {"type": "SecureString", "defaultValue": ""},
            "ClientOrganizationName": {"type": "String", "defaultValue": ""},
        },
        "triggers": entity_trigger("IP"),
        "actions": {
            "Compose_Ip_Address": {
                "runAfter": {}, "type": "Compose",
                "inputs": (
                    f"@trim(string(coalesce({ENTITY_PROPERTY_EXPR_RAW}?['Address'], "
                    f"{ENTITY_PROPERTY_EXPR_RAW}?['address'], '')))"
                ),
            },
            "HTTP_SubmitIpIndicator": {
                **http_call(
                    "https://api.security.microsoft.com/api/indicators",
                    method="POST", auth=MDE_AUTH,
                    body=indicator_body("outputs('Compose_Ip_Address')"),
                ),
                "runAfter": after("Compose_Ip_Address"),
            },
            "Set_IpBlockResult": {
                "runAfter": after("HTTP_SubmitIpIndicator", states=("Succeeded", "Failed", "Skipped", "TimedOut")),
                "type": "SetVariable",
                "inputs": {"name": "IpBlockResult", "value": result_expr("HTTP_SubmitIpIndicator", [200])},
            },
            "Compose_Entity_Comment": {
                "runAfter": after("Set_IpBlockResult"), "type": "Compose",
                "inputs": HEADER + IP_ROW,
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
            "Condition_Has_Incident": {
                "runAfter": after("Compose_Entity_Comment_Safe"), "type": "If",
                "expression": {"not": {"equals": [INCIDENT_ARM_ID_EXPR, ""]}},
                "actions": {
                    "Add_comment_to_incident_V3": {
                        "runAfter": {}, "type": "ApiConnection",
                        "inputs": {
                            "host": {"connection": {"name": SENTINEL_CONN}},
                            "method": "post",
                            "body": {
                                "incidentArmId": INCIDENT_ARM_ID_EXPR,
                                "message": "<p>@{outputs('Compose_Entity_Comment_Safe')}</p>",
                            },
                            "path": "/Incidents/Comment",
                        },
                    },
                },
                "else": {"actions": {}},
            },
            "Condition_TeamsNotify": {
                "runAfter": after("Condition_Has_Incident"), "type": "If",
                "expression": {"not": {"equals": ["@parameters('TeamsWebhookUrl')", ""]}},
                "actions": {
                    "HTTP_TeamsNotify": http_call(
                        "@{parameters('TeamsWebhookUrl')}",
                        method="POST", auth=None,
                        body={
                            "type": "AdaptiveCard",
                            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                            "version": "1.4",
                            "body": [
                                {
                                    "type": "Container",
                                    "items": [
                                        {
                                            "type": "TextBlock",
                                            "text": "🛡️ ErgoSOC-AU response playbook run (entity trigger)",
                                            "weight": "Bolder", "size": "Medium", "wrap": True,
                                        },
                                        {
                                            "type": "TextBlock",
                                            "text": "@{if(equals(parameters('ClientOrganizationName'), ''), 'Client: (not set)', concat('Client: ', parameters('ClientOrganizationName')))}",
                                            "isSubtle": True, "wrap": True,
                                        },
                                    ],
                                },
                                {
                                    "type": "FactSet",
                                    "facts": [
                                        {"title": "Playbook", "value": "@{workflow().name}"},
                                        {"title": "IP address", "value": "@{outputs('Compose_Ip_Address')}"},
                                        {"title": "Block", "value": "@{variables('IpBlockResult')}"},
                                        {"title": "Incident ARM ID", "value": f"@{{if(equals({INCIDENT_ARM_ID_EXPR_RAW}, ''), '(none -- not run from an incident)', {INCIDENT_ARM_ID_EXPR_RAW})}}"},
                                    ],
                                },
                            ],
                        },
                    ),
                },
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
    }
    definition["actions"] = {**inits, **definition["actions"]}
    definition["actions"]["Compose_Ip_Address"]["runAfter"] = after("Init_IpBlockResult")

    template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "metadata": {
            "title": "Response: block an IP entity's indicator tenant-wide (entity trigger)",
            "description": "Submits a tenant-wide block indicator via Defender for Endpoint's own indicators API for a single IP entity, run via Microsoft Sentinel's entity trigger (Preview) -- select the entity inside an incident's overview blade, then Actions -> Run playbook. IP half only -- entity triggers do not currently support URL entities; use azuredeploy-response-indicator-block.json (incident trigger) for URL blocking. Cannot be attached to a Sentinel automation rule (a platform limitation of entity-triggered playbooks, not a choice made here). Posts a comment back to the incident when run from one (Incident ARM ID is optional/empty when run without an associated incident, e.g. from Hunting). NOTE: the IP entity type string in the trigger path and the entity's address field name are this session's best-confidence guesses by analogy with the confirmed Account entity trigger, not independently verified -- see the module docstring.",
            "prerequisites": "One existing user-assigned managed identity, granted the WindowsDefenderATP (not Microsoft Graph) application permission Ti.ReadWrite.All.",
            "postDeployment": [
                "Grant the user-assigned managed identity Microsoft Sentinel Responder on the resource group holding the workspace.",
                "Grant the managed identity the Ti.ReadWrite.All application permission on the WindowsDefenderATP API (app ID fc780465-2017-40d4-a0c5-307022471b92 -- not Microsoft Graph) via an app-role assignment, then allow time for token propagation.",
                "Authorise the Microsoft Sentinel API connection.",
                "This playbook uses the entity trigger -- it will not appear as an option for Sentinel automation rules, and must be run manually by selecting an IP entity and choosing Run playbook.",
                "Unverified: the entity type string in the trigger path and the entity's address field name are best-confidence guesses (see the module docstring) -- if the first run doesn't resolve an IP address, check the trigger's own Code view for the actual values and report back.",
            ],
            "lastUpdateTime": "2026-09-10",
            "entities": ["IP"],
            "tags": ["Response", "IP", "Defender for Endpoint", "Indicators", "Entity Trigger"],
            "support": {"tier": "community"},
        },
        "parameters": {
            **base_parameters("ErgoSOC-AU-Indicator-Block-IP-EntityTrigger"),
            "Action": {
                "type": "string", "defaultValue": "Block",
                "allowedValues": ["Alert", "Warn", "Block", "Audit", "BlockAndRemediate", "AlertAndBlock", "Allowed"],
                "metadata": {"description": "Defender for Endpoint indicator action. Block prevents access with no alert; AlertAndBlock also raises a Defender alert."},
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
                "ErgoSOC-AU-Indicator-Block-IP-EntityTrigger",
                extra_deploy_parameters={
                    "Action": {"value": "[parameters('Action')]"},
                    "IndicatorExpirationDays": {"value": "[parameters('IndicatorExpirationDays')]"},
                    "TeamsWebhookUrl": {"value": "[parameters('TeamsWebhookUrl')]"},
                    "ClientOrganizationName": {"value": "[parameters('ClientOrganizationName')]"},
                },
            ),
        ],
        "outputs": base_outputs(),
    }
    return template


if __name__ == "__main__":
    write_template(build_template(), "azuredeploy-response-indicator-block-ip-entity.json", HERE)

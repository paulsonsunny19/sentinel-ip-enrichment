#!/usr/bin/env python3
"""Generates azuredeploy-response-account-revoke-sessions-entity.json.

Same action as ErgoSOC-AU-Account-RevokeSessions (azuredeploy-response-
account-revoke-sessions.json), but on Microsoft Sentinel's "entity" trigger
(Preview) instead of the incident trigger every other playbook in this repo
uses. Run manually by selecting a single Account entity inside an incident's
overview blade -- Actions -> Run playbook -- rather than from the incident's
own Actions menu. See response_common.py's ENTITY_TRIGGER/INCIDENT_ARM_ID_EXPR
comments for exactly what's been verified about this trigger and what's
still a best-confidence guess (the "Incident ARM ID" field's literal casing).

Real platform limitation, not a choice made here: entity-triggered playbooks
CANNOT be called by a Sentinel automation rule (different trigger schema).
Irrelevant for this repo's response playbooks specifically, since none of
them are wired to automation rules anyway -- see README-RESPONSE.md.

First-cut simplification versus the incident-trigger version: the Teams
notification card here omits Ticket/Severity/Incident owner, since none of
those are available from triggerBody() on an entity trigger without an
extra "get incident" API call this first version deliberately doesn't add
yet (keeping the new-and-unverified surface area to just the one field
above). Add it back once the core mechanism is confirmed working.

Requires the same Microsoft Graph application permission as the incident-
trigger version: User.ReadWrite.All (covers revokeSignInSessions) on the
UAMI, plus Microsoft Sentinel Responder for the connector itself.
"""
import pathlib

from response_common import (
    ENTITY_TRIGGER,
    GRAPH_AUTH,
    INCIDENT_ARM_ID_EXPR,
    INCIDENT_ARM_ID_EXPR_RAW,
    SENTINEL_CONN,
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

HEADER = (
    "<div style=\"font-family:Segoe UI,Arial,sans-serif;font-size:13px;color:#605e5c;"
    "margin-bottom:10px\">ErgoSOC-AU response playbook &mdash; account containment "
    "(revoke sessions) &middot; entity trigger &middot; run @{utcNow()} UTC</div>"
)

ACCOUNT_ROW = (
    f"<table style='border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:12px;width:100%'>"
    f"<tr><th style='{TH}'>Account</th><td style='{TD}' colspan=\"3\">"
    f"@{{outputs('Compose_Display_Name_Entity')}} (@{{outputs('Compose_User_Ref')}})</td></tr>"
    f"<tr><th style='{TH}'>Resolved Entra object ID</th><td style='{TD}'>"
    f"@{{if(equals(outputs('Compose_Effective_Object_Id'), ''), 'NOT RESOLVED -- no action taken', outputs('Compose_Effective_Object_Id'))}}</td>"
    f"<th style='{TH}'>Approval</th><td style='{TD}'>manual playbook run by an analyst (entity trigger)</td></tr>"
    f"<tr><th style='{TH}'>Revoke sign-in sessions</th><td style='{TD}' colspan=\"3\">@{{variables('RevokeResult')}}</td></tr>"
    f"</table>"
)


def build_definition():
    return {
        "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "$connections": {"defaultValue": {}, "type": "Object"},
            "TeamsWebhookUrl": {"type": "SecureString", "defaultValue": ""},
            "ClientOrganizationName": {"type": "String", "defaultValue": ""},
        },
        "triggers": ENTITY_TRIGGER,
        "actions": {
            "Entities_-_Get_Accounts": {
                "runAfter": {}, "type": "ApiConnection",
                "inputs": {
                    "host": {"connection": {"name": SENTINEL_CONN}},
                    "method": "post",
                    "path": "/entities/account",
                },
            },
            "For_each_Account_entity": {
                "foreach": "@coalesce(body('Entities_-_Get_Accounts')?['Accounts'], json('[]'))",
                "runAfter": after("Entities_-_Get_Accounts"),
                "type": "Foreach",
                "runtimeConfiguration": {"concurrency": {"repetitions": 1}},
                "actions": {
                    "Reset_RevokeResult": {
                        "runAfter": {}, "type": "SetVariable",
                        "inputs": {"name": "RevokeResult", "value": "skipped - could not resolve Entra object ID for this entity"},
                    },
                    "Reset_ResolvedObjectId": {
                        "runAfter": after("Reset_RevokeResult"), "type": "SetVariable",
                        "inputs": {"name": "ResolvedObjectId", "value": ""},
                    },
                    "Compose_AadUserId": {
                        "runAfter": after("Reset_ResolvedObjectId"), "type": "Compose",
                        "inputs": (
                            "@trim(string(coalesce(items('For_each_Account_entity')?['AadUserId'], "
                            "items('For_each_Account_entity')?['aadUserId'], "
                            "items('For_each_Account_entity')?['ObjectGuid'], "
                            "items('For_each_Account_entity')?['objectGuid'], '')))"
                        ),
                    },
                    "Compose_UPN": {
                        "runAfter": after("Compose_AadUserId"), "type": "Compose",
                        "inputs": (
                            "@toLower(trim(string(coalesce("
                            "items('For_each_Account_entity')?['UserPrincipalName'], "
                            "items('For_each_Account_entity')?['userPrincipalName'], "
                            "if(and(not(equals(items('For_each_Account_entity')?['AccountName'], null)), "
                            "not(equals(items('For_each_Account_entity')?['UPNSuffix'], null))), "
                            "concat(items('For_each_Account_entity')?['AccountName'], '@', items('For_each_Account_entity')?['UPNSuffix']), "
                            # 'Name' confirmed as a real field on this trigger's account entity shape
                            # (differs from the incident trigger's 'AccountName') -- kept as a further
                            # fallback rather than assumed primary, since 'AccountName' may also work.
                            "if(and(not(equals(items('For_each_Account_entity')?['Name'], null)), "
                            "not(equals(items('For_each_Account_entity')?['UPNSuffix'], null))), "
                            "concat(items('For_each_Account_entity')?['Name'], '@', items('For_each_Account_entity')?['UPNSuffix']), ''), "
                            "''), "
                            "''))))"
                        ),
                    },
                    "Compose_Display_Name_Entity": {
                        "runAfter": after("Compose_UPN"), "type": "Compose",
                        "inputs": (
                            "@trim(string(coalesce(items('For_each_Account_entity')?['DisplayName'], "
                            "items('For_each_Account_entity')?['displayName'], "
                            "items('For_each_Account_entity')?['Name'], '(no display name)')))"
                        ),
                    },
                    "Compose_User_Ref": {
                        "runAfter": after("Compose_Display_Name_Entity"), "type": "Compose",
                        "inputs": "@if(not(equals(outputs('Compose_AadUserId'), '')), outputs('Compose_AadUserId'), outputs('Compose_UPN'))",
                    },
                    "Condition_Resolve_ObjectId": {
                        "runAfter": after("Compose_User_Ref"), "type": "If",
                        "expression": {
                            "and": [
                                {"equals": ["@outputs('Compose_AadUserId')", ""]},
                                {"not": {"equals": ["@outputs('Compose_UPN')", ""]}},
                            ]
                        },
                        "actions": {
                            "HTTP_Resolve_User_Id": http_call(
                                "@{concat('https://graph.microsoft.com/v1.0/users/', "
                                "uriComponent(outputs('Compose_UPN')), '?$select=id')}",
                                method="GET", auth=GRAPH_AUTH,
                            ),
                            "Set_ResolvedObjectId": {
                                "runAfter": after("HTTP_Resolve_User_Id", states=("Succeeded", "Failed", "Skipped", "TimedOut")),
                                "type": "SetVariable",
                                "inputs": {
                                    "name": "ResolvedObjectId",
                                    "value": (
                                        "@if(equals(outputs('HTTP_Resolve_User_Id')?['statusCode'], 200), "
                                        "string(coalesce(body('HTTP_Resolve_User_Id')?['id'], '')), '')"
                                    ),
                                },
                            },
                        },
                        "else": {"actions": {}},
                    },
                    "Compose_Effective_Object_Id": {
                        "runAfter": after("Condition_Resolve_ObjectId"), "type": "Compose",
                        "inputs": "@if(not(equals(outputs('Compose_AadUserId'), '')), outputs('Compose_AadUserId'), variables('ResolvedObjectId'))",
                    },
                    "Condition_Has_Object_Id": {
                        "runAfter": after("Compose_Effective_Object_Id"), "type": "If",
                        "expression": {"not": {"equals": ["@outputs('Compose_Effective_Object_Id')", ""]}},
                        "actions": {
                            "HTTP_RevokeSessions": http_call(
                                "@{concat('https://graph.microsoft.com/v1.0/users/', "
                                "uriComponent(outputs('Compose_Effective_Object_Id')), '/revokeSignInSessions')}",
                                method="POST", auth=GRAPH_AUTH, body={},
                            ),
                            "Set_RevokeResult": {
                                "runAfter": after("HTTP_RevokeSessions", states=("Succeeded", "Failed", "Skipped", "TimedOut")),
                                "type": "SetVariable",
                                "inputs": {"name": "RevokeResult", "value": result_expr("HTTP_RevokeSessions", [200])},
                            },
                        },
                        "else": {"actions": {}},
                    },
                    "Compose_Entity_Comment": {
                        "runAfter": after("Condition_Has_Object_Id"), "type": "Compose",
                        "inputs": HEADER + ACCOUNT_ROW,
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
                                                {"title": "Account", "value": "@{outputs('Compose_User_Ref')}"},
                                                {"title": "Revoke sessions", "value": "@{variables('RevokeResult')}"},
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
            },
        },
        "outputs": {},
    }


def build_template():
    definition = build_definition()
    inits = {
        "Init_RevokeResult": {
            "runAfter": {}, "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "RevokeResult", "type": "string", "value": ""}]},
        },
        "Init_ResolvedObjectId": {
            "runAfter": after("Init_RevokeResult"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "ResolvedObjectId", "type": "string", "value": ""}]},
        },
    }
    definition["actions"] = {**inits, **definition["actions"]}
    definition["actions"]["Entities_-_Get_Accounts"]["runAfter"] = after("Init_ResolvedObjectId")

    template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "metadata": {
            "title": "Response: revoke sign-in sessions for an Account entity (entity trigger)",
            "description": "Revokes all active sign-in sessions for a single Account entity, run via Microsoft Sentinel's entity trigger (Preview) -- select the entity inside an incident's overview blade, then Actions -> Run playbook. Cannot be attached to a Sentinel automation rule (a platform limitation of entity-triggered playbooks, not a choice made here). Posts a comment back to the incident when run from one (Incident ARM ID is optional/empty when run without an associated incident, e.g. from Hunting).",
            "prerequisites": "One existing user-assigned managed identity, granted the Microsoft Graph application permission User.ReadWrite.All and Microsoft Sentinel Responder on the resource group holding the workspace.",
            "postDeployment": [
                "Grant the user-assigned managed identity Microsoft Sentinel Responder on the resource group holding the workspace.",
                "Grant the managed identity the User.ReadWrite.All Microsoft Graph application permission via an app-role assignment, then allow time for token propagation.",
                "Authorise the Microsoft Sentinel API connection.",
                "This playbook uses the entity trigger -- it will not appear as an option for Sentinel automation rules, and must be run manually by selecting an Account entity and choosing Run playbook.",
            ],
            "lastUpdateTime": "2026-09-09",
            "entities": ["Account"],
            "tags": ["Response", "Account", "Entra ID", "Containment", "Entity Trigger"],
            "support": {"tier": "community"},
        },
        "parameters": base_parameters("ErgoSOC-AU-Account-RevokeSessions-EntityTrigger"),
        "variables": {
            "SentinelConnectionName": "[concat('MicrosoftSentinel-', parameters('PlaybookName'))]",
        },
        "resources": [
            sentinel_connection_resource(),
            workflow_resource(
                definition,
                "ErgoSOC-AU-Account-RevokeSessions-EntityTrigger",
                extra_deploy_parameters={
                    "TeamsWebhookUrl": {"value": "[parameters('TeamsWebhookUrl')]"},
                    "ClientOrganizationName": {"value": "[parameters('ClientOrganizationName')]"},
                },
            ),
        ],
        "outputs": base_outputs(),
    }
    return template


if __name__ == "__main__":
    write_template(build_template(), "azuredeploy-response-account-revoke-sessions-entity.json", HERE)

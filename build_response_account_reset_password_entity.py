#!/usr/bin/env python3
"""Generates azuredeploy-response-account-reset-password-entity.json.

Same action as ErgoSOC-AU-Account-ResetPassword (azuredeploy-response-
account-reset-password.json), but on Microsoft Sentinel's "entity" trigger
(Preview) instead of the incident trigger. Run manually by selecting a
single Account entity inside an incident's overview blade -- Actions ->
Run playbook.

Built on the same, now-confirmed entity-trigger pattern as
build_response_account_revoke_sessions_entity.py -- see that file's and
response_common.py's comments for what's verified about the trigger
itself. The account-entity resolve chain (AadUserId/UPN/display name,
Graph object-ID lookup) is shared via
response_common.entity_account_resolve_actions() rather than duplicated
here, since that logic shipped two real bugs the first time it was
hand-copied.

The generated temporary password is never logged, echoed to the incident
comment, or returned in any output -- only whether the reset succeeded.
This is a containment lockout: the user cannot sign in again until your
helpdesk issues them a new password through your normal verified channel.

Requires Microsoft Graph application permission User.ReadWrite.All on the
UAMI. Also requires the UAMI itself be assigned an Entra ID directory
role (User Administrator, or Privileged Authentication Administrator if
the target may be an admin/privileged account) -- Graph permission alone
is not sufficient for a passwordProfile write; see this session's own
research on that requirement if you need the detail again.
"""
import pathlib

from response_common import (
    ENTITY_ACCOUNT_RESOLVE_LAST_ACTION,
    GRAPH_AUTH,
    INCIDENT_ARM_ID_EXPR,
    INCIDENT_ARM_ID_EXPR_RAW,
    SENTINEL_CONN,
    TD,
    TH,
    after,
    base_outputs,
    base_parameters,
    entity_account_resolve_actions,
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
    "margin-bottom:10px\">ErgoSOC-AU response playbook &mdash; reset password "
    "&middot; entity trigger &middot; run @{utcNow()} UTC</div>"
)

ACCOUNT_ROW = (
    f"<table style='border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:12px;width:100%'>"
    f"<tr><th style='{TH}'>Account</th><td style='{TD}' colspan=\"3\">"
    f"@{{outputs('Compose_Display_Name_Entity')}} (@{{outputs('Compose_User_Ref')}})</td></tr>"
    f"<tr><th style='{TH}'>Resolved Entra object ID</th><td style='{TD}'>"
    f"@{{if(equals(outputs('Compose_Effective_Object_Id'), ''), 'NOT RESOLVED -- no action taken', outputs('Compose_Effective_Object_Id'))}}</td>"
    f"<th style='{TH}'>Approval</th><td style='{TD}'>manual playbook run by an analyst (entity trigger)</td></tr>"
    f"<tr><th style='{TH}'>Force password reset</th><td style='{TD}' colspan=\"3\">@{{variables('ResetResult')}}"
    f" <i>(new password not shown here -- issue via your normal channel)</i></td></tr>"
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
        "triggers": entity_trigger("Account"),
        "actions": {
            **entity_account_resolve_actions("Init_ResolvedObjectId"),
            "Condition_Has_Object_Id": {
                "runAfter": after(ENTITY_ACCOUNT_RESOLVE_LAST_ACTION), "type": "If",
                "expression": {"not": {"equals": ["@outputs('Compose_Effective_Object_Id')", ""]}},
                "actions": {
                    "Compose_TempPassword": {
                        "runAfter": {}, "type": "Compose",
                        "inputs": (
                            "@concat(toUpper(substring(guid(), 0, 6)), '#', "
                            "toLower(substring(guid(), 0, 6)), string(rand(10, 99)))"
                        ),
                    },
                    "HTTP_ResetPassword": {
                        **http_call(
                            "@{concat('https://graph.microsoft.com/v1.0/users/', "
                            "uriComponent(outputs('Compose_Effective_Object_Id')))}",
                            method="PATCH", auth=GRAPH_AUTH,
                            body={
                                "passwordProfile": {
                                    "forceChangePasswordNextSignIn": True,
                                    "password": "@{outputs('Compose_TempPassword')}",
                                }
                            },
                        ),
                        "runAfter": after("Compose_TempPassword"),
                    },
                    "Set_ResetResult": {
                        "runAfter": after("HTTP_ResetPassword", states=("Succeeded", "Failed", "Skipped", "TimedOut")),
                        "type": "SetVariable",
                        "inputs": {"name": "ResetResult", "value": result_expr("HTTP_ResetPassword", [204])},
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
                                        {"title": "Reset password", "value": "@{variables('ResetResult')}"},
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
        "Init_ResetResult": {
            "runAfter": {}, "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "ResetResult", "type": "string", "value": ""}]},
        },
        "Init_ResolvedObjectId": {
            "runAfter": after("Init_ResetResult"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "ResolvedObjectId", "type": "string", "value": ""}]},
        },
    }
    definition["actions"] = {**inits, **definition["actions"]}

    template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "metadata": {
            "title": "Response: reset password for an Account entity (entity trigger)",
            "description": "Forces a password reset (temporary password never logged or displayed) for a single Account entity, run via Microsoft Sentinel's entity trigger (Preview) -- select the entity inside an incident's overview blade, then Actions -> Run playbook. Cannot be attached to a Sentinel automation rule (a platform limitation of entity-triggered playbooks, not a choice made here). Posts a comment back to the incident when run from one (Incident ARM ID is optional/empty when run without an associated incident, e.g. from Hunting).",
            "prerequisites": "One existing user-assigned managed identity, granted the Microsoft Graph application permission User.ReadWrite.All, an Entra ID directory role sufficient to reset the target's password (User Administrator, or Privileged Authentication Administrator if the target may be an admin account), and Microsoft Sentinel Responder on the resource group holding the workspace.",
            "postDeployment": [
                "Grant the user-assigned managed identity Microsoft Sentinel Responder on the resource group holding the workspace.",
                "Grant the managed identity the User.ReadWrite.All Microsoft Graph application permission via an app-role assignment, then allow time for token propagation.",
                "Assign the managed identity an Entra ID directory role that can reset the target account's password -- User Administrator for regular users, Privileged Authentication Administrator if the target may be an admin/privileged account (the Graph permission alone is not sufficient for a passwordProfile write).",
                "Authorise the Microsoft Sentinel API connection.",
                "This playbook uses the entity trigger -- it will not appear as an option for Sentinel automation rules, and must be run manually by selecting an Account entity and choosing Run playbook.",
            ],
            "lastUpdateTime": "2026-09-10",
            "entities": ["Account"],
            "tags": ["Response", "Account", "Entra ID", "Containment", "Entity Trigger"],
            "support": {"tier": "community"},
        },
        "parameters": base_parameters("ErgoSOC-AU-Account-ResetPassword-EntityTrigger"),
        "variables": {
            "SentinelConnectionName": "[concat('MicrosoftSentinel-', parameters('PlaybookName'))]",
        },
        "resources": [
            sentinel_connection_resource(),
            workflow_resource(
                definition,
                "ErgoSOC-AU-Account-ResetPassword-EntityTrigger",
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
    write_template(build_template(), "azuredeploy-response-account-reset-password-entity.json", HERE)

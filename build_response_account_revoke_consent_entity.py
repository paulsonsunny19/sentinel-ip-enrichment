#!/usr/bin/env python3
"""Generates azuredeploy-response-account-revoke-consent-entity.json.

Same action as ErgoSOC-AU-Account-RevokeAppConsent (azuredeploy-response-
account-revoke-consent.json), but on Microsoft Sentinel's "entity" trigger
(Preview) instead of the incident trigger. Run manually by selecting a
single Account entity inside an incident's overview blade -- Actions ->
Run playbook.

Built on the same, now-confirmed entity-trigger pattern as
build_response_account_revoke_sessions_entity.py -- see that file's and
response_common.py's comments for what's verified about the trigger
itself. The account-entity resolve chain (AadUserId/UPN/display name,
Graph object-ID lookup) is shared via
response_common.entity_account_resolve_actions() rather than duplicated
here.

The For_each_Grant loop below is unrelated to the entity-trigger/Foreach
distinction that changed elsewhere in this file's siblings -- it loops
over the *account's OAuth grants* (an API response), not over Sentinel
entities, so it stays exactly as it is in the incident-trigger version.

This revokes the user's own (delegated) consent grants only -- it does
not touch tenant-wide admin consent grants or the app's own app-role
assignments. If the malicious app was admin-consented at the tenant
level, that needs a separate, deliberate tenant-admin action, which this
playbook does not attempt.

Requires Microsoft Graph application permission
DelegatedPermissionGrant.ReadWrite.All on the UAMI.
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
    sentinel_connection_resource,
    workflow_resource,
    write_template,
)

HERE = pathlib.Path(__file__).resolve().parent

HEADER = (
    "<div style=\"font-family:Segoe UI,Arial,sans-serif;font-size:13px;color:#605e5c;"
    "margin-bottom:10px\">ErgoSOC-AU response playbook &mdash; revoke OAuth app consent "
    "&middot; entity trigger &middot; run @{utcNow()} UTC</div>"
)

ACCOUNT_ROW = (
    f"<table style='border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:12px;width:100%'>"
    f"<tr><th style='{TH}'>Account</th><td style='{TD}' colspan=\"3\">"
    f"@{{outputs('Compose_Display_Name_Entity')}} (@{{outputs('Compose_User_Ref')}})</td></tr>"
    f"<tr><th style='{TH}'>Resolved Entra object ID</th><td style='{TD}'>"
    f"@{{if(equals(outputs('Compose_Effective_Object_Id'), ''), 'NOT RESOLVED -- no action taken', outputs('Compose_Effective_Object_Id'))}}</td>"
    f"<th style='{TH}'>Approval</th><td style='{TD}'>manual playbook run by an analyst (entity trigger)</td></tr>"
    f"<tr><th style='{TH}'>Delegated permission grants</th><td style='{TD}' colspan=\"3\">@{{variables('GrantsSummary')}}</td></tr>"
    f"</table>"
    f"<div style=\"font-family:Segoe UI,Arial,sans-serif;font-size:11px;color:#605e5c;margin-top:6px\">"
    f"Revokes the user's own consent grants only. If a malicious app was admin-consented tenant-wide, "
    f"removing its service principal or app-role assignments is a separate, deliberate admin action this "
    f"playbook does not perform.</div>"
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
                    "HTTP_List_Grants": http_call(
                        "@{concat('https://graph.microsoft.com/v1.0/users/', "
                        "uriComponent(outputs('Compose_Effective_Object_Id')), '/oauth2PermissionGrants')}",
                        method="GET", auth=GRAPH_AUTH,
                    ),
                    "For_each_Grant": {
                        "foreach": "@coalesce(body('HTTP_List_Grants')?['value'], json('[]'))",
                        "runAfter": after("HTTP_List_Grants"),
                        "type": "Foreach",
                        "runtimeConfiguration": {"concurrency": {"repetitions": 1}},
                        "actions": {
                            "HTTP_Delete_Grant": http_call(
                                "@{concat('https://graph.microsoft.com/v1.0/oauth2PermissionGrants/', "
                                "items('For_each_Grant')?['id'])}",
                                method="DELETE", auth=GRAPH_AUTH,
                            ),
                            "Condition_Delete_Succeeded": {
                                "runAfter": after("HTTP_Delete_Grant", states=("Succeeded", "Failed", "Skipped", "TimedOut")),
                                "type": "If",
                                "expression": {"equals": ["@outputs('HTTP_Delete_Grant')?['statusCode']", 204]},
                                "actions": {
                                    "Increment_RevokedCount": {
                                        "runAfter": {}, "type": "IncrementVariable",
                                        "inputs": {"name": "RevokedCount", "value": 1},
                                    },
                                },
                                "else": {
                                    "actions": {
                                        "Increment_FailedCount": {
                                            "runAfter": {}, "type": "IncrementVariable",
                                            "inputs": {"name": "FailedCount", "value": 1},
                                        },
                                    }
                                },
                            },
                        },
                    },
                },
                "else": {"actions": {}},
            },
            "Compose_GrantsSummary": {
                "runAfter": after("Condition_Has_Object_Id"), "type": "Compose",
                "inputs": (
                    "@if(equals(outputs('Compose_Effective_Object_Id'), ''), "
                    "'not attempted - no Entra object ID resolved', "
                    "if(equals(add(variables('RevokedCount'), variables('FailedCount')), 0), "
                    "'no delegated permission grants found for this user', "
                    "concat('revoked ', string(variables('RevokedCount')), ' of ', "
                    "string(add(variables('RevokedCount'), variables('FailedCount'))), "
                    "' delegated permission grants', "
                    "if(greater(variables('FailedCount'), 0), "
                    "concat(' (', string(variables('FailedCount')), ' failed to revoke -- check run history)'), ''))))"
                ),
            },
            "Set_GrantsSummary": {
                "runAfter": after("Compose_GrantsSummary"), "type": "SetVariable",
                "inputs": {"name": "GrantsSummary", "value": "@outputs('Compose_GrantsSummary')"},
            },
            "Compose_Entity_Comment": {
                "runAfter": after("Set_GrantsSummary"), "type": "Compose",
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
                                        {"title": "OAuth grants", "value": "@{variables('GrantsSummary')}"},
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
        "Init_RevokedCount": {
            "runAfter": {}, "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "RevokedCount", "type": "integer", "value": 0}]},
        },
        "Init_FailedCount": {
            "runAfter": after("Init_RevokedCount"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "FailedCount", "type": "integer", "value": 0}]},
        },
        "Init_GrantsSummary": {
            "runAfter": after("Init_FailedCount"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "GrantsSummary", "type": "string", "value": ""}]},
        },
        "Init_ResolvedObjectId": {
            "runAfter": after("Init_GrantsSummary"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "ResolvedObjectId", "type": "string", "value": ""}]},
        },
    }
    definition["actions"] = {**inits, **definition["actions"]}

    template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "metadata": {
            "title": "Response: revoke OAuth app consent for an Account entity (entity trigger)",
            "description": "Lists and revokes every delegated OAuth2 permission grant a single Account entity has consented to, run via Microsoft Sentinel's entity trigger (Preview) -- select the entity inside an incident's overview blade, then Actions -> Run playbook. Does not touch tenant-wide admin consent grants. Cannot be attached to a Sentinel automation rule (a platform limitation of entity-triggered playbooks, not a choice made here). Posts a comment back to the incident when run from one (Incident ARM ID is optional/empty when run without an associated incident, e.g. from Hunting).",
            "prerequisites": "One existing user-assigned managed identity, granted the Microsoft Graph application permission DelegatedPermissionGrant.ReadWrite.All.",
            "postDeployment": [
                "Grant the user-assigned managed identity Microsoft Sentinel Responder on the resource group holding the workspace.",
                "Grant the managed identity the DelegatedPermissionGrant.ReadWrite.All Microsoft Graph application permission via an app-role assignment, then allow time for token propagation.",
                "Authorise the Microsoft Sentinel API connection.",
                "This playbook uses the entity trigger -- it will not appear as an option for Sentinel automation rules, and must be run manually by selecting an Account entity and choosing Run playbook.",
            ],
            "lastUpdateTime": "2026-09-10",
            "entities": ["Account"],
            "tags": ["Response", "Account", "Entra ID", "OAuth Consent", "Containment", "Entity Trigger"],
            "support": {"tier": "community"},
        },
        "parameters": base_parameters("ErgoSOC-AU-Account-RevokeAppConsent-EntityTrigger"),
        "variables": {
            "SentinelConnectionName": "[concat('MicrosoftSentinel-', parameters('PlaybookName'))]",
        },
        "resources": [
            sentinel_connection_resource(),
            workflow_resource(
                definition,
                "ErgoSOC-AU-Account-RevokeAppConsent-EntityTrigger",
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
    write_template(build_template(), "azuredeploy-response-account-revoke-consent-entity.json", HERE)

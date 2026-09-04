#!/usr/bin/env python3
"""Generates azuredeploy-response-account-revoke-consent.json.

Response (not enrichment) playbook: for each Account entity on the
incident, lists every delegated OAuth2 permission grant the user has
consented to (GET /users/{id}/oauth2PermissionGrants) and revokes all of
them (DELETE /oauth2PermissionGrants/{id} for each). Useful after an
account compromise where the attacker consented a malicious OAuth app --
revoking the grant cuts that app's access without touching the user's
own credentials.

This revokes the user's own (delegated) consent grants only -- it does
not touch tenant-wide admin consent grants or the app's own app-role
assignments. If the malicious app was admin-consented at the tenant
level, that needs a separate, deliberate tenant-admin action (removing
the service principal or its app-role assignments), which this playbook
does not attempt.

Not wired to any automation rule -- see response_common.py's module
docstring and README-RESPONSE.md.

Requires Microsoft Graph application permission
DelegatedPermissionGrant.ReadWrite.All on the UAMI.
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
    sentinel_connection_resource,
    workflow_resource,
    write_template,
)

HERE = pathlib.Path(__file__).resolve().parent
SENTINEL_CONN = "@parameters('$connections')['azuresentinel']['connectionId']"

HEADER = (
    "<div style=\"font-family:Segoe UI,Arial,sans-serif;font-size:13px;color:#605e5c;"
    "margin-bottom:10px\">ErgoSOC-AU response playbook &mdash; revoke OAuth app consent "
    "&middot; run @{utcNow()} UTC</div>"
)

ACCOUNT_ROW = (
    f"<table style='border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:12px;width:100%'>"
    f"<tr><th style='{TH}'>Account</th><td style='{TD}' colspan=\"3\">"
    f"@{{outputs('Compose_Display_Name_Entity')}} (@{{outputs('Compose_User_Ref')}})</td></tr>"
    f"<tr><th style='{TH}'>Resolved Entra object ID</th><td style='{TD}'>"
    f"@{{if(equals(outputs('Compose_Effective_Object_Id'), ''), 'NOT RESOLVED -- no action taken', outputs('Compose_Effective_Object_Id'))}}</td>"
    f"<th style='{TH}'>Approval</th><td style='{TD}'>manual playbook run by an analyst</td></tr>"
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
            "Entities_-_Get_Accounts": {
                "runAfter": {}, "type": "ApiConnection",
                "inputs": {
                    "host": {"connection": {"name": SENTINEL_CONN}},
                    "method": "post",
                    "body": "@triggerBody()?['object']?['properties']?['relatedEntities']",
                    "path": "/entities/account",
                },
            },
            "For_each_Account_entity": {
                "foreach": "@coalesce(body('Entities_-_Get_Accounts')?['Accounts'], json('[]'))",
                "runAfter": after("Entities_-_Get_Accounts"),
                "type": "Foreach",
                "runtimeConfiguration": {"concurrency": {"repetitions": 1}},
                "actions": {
                    "Reset_RevokedCount": {
                        "runAfter": {}, "type": "SetVariable",
                        "inputs": {"name": "RevokedCount", "value": 0},
                    },
                    "Reset_FailedCount": {
                        "runAfter": after("Reset_RevokedCount"), "type": "SetVariable",
                        "inputs": {"name": "FailedCount", "value": 0},
                    },
                    "Reset_ResolvedObjectId": {
                        "runAfter": after("Reset_FailedCount"), "type": "SetVariable",
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
                            "concat(items('For_each_Account_entity')?['AccountName'], '@', items('For_each_Account_entity')?['UPNSuffix']), ''), "
                            "''))))"
                        ),
                    },
                    "Compose_Display_Name_Entity": {
                        "runAfter": after("Compose_UPN"), "type": "Compose",
                        "inputs": (
                            "@trim(string(coalesce(items('For_each_Account_entity')?['DisplayName'], "
                            "items('For_each_Account_entity')?['displayName'], '(no display name)')))"
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
        "Init_RevokedCount": {
            "runAfter": {}, "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "RevokedCount", "type": "integer", "value": 0}]},
        },
        "Init_FailedCount": {
            "runAfter": after("Init_RevokedCount"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "FailedCount", "type": "integer", "value": 0}]},
        },
        "Init_ResolvedObjectId": {
            "runAfter": after("Init_FailedCount"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "ResolvedObjectId", "type": "string", "value": ""}]},
        },
        "Init_GrantsSummary": {
            "runAfter": after("Init_ResolvedObjectId"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "GrantsSummary", "type": "string", "value": ""}]},
        },
    }
    definition["actions"] = {**inits, **definition["actions"]}
    definition["actions"]["Entities_-_Get_Accounts"]["runAfter"] = after("Init_GrantsSummary")

    template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "metadata": {
            "title": "Response: revoke OAuth app consent for Account entities",
            "description": "For each Account entity on a Microsoft Sentinel incident, lists and revokes every delegated OAuth2 permission grant the user has consented to. Useful after an account compromise where the attacker consented a malicious OAuth app. Does not touch tenant-wide admin consent grants. Not wired to an automation rule -- an analyst manually running the playbook from the incident is the approval gate.",
            "prerequisites": "One existing user-assigned managed identity, granted the Microsoft Graph application permission DelegatedPermissionGrant.ReadWrite.All.",
            "postDeployment": [
                "Grant the user-assigned managed identity Microsoft Sentinel Responder on the resource group holding the workspace.",
                "Grant the managed identity the DelegatedPermissionGrant.ReadWrite.All Microsoft Graph application permission via an app-role assignment, then allow time for token propagation.",
                "Authorise the Microsoft Sentinel API connection.",
                "Do NOT attach this playbook to an automation rule unless your team has explicitly decided it should run without human approval. Run it manually from the incident's Actions menu instead.",
            ],
            "lastUpdateTime": "2026-09-02",
            "entities": ["Account"],
            "tags": ["Response", "Account", "Entra ID", "OAuth Consent", "Containment"],
            "support": {"tier": "community"},
        },
        "parameters": base_parameters("ErgoSOC-AU-Account-RevokeAppConsent"),
        "variables": {
            "SentinelConnectionName": "[concat('MicrosoftSentinel-', parameters('PlaybookName'))]",
        },
        "resources": [
            sentinel_connection_resource(),
            workflow_resource(definition, "ErgoSOC-AU-Account-RevokeAppConsent"),
        ],
        "outputs": base_outputs(),
    }
    return template


if __name__ == "__main__":
    write_template(build_template(), "azuredeploy-response-account-revoke-consent.json", HERE)

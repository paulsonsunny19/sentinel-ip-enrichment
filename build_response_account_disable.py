#!/usr/bin/env python3
"""Generates azuredeploy-response-account-disable.json.

Response (not enrichment) playbook: for each Account entity on the
incident, disables the account (accountEnabled = false) and/or marks it
compromised in Entra ID Protection (confirmCompromised). Each action has
its own on/off parameter, both default true.

Not wired to any automation rule -- see response_common.py's module
docstring and README-RESPONSE.md.

Requires Microsoft Graph application permissions on the UAMI:
User.ReadWrite.All (disable) and IdentityRiskyUser.ReadWrite.All (confirm
compromised).
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
    "margin-bottom:10px\">ErgoSOC-AU response playbook &mdash; account disable / "
    "confirm compromised &middot; run @{utcNow()} UTC</div>"
)

ACCOUNT_ROW = (
    f"<table style='border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:12px;width:100%'>"
    f"<tr><th style='{TH}'>Account</th><td style='{TD}' colspan=\"3\">"
    f"@{{outputs('Compose_Display_Name_Entity')}} (@{{outputs('Compose_User_Ref')}})</td></tr>"
    f"<tr><th style='{TH}'>Resolved Entra object ID</th><td style='{TD}'>"
    f"@{{if(equals(outputs('Compose_Effective_Object_Id'), ''), 'NOT RESOLVED -- no action taken', outputs('Compose_Effective_Object_Id'))}}</td>"
    f"<th style='{TH}'>Approval</th><td style='{TD}'>manual playbook run by an analyst</td></tr>"
    f"<tr><th style='{TH}'>Disable account</th><td style='{TD}'>@{{variables('DisableResult')}}</td>"
    f"<th style='{TH}'>Confirm compromised (Identity Protection)</th><td style='{TD}'>@{{variables('ConfirmResult')}}</td></tr>"
    f"</table>"
)


def build_definition():
    return {
        "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "$connections": {"defaultValue": {}, "type": "Object"},
            "DisableAccount": {"type": "Bool", "defaultValue": True},
            "ConfirmCompromised": {"type": "Bool", "defaultValue": True},
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
                    "Reset_DisableResult": {
                        "runAfter": {}, "type": "SetVariable",
                        "inputs": {
                            "name": "DisableResult",
                            "value": "@if(equals(parameters('DisableAccount'), true), 'skipped - could not resolve Entra object ID for this entity', 'disabled by deployment setting')",
                        },
                    },
                    "Reset_ConfirmResult": {
                        "runAfter": after("Reset_DisableResult"), "type": "SetVariable",
                        "inputs": {
                            "name": "ConfirmResult",
                            "value": "@if(equals(parameters('ConfirmCompromised'), true), 'skipped - could not resolve Entra object ID for this entity', 'disabled by deployment setting')",
                        },
                    },
                    "Reset_ResolvedObjectId": {
                        "runAfter": after("Reset_ConfirmResult"), "type": "SetVariable",
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
                            "Condition_DisableAccount": {
                                "runAfter": {}, "type": "If",
                                "expression": {"equals": ["@parameters('DisableAccount')", True]},
                                "actions": {
                                    "HTTP_DisableAccount": http_call(
                                        "@{concat('https://graph.microsoft.com/v1.0/users/', "
                                        "uriComponent(outputs('Compose_Effective_Object_Id')))}",
                                        method="PATCH", auth=GRAPH_AUTH,
                                        body={"accountEnabled": False},
                                    ),
                                    "Set_DisableResult": {
                                        "runAfter": after("HTTP_DisableAccount", states=("Succeeded", "Failed", "Skipped", "TimedOut")),
                                        "type": "SetVariable",
                                        "inputs": {"name": "DisableResult", "value": result_expr("HTTP_DisableAccount", [204])},
                                    },
                                },
                                "else": {"actions": {}},
                            },
                            "Condition_ConfirmCompromised": {
                                "runAfter": after("Condition_DisableAccount"), "type": "If",
                                "expression": {"equals": ["@parameters('ConfirmCompromised')", True]},
                                "actions": {
                                    "HTTP_ConfirmCompromised": http_call(
                                        "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/confirmCompromised",
                                        method="POST", auth=GRAPH_AUTH,
                                        body={"userIds": ["@{outputs('Compose_Effective_Object_Id')}"]},
                                    ),
                                    "Set_ConfirmResult": {
                                        "runAfter": after("HTTP_ConfirmCompromised", states=("Succeeded", "Failed", "Skipped", "TimedOut")),
                                        "type": "SetVariable",
                                        "inputs": {"name": "ConfirmResult", "value": result_expr("HTTP_ConfirmCompromised", [200, 202, 204])},
                                    },
                                },
                                "else": {"actions": {}},
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
        "Init_DisableResult": {
            "runAfter": {}, "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "DisableResult", "type": "string", "value": "disabled by deployment setting"}]},
        },
        "Init_ConfirmResult": {
            "runAfter": after("Init_DisableResult"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "ConfirmResult", "type": "string", "value": "disabled by deployment setting"}]},
        },
        "Init_ResolvedObjectId": {
            "runAfter": after("Init_ConfirmResult"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "ResolvedObjectId", "type": "string", "value": ""}]},
        },
    }
    definition["actions"] = {**inits, **definition["actions"]}
    definition["actions"]["Entities_-_Get_Accounts"]["runAfter"] = after("Init_ResolvedObjectId")

    template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "metadata": {
            "title": "Response: disable account and/or confirm compromised for Account entities",
            "description": "For each Account entity on a Microsoft Sentinel incident, disables the Entra ID account and/or marks it compromised in Entra ID Protection (confirmCompromised). Each action has its own on/off parameter. Not wired to an automation rule -- an analyst manually running the playbook from the incident is the approval gate.",
            "prerequisites": "One existing user-assigned managed identity, granted the Microsoft Graph application permissions User.ReadWrite.All (disable) and IdentityRiskyUser.ReadWrite.All (confirm compromised).",
            "postDeployment": [
                "Grant the user-assigned managed identity Microsoft Sentinel Responder on the resource group holding the workspace.",
                "Grant the managed identity the User.ReadWrite.All and IdentityRiskyUser.ReadWrite.All Microsoft Graph application permissions via app-role assignments, then allow time for token propagation.",
                "Authorise the Microsoft Sentinel API connection.",
                "Do NOT attach this playbook to an automation rule unless your team has explicitly decided it should run without human approval. Run it manually from the incident's Actions menu instead.",
            ],
            "lastUpdateTime": "2026-09-02",
            "entities": ["Account"],
            "tags": ["Response", "Account", "Entra ID", "Identity Protection", "Containment"],
            "support": {"tier": "community"},
        },
        "parameters": {
            **base_parameters("ErgoSOC-AU-Account-DisableAndConfirmCompromised"),
            "DisableAccount": {
                "type": "bool", "defaultValue": True,
                "metadata": {"description": "Disable the Entra ID account (accountEnabled = false)."},
            },
            "ConfirmCompromised": {
                "type": "bool", "defaultValue": True,
                "metadata": {"description": "Mark the account compromised in Entra ID Protection (identityProtection/riskyUsers/confirmCompromised)."},
            },
        },
        "variables": {
            "SentinelConnectionName": "[concat('MicrosoftSentinel-', parameters('PlaybookName'))]",
        },
        "resources": [
            sentinel_connection_resource(),
            workflow_resource(
                definition,
                "ErgoSOC-AU-Account-DisableAndConfirmCompromised",
                extra_deploy_parameters={
                    "DisableAccount": {"value": "[parameters('DisableAccount')]"},
                    "ConfirmCompromised": {"value": "[parameters('ConfirmCompromised')]"},
                },
            ),
        ],
        "outputs": base_outputs(),
    }
    return template


if __name__ == "__main__":
    write_template(build_template(), "azuredeploy-response-account-disable.json", HERE)

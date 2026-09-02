#!/usr/bin/env python3
"""Generates azuredeploy-response-email-block.json.

ASSISTED, not automated -- read this before deploying it. Unlike the other
three response playbooks, this one makes no live write API call. The
reason: writing to the Microsoft 365 Tenant Allow/Block List is only
reliably supported via the Exchange Online PowerShell
*-TenantAllowBlockListItems cmdlets; there is no well-documented Microsoft
Graph HTTP endpoint for it (the Graph beta tenantAllowBlockLists surface
appears to be read-oriented in practice, and community reports consistently
say writes require EXO PowerShell -- see README-RESPONSE.md for the sources).
Shipping a guessed Graph call here would silently do nothing while looking
like it worked, which is worse than not automating it.

So instead, for each Mail message entity, this playbook composes the exact
PowerShell command(s) to run (New-TenantAllowBlockListItems) and the search
values needed to locate the message in Microsoft Defender Threat Explorer,
and posts them to the incident comment for an analyst to execute. If your
tenant already has an Automation Account or Function App that can run EXO
PowerShell with app-only auth (Exchange.ManageAsApp), swap the composed
command into an actual call from there -- that's a bigger, separate piece
of infrastructure than the plain UAMI HTTP pattern used everywhere else in
this repo, so it's deliberately not built into this Logic App.

Because it performs no write call, this playbook needs no Graph write
permission at all -- Microsoft Sentinel Responder is the only grant it
needs, same as a read-only enrichment playbook.
"""
import pathlib

from response_common import (
    TD,
    TH,
    after,
    base_outputs,
    base_parameters,
    sentinel_connection_resource,
    workflow_resource,
    write_template,
)

HERE = pathlib.Path(__file__).resolve().parent
SENTINEL_CONN = "@parameters('$connections')['azuresentinel']['connectionId']"

HEADER = (
    "<div style=\"font-family:Segoe UI,Arial,sans-serif;font-size:13px;color:#605e5c;"
    "margin-bottom:10px\">ErgoSOC-AU response playbook &mdash; email block/quarantine "
    "assist (no live action taken -- see below) &middot; run @{utcNow()} UTC</div>"
)

EMAIL_ROW = (
    f"<table style='border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:12px;width:100%'>"
    f"<tr><th style='{TH}'>Sender</th><td style='{TD}'>@{{outputs('Compose_Sender')}}</td>"
    f"<th style='{TH}'>Sender domain</th><td style='{TD}'>@{{outputs('Compose_SenderDomain')}}</td></tr>"
    f"<tr><th style='{TH}'>Recipient</th><td style='{TD}'>@{{outputs('Compose_Recipient')}}</td>"
    f"<th style='{TH}'>Subject</th><td style='{TD}'>@{{outputs('Compose_Subject')}}</td></tr>"
    f"<tr><th style='{TH}'>Network message ID</th><td style='{TD}' colspan=\"3\">@{{outputs('Compose_NetworkMessageId')}}</td></tr>"
    f"</table>"
    f"<div style='margin:10px 0 4px 0;font-family:Segoe UI,Arial,sans-serif;font-size:13px'><b>Block command(s) to run "
    f"(Exchange Online PowerShell)</b> <span style=\"font-weight:400;color:#605e5c\">"
    f"-- not run automatically; see the playbook's prerequisites for why</span></div>"
    f"<table style='border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:12px;width:100%'>"
    f"<tr><td style='{TD}'><code>@{{outputs('Compose_BlockCommands')}}</code></td></tr>"
    f"</table>"
    f"<div style='margin:10px 0 4px 0;font-family:Segoe UI,Arial,sans-serif;font-size:13px'><b>To remove/quarantine the "
    f"message</b></div>"
    f"<div style=\"font-family:Segoe UI,Arial,sans-serif;font-size:12px;color:#323130\">Open "
    f"<a href='https://security.microsoft.com/threatexplorerv3' target='_blank'>Microsoft Defender Threat Explorer</a> "
    f"and search All email using Network message ID <code>@{{outputs('Compose_NetworkMessageId')}}</code> "
    f"(or Subject/Sender/Recipient above), then use Take action &rarr; Move to Deleted Items / Move to Junk / Soft delete "
    f"as appropriate.</div>"
)


def build_definition():
    return {
        "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "$connections": {"defaultValue": {}, "type": "Object"},
            "BlockSenderDomain": {"type": "Bool", "defaultValue": True},
            "BlockSenderAddress": {"type": "Bool", "defaultValue": False},
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
            "Parse_Related_Entities": {
                "runAfter": {}, "type": "ParseJson",
                "inputs": {
                    "content": "@triggerBody()?['object']?['properties']?['relatedEntities']",
                    "schema": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "string"},
                                "name": {"type": "string"},
                                "type": {"type": "string"},
                                "kind": {"type": "string"},
                                "properties": {
                                    "type": "object",
                                    "properties": {
                                        "networkMessageId": {"type": "string"},
                                        "internetMessageId": {"type": "string"},
                                        "p1Sender": {"type": "string"},
                                        "senderIP": {"type": "string"},
                                        "recipient": {"type": "string"},
                                        "receiveDate": {"type": "string"},
                                        "subject": {"type": "string"},
                                    },
                                },
                            },
                        },
                    },
                },
            },
            "Filter_Mail_Entities": {
                "runAfter": after("Parse_Related_Entities"), "type": "Query",
                "inputs": {
                    "from": "@body('Parse_Related_Entities')",
                    "where": "@equals(item()?['kind'], 'MailMessage')",
                },
            },
            "For_each_Mail_entity": {
                "foreach": "@body('Filter_Mail_Entities')",
                "runAfter": after("Filter_Mail_Entities"),
                "type": "Foreach",
                "runtimeConfiguration": {"concurrency": {"repetitions": 1}},
                "actions": {
                    "Compose_NetworkMessageId": {
                        "runAfter": {}, "type": "Compose",
                        "inputs": (
                            "@trim(string(coalesce(items('For_each_Mail_entity')?['properties']?['networkMessageId'], "
                            "items('For_each_Mail_entity')?['NetworkMessageId'], '(unknown)')))"
                        ),
                    },
                    "Compose_Sender": {
                        "runAfter": after("Compose_NetworkMessageId"), "type": "Compose",
                        "inputs": (
                            "@toLower(trim(string(coalesce(items('For_each_Mail_entity')?['properties']?['p1Sender'], "
                            "items('For_each_Mail_entity')?['Sender'], items('For_each_Mail_entity')?['sender'], '(unknown)'))))"
                        ),
                    },
                    "Compose_SenderDomain": {
                        "runAfter": after("Compose_Sender"), "type": "Compose",
                        "inputs": (
                            "@if(contains(outputs('Compose_Sender'), '@'), "
                            "last(split(outputs('Compose_Sender'), '@')), '(unknown)')"
                        ),
                    },
                    "Compose_Recipient": {
                        "runAfter": after("Compose_SenderDomain"), "type": "Compose",
                        "inputs": (
                            "@trim(string(coalesce(items('For_each_Mail_entity')?['properties']?['recipient'], "
                            "items('For_each_Mail_entity')?['Recipient'], '(unknown)')))"
                        ),
                    },
                    "Compose_Subject": {
                        "runAfter": after("Compose_Recipient"), "type": "Compose",
                        "inputs": (
                            "@trim(string(coalesce(items('For_each_Mail_entity')?['properties']?['subject'], "
                            "items('For_each_Mail_entity')?['Subject'], '(no subject)')))"
                        ),
                    },
                    "Compose_BlockCommands": {
                        "runAfter": after("Compose_Subject"), "type": "Compose",
                        "inputs": (
                            "@concat("
                            "if(equals(parameters('BlockSenderDomain'), true), "
                            "concat('New-TenantAllowBlockListItems -ListType Sender -Block -Entries \"', "
                            "outputs('Compose_SenderDomain'), '\" -NoExpiration<br>'), ''), "
                            "if(equals(parameters('BlockSenderAddress'), true), "
                            "concat('New-TenantAllowBlockListItems -ListType Sender -Block -Entries \"', "
                            "outputs('Compose_Sender'), '\" -NoExpiration<br>'), ''), "
                            "if(and(equals(parameters('BlockSenderDomain'), false), equals(parameters('BlockSenderAddress'), false)), "
                            "'(both BlockSenderDomain and BlockSenderAddress are set to false for this deployment -- no command generated)', '')"
                            ")"
                        ),
                    },
                    "Compose_Entity_Comment": {
                        "runAfter": after("Compose_BlockCommands"), "type": "Compose",
                        "inputs": HEADER + EMAIL_ROW,
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
    template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "metadata": {
            "title": "Response (assisted): compose sender block command and quarantine pointer for Mail message entities",
            "description": "For each Mail message entity on a Microsoft Sentinel incident, composes the exact Exchange Online PowerShell command(s) to block the sender/domain and the search values needed to find and remove the message in Microsoft Defender Threat Explorer, and posts them to the incident comment. Does NOT call any write API itself -- writing to the Tenant Allow/Block List is only reliably supported via Exchange Online PowerShell, not a documented Graph HTTP endpoint, so this playbook assists rather than automates. Not wired to an automation rule.",
            "prerequisites": "One existing user-assigned managed identity with Microsoft Sentinel Responder only -- no Graph write permission is needed since this playbook performs no write call.",
            "postDeployment": [
                "Grant the user-assigned managed identity Microsoft Sentinel Responder on the resource group holding the workspace.",
                "Authorise the Microsoft Sentinel API connection.",
                "This playbook only composes commands/links; an analyst (or a separate automation with Exchange Online PowerShell access) still has to run them.",
            ],
            "lastUpdateTime": "2026-09-02",
            "entities": ["MailMessage"],
            "tags": ["Response", "Email", "Assisted", "Tenant Allow-Block List"],
            "support": {"tier": "community"},
        },
        "parameters": {
            **base_parameters("ErgoSOC-AU-Email-BlockSenderAndQuarantine"),
            "BlockSenderDomain": {
                "type": "bool", "defaultValue": True,
                "metadata": {"description": "Include a block command for the sender's whole domain in the generated command list."},
            },
            "BlockSenderAddress": {
                "type": "bool", "defaultValue": False,
                "metadata": {"description": "Include a block command for the exact sender address (in addition to, or instead of, the domain) in the generated command list."},
            },
        },
        "variables": {
            "SentinelConnectionName": "[concat('MicrosoftSentinel-', parameters('PlaybookName'))]",
        },
        "resources": [
            sentinel_connection_resource(),
            workflow_resource(
                definition,
                "ErgoSOC-AU-Email-BlockSenderAndQuarantine",
                extra_deploy_parameters={
                    "BlockSenderDomain": {"value": "[parameters('BlockSenderDomain')]"},
                    "BlockSenderAddress": {"value": "[parameters('BlockSenderAddress')]"},
                },
            ),
        ],
        "outputs": base_outputs(),
    }
    return template


if __name__ == "__main__":
    write_template(build_template(), "azuredeploy-response-email-block.json", HERE)

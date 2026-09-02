#!/usr/bin/env python3
"""Generates azuredeploy-response-email-block.json.

ASSISTED BY DEFAULT, with an opt-in AUTOMATED path. Writing to the
Microsoft 365 Tenant Allow/Block List is only reliably supported via the
Exchange Online PowerShell *-TenantAllowBlockListItems cmdlets -- there is
no well-documented Microsoft Graph HTTP endpoint for it (the Graph beta
tenantAllowBlockLists surface appears to be read-oriented in practice, and
community reports consistently say writes require EXO PowerShell -- see
README-RESPONSE.md for the sources). So this playbook always composes the
exact PowerShell command(s) and posts them to the incident comment for an
analyst to run.

If you've deployed azuredeploy-automation-account-response.json (assigned
a DEDICATED user-assigned managed identity -- deliberately separate from
the UAMI the rest of this repo's playbooks share, to keep its Exchange
Online write access isolated) and published
runbooks/Set-ErgoSOC-TenantBlockListItem.ps1 into it (see
README-RESPONSE.md), you can additionally set AutoExecuteBlock=true and
fill in AutomationAccountResourceId/ExoManagedIdentityClientId/
ExoOrganization to have this playbook actually submit the block as an
Automation job, not just compose the command. That default stays OFF --
turning it on is a deliberate, separate decision from deploying the
playbook itself, since it's a bigger trust escalation (something that can
write to your tenant's mail flow) than everything else in this repo.

The job submission is fire-and-forget (the Automation Job REST API is
asynchronous) -- the comment reports the job ID and tells you to check the
Automation Account's Jobs blade for the actual outcome, it does not poll
for completion within the same Logic App run.
"""
import pathlib

from response_common import (
    ARM_AUTH,
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
    "margin-bottom:10px\">ErgoSOC-AU response playbook &mdash; email block/quarantine "
    "&middot; run @{utcNow()} UTC</div>"
)

EMAIL_ROW = (
    f"<table style='border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:12px;width:100%'>"
    f"<tr><th style='{TH}'>Sender</th><td style='{TD}'>@{{outputs('Compose_Sender')}}</td>"
    f"<th style='{TH}'>Sender domain</th><td style='{TD}'>@{{outputs('Compose_SenderDomain')}}</td></tr>"
    f"<tr><th style='{TH}'>Recipient</th><td style='{TD}'>@{{outputs('Compose_Recipient')}}</td>"
    f"<th style='{TH}'>Subject</th><td style='{TD}'>@{{outputs('Compose_Subject')}}</td></tr>"
    f"<tr><th style='{TH}'>Network message ID</th><td style='{TD}' colspan=\"3\">@{{outputs('Compose_NetworkMessageId')}}</td></tr>"
    f"</table>"
    f"<div style='margin:10px 0 4px 0;font-family:Segoe UI,Arial,sans-serif;font-size:13px'><b>Block command(s)</b> "
    f"<span style=\"font-weight:400;color:#605e5c\">(Exchange Online PowerShell -- the only reliable way to write "
    f"this list)</span></div>"
    f"<table style='border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:12px;width:100%'>"
    f"<tr><td style='{TD}'><code>@{{outputs('Compose_BlockCommands')}}</code></td></tr>"
    f"</table>"
    f"<div style='margin:10px 0 4px 0;font-family:Segoe UI,Arial,sans-serif;font-size:13px'><b>Auto-execute "
    f"(Automation Account)</b></div>"
    f"<table style='border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:12px;width:100%'>"
    f"<tr><th style='{TH}'>Domain block job</th><td style='{TD}'>@{{variables('DomainJobResult')}}</td>"
    f"<th style='{TH}'>Address block job</th><td style='{TD}'>@{{variables('AddressJobResult')}}</td></tr>"
    f"</table>"
    f"<div style='margin:10px 0 4px 0;font-family:Segoe UI,Arial,sans-serif;font-size:13px'><b>To remove/quarantine the "
    f"message</b></div>"
    f"<div style=\"font-family:Segoe UI,Arial,sans-serif;font-size:12px;color:#323130\">Open "
    f"<a href='https://security.microsoft.com/threatexplorerv3' target='_blank'>Microsoft Defender Threat Explorer</a> "
    f"and search All email using Network message ID <code>@{{outputs('Compose_NetworkMessageId')}}</code> "
    f"(or Subject/Sender/Recipient above), then use Take action &rarr; Move to Deleted Items / Move to Junk / Soft delete "
    f"as appropriate.</div>"
)


def submit_job_action(suffix, value_expr):
    """One Automation Job PUT for a given sender/domain value expression
    (e.g. outputs('Compose_SenderDomain')). The job name is a fresh guid()
    generated right before the call, reused in both the URI and the
    reported comment.

    suffix distinguishes the action names of this call site (e.g. 'Domain'
    vs 'Address') -- Logic Apps requires action names to be unique across
    the whole workflow, not just within their own If-branch, so the two
    call sites below can't share plain 'Compose_JobId'/'HTTP_SubmitBlockJob'
    names even though they sit in separate branches."""
    compose_name = f"Compose_JobId_{suffix}"
    http_name = f"HTTP_SubmitBlockJob_{suffix}"
    return {
        compose_name: {"runAfter": {}, "type": "Compose", "inputs": "@guid()"},
        http_name: {
            **http_call(
                f"@{{concat('https://management.azure.com', parameters('AutomationAccountResourceId'), "
                f"'/jobs/', outputs('{compose_name}'), '?api-version=2019-06-01')}}",
                method="PUT", auth=ARM_AUTH,
                body={
                    "properties": {
                        "runbook": {"name": "@{parameters('RunbookName')}"},
                        "parameters": {
                            "ManagedIdentityClientId": "@{parameters('ExoManagedIdentityClientId')}",
                            "Organization": "@{parameters('ExoOrganization')}",
                            "Value": f"@{{{value_expr}}}",
                            "EntryType": "Sender",
                            "Action": "Block",
                        },
                    }
                },
            ),
            "runAfter": after(compose_name),
        },
    }


def build_definition():
    return {
        "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "$connections": {"defaultValue": {}, "type": "Object"},
            "BlockSenderDomain": {"type": "Bool", "defaultValue": True},
            "BlockSenderAddress": {"type": "Bool", "defaultValue": False},
            "AutoExecuteBlock": {"type": "Bool", "defaultValue": False},
            "AutomationAccountResourceId": {"type": "String", "defaultValue": ""},
            "RunbookName": {"type": "String", "defaultValue": "Set-ErgoSOC-TenantBlockListItem"},
            "ExoManagedIdentityClientId": {"type": "String", "defaultValue": ""},
            "ExoOrganization": {"type": "String", "defaultValue": ""},
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
                    "Reset_DomainJobResult": {
                        "runAfter": {}, "type": "SetVariable",
                        "inputs": {"name": "DomainJobResult", "value": "not attempted (AutoExecuteBlock is off, or AutomationAccountResourceId/BlockSenderDomain not set)"},
                    },
                    "Reset_AddressJobResult": {
                        "runAfter": after("Reset_DomainJobResult"), "type": "SetVariable",
                        "inputs": {"name": "AddressJobResult", "value": "not attempted (AutoExecuteBlock is off, or AutomationAccountResourceId/BlockSenderAddress not set)"},
                    },
                    "Compose_NetworkMessageId": {
                        "runAfter": after("Reset_AddressJobResult"), "type": "Compose",
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
                    "Condition_AutoExecute_Domain": {
                        "runAfter": after("Compose_BlockCommands"), "type": "If",
                        "expression": {
                            "and": [
                                {"equals": ["@parameters('AutoExecuteBlock')", True]},
                                {"equals": ["@parameters('BlockSenderDomain')", True]},
                                {"not": {"equals": ["@parameters('AutomationAccountResourceId')", ""]}},
                            ]
                        },
                        "actions": {
                            **submit_job_action("Domain", "outputs('Compose_SenderDomain')"),
                            "Set_DomainJobResult": {
                                "runAfter": after("HTTP_SubmitBlockJob_Domain", states=("Succeeded", "Failed", "Skipped", "TimedOut")),
                                "type": "SetVariable",
                                "inputs": {
                                    "name": "DomainJobResult",
                                    "value": (
                                        "@concat('job ', outputs('Compose_JobId_Domain'), ' submission: ', "
                                        + result_expr("HTTP_SubmitBlockJob_Domain", [200, 201]).lstrip("@")
                                        + ", ' (submission succeeding does not mean the block already applied -- "
                                        + "check the Automation Account Jobs blade for the actual completion status)')"
                                    ),
                                },
                            },
                        },
                        "else": {"actions": {}},
                    },
                    "Condition_AutoExecute_Address": {
                        "runAfter": after("Condition_AutoExecute_Domain"), "type": "If",
                        "expression": {
                            "and": [
                                {"equals": ["@parameters('AutoExecuteBlock')", True]},
                                {"equals": ["@parameters('BlockSenderAddress')", True]},
                                {"not": {"equals": ["@parameters('AutomationAccountResourceId')", ""]}},
                            ]
                        },
                        "actions": {
                            **submit_job_action("Address", "outputs('Compose_Sender')"),
                            "Set_AddressJobResult": {
                                "runAfter": after("HTTP_SubmitBlockJob_Address", states=("Succeeded", "Failed", "Skipped", "TimedOut")),
                                "type": "SetVariable",
                                "inputs": {
                                    "name": "AddressJobResult",
                                    "value": (
                                        "@concat('job ', outputs('Compose_JobId_Address'), ' submission: ', "
                                        + result_expr("HTTP_SubmitBlockJob_Address", [200, 201]).lstrip("@")
                                        + ", ' (submission succeeding does not mean the block already applied -- "
                                        + "check the Automation Account Jobs blade for the actual completion status)')"
                                    ),
                                },
                            },
                        },
                        "else": {"actions": {}},
                    },
                    "Compose_Entity_Comment": {
                        "runAfter": after("Condition_AutoExecute_Address"), "type": "Compose",
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
    inits = {
        "Init_DomainJobResult": {
            "runAfter": {}, "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "DomainJobResult", "type": "string", "value": ""}]},
        },
        "Init_AddressJobResult": {
            "runAfter": after("Init_DomainJobResult"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "AddressJobResult", "type": "string", "value": ""}]},
        },
    }
    definition["actions"] = {**inits, **definition["actions"]}
    definition["actions"]["Parse_Related_Entities"]["runAfter"] = after("Init_AddressJobResult")

    template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "metadata": {
            "title": "Response: block sender/domain (assisted by default, optional auto-execute) and quarantine pointer for Mail message entities",
            "description": "For each Mail message entity on a Microsoft Sentinel incident, composes the exact Exchange Online PowerShell command(s) to block the sender/domain and the search values needed to find and remove the message in Microsoft Defender Threat Explorer, and posts them to the incident comment. If AutoExecuteBlock is set to true and an Automation Account (running runbooks/Set-ErgoSOC-TenantBlockListItem.ps1) is configured, it additionally submits the block as an Automation job -- otherwise it only composes the command for an analyst to run. Not wired to an automation rule.",
            "prerequisites": "One existing user-assigned managed identity with Microsoft Sentinel Responder (this is the Logic App's own identity). If using AutoExecuteBlock, also: an Automation Account (azuredeploy-automation-account-response.json) assigned a SEPARATE dedicated managed identity with the runbook published, Automation Job Operator Azure RBAC on that Automation Account for the Logic App's UAMI, and that Automation Account's own identity registered as an Exchange Online service principal with a scoped role -- see README-RESPONSE.md.",
            "postDeployment": [
                "Grant the user-assigned managed identity Microsoft Sentinel Responder on the resource group holding the workspace.",
                "Authorise the Microsoft Sentinel API connection.",
                "Leave AutoExecuteBlock=false (the default) to stay assisted-only. To enable auto-execution, complete the Automation Account / dedicated identity / EXO RBAC setup in README-RESPONSE.md first, then redeploy with AutoExecuteBlock=true and the Automation Account / Exo* parameters filled in.",
            ],
            "lastUpdateTime": "2026-09-02",
            "entities": ["MailMessage"],
            "tags": ["Response", "Email", "Tenant Allow-Block List"],
            "support": {"tier": "community"},
        },
        "parameters": {
            **base_parameters("ErgoSOC-AU-Email-BlockSenderAndQuarantine"),
            "BlockSenderDomain": {
                "type": "bool", "defaultValue": True,
                "metadata": {"description": "Include a block command (and, if AutoExecuteBlock is on, a job) for the sender's whole domain."},
            },
            "BlockSenderAddress": {
                "type": "bool", "defaultValue": False,
                "metadata": {"description": "Include a block command (and, if AutoExecuteBlock is on, a job) for the exact sender address."},
            },
            "AutoExecuteBlock": {
                "type": "bool", "defaultValue": False,
                "metadata": {"description": "Actually submit the block as an Automation job instead of only composing the command. Requires AutomationAccountResourceId and the Exo* parameters below. Stays off by default -- turn on deliberately, after completing the setup in README-RESPONSE.md."},
            },
            "AutomationAccountResourceId": {
                "type": "string", "defaultValue": "",
                "metadata": {"description": "Full resource ID of the Automation Account from azuredeploy-automation-account-response.json. Required only if AutoExecuteBlock is true."},
            },
            "RunbookName": {
                "type": "string", "defaultValue": "Set-ErgoSOC-TenantBlockListItem",
                "metadata": {"description": "Name of the published runbook (runbooks/Set-ErgoSOC-TenantBlockListItem.ps1) in the Automation Account."},
            },
            "ExoManagedIdentityClientId": {
                "type": "string", "defaultValue": "",
                "metadata": {"description": "Client (application) ID of the DEDICATED managed identity assigned to the Automation Account (the ManagedIdentityClientId output of azuredeploy-automation-account-response.json) -- deliberately a separate identity from this playbook's own UserAssignedManagedIdentityResourceId, so Exchange Online write access stays isolated. Required only if AutoExecuteBlock is true."},
            },
            "ExoOrganization": {
                "type": "string", "defaultValue": "",
                "metadata": {"description": "Tenant's *.onmicrosoft.com domain, passed to Connect-ExchangeOnline. Required only if AutoExecuteBlock is true."},
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
                    "AutoExecuteBlock": {"value": "[parameters('AutoExecuteBlock')]"},
                    "AutomationAccountResourceId": {"value": "[parameters('AutomationAccountResourceId')]"},
                    "RunbookName": {"value": "[parameters('RunbookName')]"},
                    "ExoManagedIdentityClientId": {"value": "[parameters('ExoManagedIdentityClientId')]"},
                    "ExoOrganization": {"value": "[parameters('ExoOrganization')]"},
                },
            ),
        ],
        "outputs": base_outputs(),
    }
    return template


if __name__ == "__main__":
    write_template(build_template(), "azuredeploy-response-email-block.json", HERE)

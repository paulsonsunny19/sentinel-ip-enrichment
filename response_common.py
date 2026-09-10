"""Shared building blocks for the ErgoSOC-AU response (remediation) playbooks.

These are a different category from the six enrichment playbooks in this repo:
they WRITE to Entra ID / Defender for Endpoint instead of only reading and
posting a comment. See README-RESPONSE.md for the full safety model; in short:

  - None of these are wired to a Sentinel automation rule by anything in this
    repo, and none should be by default. That's deliberate: an analyst
    manually clicking "Run playbook" on the incident (Sentinel Portal ->
    incident -> Actions -> Run playbook) *is* the approval gate here. An
    automation rule would remove that checkpoint. Only attach one of these to
    an automation rule if your team has explicitly decided it wants the
    action to run with no human in the loop.
  - Every write call is reported to the incident comment, success or
    failure, with the API's own error detail on failure -- so there's always
    an audit trail of what was attempted and what actually happened. Nothing
    is ever silently assumed to have worked.
  - Each action has its own Enable<Action>/<Action>Confirmed-style bool
    parameter (default true) so a playbook combining two actions can be
    deployed with only one of them turned on.
  - Secrets a call generates (e.g. a temporary password) are never echoed
    into the incident comment or logged -- only whether the action
    succeeded. See each playbook's own module for specifics.
"""
import json


def managed_identity_authentication(audience=None):
    """Return Logic Apps authentication bound to the required user-assigned identity."""
    authentication = {
        "type": "ManagedServiceIdentity",
        "identity": "[parameters('UserAssignedManagedIdentityResourceId')]",
    }
    if audience:
        authentication["audience"] = audience
    return authentication


CONNECTOR_MANAGED_IDENTITY_AUTH = managed_identity_authentication()
GRAPH_AUTH = managed_identity_authentication("https://graph.microsoft.com")
# Defender for Endpoint machine-action API: a separate resource/audience from
# Microsoft Graph, needs its own app-role assignment against the
# "WindowsDefenderATP" enterprise application (not Microsoft Graph).
MDE_AUTH = managed_identity_authentication("https://api.securitycenter.microsoft.com")
# Azure Resource Manager: used to start an Azure Automation runbook job (the
# UAMI needs an Azure RBAC role -- e.g. "Automation Job Operator" -- on the
# target Automation Account, not a Graph app-role assignment).
ARM_AUTH = managed_identity_authentication("https://management.azure.com/")

SENTINEL_CONN = "@parameters('$connections')['azuresentinel']['connectionId']"

# Defender for Endpoint's indicators API lists expirationTime as optional,
# but whether omitting it actually means "never expires" (versus some
# platform default) isn't something this session could verify -- so
# IndicatorExpirationDays=0 is treated as "effectively never" by submitting
# a far-future date instead, rather than relying on unconfirmed omit
# behavior. Used for both the FileHash and IP/URL block-indicator
# playbooks' expirationTime field.
INDICATOR_EXPIRATION_EXPR = (
    "@{if(equals(parameters('IndicatorExpirationDays'), 0), '2099-12-31T00:00:00Z', "
    "addDays(utcNow(), parameters('IndicatorExpirationDays')))}"
)

# Microsoft Sentinel "entity" trigger (Preview) -- an alternative to the
# incident trigger every other playbook in this repo uses. Run manually by
# selecting a single entity inside an incident's overview blade, not by an
# automation rule (entity-triggered playbooks can't be called by one -- a
# real platform limitation, not a choice made here).
#
# Verified against two real sources this session: a live Account-entity
# playbook built in the Portal (Code view + dynamic-content picker), and a
# complete reference sample (a "Reset-AADUserPassword-EntityTrigger"
# template) that corrected two guesses the live-build evidence alone had
# left wrong:
#   - The entity TYPE is baked into the trigger path itself --
#     "/entity/@{encodeURIComponent('Account')}" for an Account entity --
#     not left generic. The live-build example's empty path
#     ("/entity/@{encodeURIComponent('')}") was simply an unfinished
#     trigger configuration, not evidence the path stays generic.
#   - The entity's own data is read directly off
#     triggerBody()?['Entity']?['properties']?[...] -- no "Entities - Get
#     <type>" connector action needed at all (contrast the incident
#     trigger, which needs that action with
#     triggerBody()?['object']?['properties']?['relatedEntities'] as its
#     body). This also sidesteps a real blocker: the entity-trigger
#     flavor of "Entities - Get Accounts" has its own required "Entities
#     list" input with no confirmed value to supply.
#   - An entity trigger fires for exactly one entity, not an array -- no
#     Foreach loop needed, unlike every incident-trigger playbook in this
#     repo.
def entity_trigger(entity_type):
    return {
        "Microsoft_Sentinel_entity": {
            "type": "ApiConnectionWebhook",
            "inputs": {
                "host": {"connection": {"name": SENTINEL_CONN}},
                "body": {"callback_url": "@{listCallbackUrl()}"},
                "path": f"/entity/@{{encodeURIComponent('{entity_type}')}}",
            },
        }
    }


# Field name/casing confirmed against the reference sample above:
# "IncidentArmID" (capital ID), read off triggerBody() directly -- not
# "IncidentArmId" as the live-build dynamic-content label alone had
# suggested (labels are human-friendly, not literal field names). Missing
# entirely (not just an empty string) when the playbook was run without an
# associated incident (e.g. from Hunting) -- confirmed against a real
# deployment error: "Incident Arm id missing" from Incidents/Comment, even
# though Condition_Has_Incident was meant to skip that call in exactly this
# case.
#
# Wrapped in coalesce(..., '') deliberately: WDL's equals() treats null and
# '' as NOT equal (equals(null, '') is false), so a bare
# not(equals(triggerBody()?['IncidentArmID'], '')) reads a genuinely missing
# field as "has an incident" (null != '' passes the not-equals-empty test),
# and the flow proceeds to call Incidents/Comment with a null incidentArmId
# -- which is the exact failure above. Coalescing to '' here, once, at the
# source normalises "missing" and "empty" to the same value everywhere this
# constant is used, so every equals/not-equals check downstream is correct
# regardless of which of the two the trigger actually sends.
#
# Two forms, same expression: INCIDENT_ARM_ID_EXPR (with its leading '@')
# for use as an entire top-level field value (e.g. "incidentArmId": ...,
# or as a whole element of an "equals" array) or an entire "expression"
# string; INCIDENT_ARM_ID_EXPR_RAW (no leading '@') for embedding inside a
# compound expression that's already inside its own '@{...}' wrapper or
# its own leading '@' -- a nested '@' there is invalid WDL syntax.
INCIDENT_ARM_ID_EXPR_RAW = "coalesce(triggerBody()?['IncidentArmID'], '')"
INCIDENT_ARM_ID_EXPR = f"@{INCIDENT_ARM_ID_EXPR_RAW}"

# The entity itself, off the entity trigger's own triggerBody() -- no
# "Entities - Get <type>" action needed. See entity_trigger()'s comment.
ENTITY_PROPERTY_EXPR_RAW = "triggerBody()?['Entity']?['properties']"

TD = "padding:4px 10px;border:1px solid #e1dfdd;vertical-align:top;word-break:break-word;overflow-wrap:anywhere;"
TH = "text-align:left;padding:4px 10px;background:#f3f2f1;border:1px solid #e1dfdd;font-weight:600;white-space:nowrap;"


def after(*names, states=("Succeeded",)):
    return {name: list(states) for name in names}


def http_call(uri_expr, method="GET", auth=GRAPH_AUTH, body=None):
    """A plain HTTP action. runAfter is left empty -- callers set it themselves,
    same convention build_account_template.py's graph_get() uses.

    auth=None omits the "authentication" property entirely (valid, and
    means no auth) -- used for the Teams webhook call, where the webhook
    URL itself is the credential, not a managed-identity call like every
    other HTTP action in this repo."""
    inputs = {
        "method": method,
        "uri": uri_expr,
        "headers": {"Accept": "application/json", "Content-Type": "application/json"},
    }
    if auth is not None:
        inputs["authentication"] = auth
    if body is not None:
        inputs["body"] = body
    return {
        "runAfter": {},
        "type": "Http",
        "inputs": inputs,
        "runtimeConfiguration": {"secureData": {"properties": ["inputs"]}},
    }


def result_expr(http_action_name, success_codes):
    """WDL expression: 'OK' if the named HTTP action returned one of
    success_codes, else 'FAILED (HTTP <code>) - <api error message>'."""
    codes_expr = ", ".join(
        f"equals(outputs('{http_action_name}')?['statusCode'], {c})" for c in success_codes
    )
    return (
        f"@if(or({codes_expr}), 'OK', "
        f"concat('FAILED (HTTP ', string(outputs('{http_action_name}')?['statusCode']), ') - ', "
        f"string(coalesce(outputs('{http_action_name}')?['body']?['error']?['message'], "
        f"string(outputs('{http_action_name}')?['body']), 'no error detail returned'))))"
    )


def base_parameters(default_playbook_name, extra=None):
    params = {
        "PlaybookName": {
            "type": "string", "defaultValue": default_playbook_name,
            "metadata": {"description": "Name of the Logic App playbook."},
        },
        "UserAssignedManagedIdentityResourceId": {
            "type": "string", "minLength": 1,
            "metadata": {"description": "Required. Full resource ID of the existing client-owned user-assigned managed identity used by the Logic App and the Microsoft Sentinel connection."},
        },
        "TeamsWebhookUrl": {
            "type": "securestring", "defaultValue": "",
            "metadata": {"description": "Optional. A Microsoft Teams channel's webhook URL, from that channel's Workflows app -> \"Send webhook alerts to a channel\". When set, this playbook also posts a short notification card (client, ticket number, playbook, incident owner, and what it did) to that channel after running. Leave blank (the default) to skip this -- it's a convenience notification only, not authenticated with the managed identity, and a delivery failure here is not reported back to the incident or retried."},
        },
        "ClientOrganizationName": {
            "type": "string", "defaultValue": "",
            "metadata": {"description": "Optional. Shown at the top of the Teams notification card (only relevant if TeamsWebhookUrl is set) -- e.g. the client/tenant name, useful if one Teams channel receives alerts from more than one deployment. Leave blank to omit it from the card."},
        },
    }
    if extra:
        params.update(extra)
    return params


def _teams_fact(title, value_expr):
    return {"title": title, "value": f"@{{{value_expr}}}"}


def teams_notify_actions(run_after_name, extra_facts, suffix=""):
    """Optional, fire-and-forget Teams channel notification, gated on the
    TeamsWebhookUrl parameter being set (empty by default -- opt-in per
    deployment, same pattern as the email playbook's AutoExecuteBlock).
    No authentication on the HTTP call itself: the webhook URL is the
    credential. A delivery failure here is not reported back to the
    Sentinel incident comment (which stays the authoritative record) and
    is not retried.

    extra_facts: list of (title, value_expr) tuples -- value_expr a raw
    WDL expression fragment (no leading @) -- rendered as additional rows
    in the card's FactSet, after the shared Client/Ticket/Severity/
    Playbook/Incident owner facts every playbook's notification includes.

    The body is a minimal Adaptive Card (a header Container plus a
    FactSet), not a plain {"text": ...} object -- Teams' current "Send
    webhook alerts to a channel" Workflow template (the replacement for
    the retired classic Incoming Webhook connector) posts via a "Post
    card in a chat or channel" action, which deserializes the webhook
    payload itself as an Adaptive Card and fails with "Property 'type'
    must be 'AdaptiveCard'" on anything else -- confirmed against a real
    run. Each fact's own "value" is independently a WDL string
    interpolation ("@{...}"), same as every other per-field value
    elsewhere in this repo's HTTP bodies, rather than one giant concat()
    -- simpler to read in the generated JSON, and lets Teams render each
    fact as its own label/value row instead of one long delimited line.

    "Incident owner" is a best-effort stand-in for "who ran this":
    Sentinel's manual "Run playbook" trigger does not pass the initiating
    analyst's identity into the trigger body, so the incident's assigned
    owner (who may or may not be the same person) is the closest
    available field. For a definitive record of who actually ran it, see
    the Logic App's own Run History or the Azure Activity Log.

    Uses workflow().name for the playbook name, not parameters('PlaybookName')
    -- PlaybookName is only an ARM template parameter (used to name the
    Logic App resource at deploy time), it is never passed into the
    workflow's own runtime parameter set, so referencing it here fails at
    runtime with "workflow parameter 'PlaybookName' is not found."
    workflow().name is the Logic App's own resource name, which is always
    exactly what PlaybookName was at deploy time.

    suffix keeps action names unique when a workflow has more than one
    call site for this (e.g. the IP/URL indicator-block playbook's two
    loops)."""
    condition_name = f"Condition_TeamsNotify{suffix}"
    http_name = f"HTTP_TeamsNotify{suffix}"
    severity_expr = "coalesce(triggerBody()?['object']?['properties']?['severity'], 'Unknown')"
    base_facts = [
        _teams_fact("Ticket", "concat('Incident #', string(triggerBody()?['object']?['properties']?['incidentNumber']))"),
        _teams_fact("Severity", severity_expr),
        _teams_fact("Playbook", "workflow().name"),
        _teams_fact(
            "Incident owner (best-effort)",
            "coalesce(triggerBody()?['object']?['properties']?['owner']?['userPrincipalName'], "
            "triggerBody()?['object']?['properties']?['owner']?['assignedTo'], 'unassigned')",
        ),
    ]
    all_facts = base_facts + [_teams_fact(title, expr) for title, expr in extra_facts]
    return {
        condition_name: {
            "runAfter": after(run_after_name), "type": "If",
            "expression": {"not": {"equals": ["@parameters('TeamsWebhookUrl')", ""]}},
            "actions": {
                http_name: http_call(
                    "@{parameters('TeamsWebhookUrl')}",
                    method="POST", auth=None,
                    body={
                        "type": "AdaptiveCard",
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "version": "1.4",
                        "body": [
                            {
                                "type": "Container",
                                "style": (
                                    f"@{{if(equals({severity_expr}, 'High'), 'attention', "
                                    f"if(equals({severity_expr}, 'Medium'), 'warning', "
                                    f"if(equals({severity_expr}, 'Low'), 'good', 'default')))}}"
                                ),
                                "items": [
                                    {
                                        "type": "TextBlock",
                                        "text": "🛡️ ErgoSOC-AU response playbook run",
                                        "weight": "Bolder",
                                        "size": "Medium",
                                        "wrap": True,
                                    },
                                    {
                                        "type": "TextBlock",
                                        "text": "@{if(equals(parameters('ClientOrganizationName'), ''), 'Client: (not set)', concat('Client: ', parameters('ClientOrganizationName')))}",
                                        "isSubtle": True,
                                        "wrap": True,
                                    },
                                ],
                            },
                            {
                                "type": "FactSet",
                                "facts": all_facts,
                            },
                        ],
                    },
                ),
            },
            "else": {"actions": {}},
        },
    }


def sentinel_connection_resource():
    return {
        "type": "Microsoft.Web/connections", "apiVersion": "2016-06-01",
        "name": "[variables('SentinelConnectionName')]", "location": "[resourceGroup().location]", "kind": "V1",
        "properties": {
            "displayName": "[variables('SentinelConnectionName')]",
            "customParameterValues": {},
            "parameterValueType": "Alternative",
            "api": {"id": "[concat('/subscriptions/', subscription().subscriptionId, '/providers/Microsoft.Web/locations/', resourceGroup().location, '/managedApis/azuresentinel')]"},
        },
    }


def workflow_resource(definition, template_name, extra_deploy_parameters=None):
    """The Microsoft.Logic/workflows resource. extra_deploy_parameters is a dict
    of {paramName: {"value": "[parameters('paramName')]"}} merged into the
    workflow's own $connections+bool-toggle parameter set."""
    deploy_params = {
        "$connections": {
            "value": {
                "azuresentinel": {
                    "connectionId": "[resourceId('Microsoft.Web/connections', variables('SentinelConnectionName'))]",
                    "connectionName": "[variables('SentinelConnectionName')]",
                    "id": "[concat('/subscriptions/', subscription().subscriptionId, '/providers/Microsoft.Web/locations/', resourceGroup().location, '/managedApis/azuresentinel')]",
                    "connectionProperties": {"authentication": CONNECTOR_MANAGED_IDENTITY_AUTH},
                },
            }
        },
    }
    if extra_deploy_parameters:
        deploy_params.update(extra_deploy_parameters)
    return {
        "type": "Microsoft.Logic/workflows", "apiVersion": "2017-07-01",
        "name": "[parameters('PlaybookName')]", "location": "[resourceGroup().location]",
        "identity": {
            "type": "UserAssigned",
            "userAssignedIdentities": {"[parameters('UserAssignedManagedIdentityResourceId')]": {}},
        },
        "tags": {
            "hidden-SentinelTemplateName": template_name,
            "hidden-SentinelTemplateVersion": "1.0",
        },
        "dependsOn": ["[resourceId('Microsoft.Web/connections', variables('SentinelConnectionName'))]"],
        "properties": {
            "state": "Enabled",
            "definition": definition,
            "parameters": deploy_params,
        },
    }


def base_outputs():
    return {
        "PlaybookResourceId": {
            "type": "string", "value": "[resourceId('Microsoft.Logic/workflows', parameters('PlaybookName'))]",
        },
        "ManagedIdentityType": {"type": "string", "value": "UserAssigned"},
        "ManagedIdentityResourceId": {
            "type": "string", "value": "[parameters('UserAssignedManagedIdentityResourceId')]",
        },
        "ManagedIdentityPrincipalId": {
            "type": "string",
            "value": "[reference(parameters('UserAssignedManagedIdentityResourceId'), '2018-11-30').principalId]",
        },
    }


def write_template(template, filename, here):
    output = here / filename
    output.write_text(json.dumps(template, indent=2), encoding="utf-8")
    print(f"wrote {output} ({output.stat().st_size} bytes)")

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

# tiIndicators' expirationDateTime reads as a required field in Microsoft
# Graph's threat-indicator API -- omitting it to get a genuinely permanent
# indicator isn't something we could verify (docs were unreachable this
# session), so IndicatorExpirationDays=0 is treated as "effectively never"
# by submitting a far-future date instead, rather than risking a rejected
# submission on an unconfirmed null/omit behavior.
INDICATOR_EXPIRATION_EXPR = (
    "@{if(equals(parameters('IndicatorExpirationDays'), 0), '2099-12-31T00:00:00Z', "
    "addDays(utcNow(), parameters('IndicatorExpirationDays')))}"
)

TD = "padding:4px 10px;border:1px solid #e1dfdd;vertical-align:top;word-break:break-word;overflow-wrap:anywhere;"
TH = "text-align:left;padding:4px 10px;background:#f3f2f1;border:1px solid #e1dfdd;font-weight:600;white-space:nowrap;"


def after(*names, states=("Succeeded",)):
    return {name: list(states) for name in names}


def http_call(uri_expr, method="GET", auth=GRAPH_AUTH, body=None):
    """A plain HTTP action. runAfter is left empty -- callers set it themselves,
    same convention build_account_template.py's graph_get() uses."""
    inputs = {
        "method": method,
        "uri": uri_expr,
        "headers": {"Accept": "application/json", "Content-Type": "application/json"},
        "authentication": auth,
    }
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
    }
    if extra:
        params.update(extra)
    return params


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

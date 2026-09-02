#!/usr/bin/env python3
"""Generate azuredeploy-account.json for the Sentinel Account (user) enrichment playbook."""

import json
import pathlib


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
MICROSOFT_GRAPH_MANAGED_IDENTITY_AUTH = managed_identity_authentication(
    "https://graph.microsoft.com"
)


KQL_UPN = "@{replace(toLower(outputs('Compose_UPN')), decodeUriComponent('%27'), '')}"


# One workspace query summarizes sign-in activity for this user (interactive +
# non-interactive) into a single JSON row, matching the DefenderJson-style pattern used
# by the other playbooks in this repo. FailedMFA/MFAFraud come from a separate mv-expand
# over each sign-in's per-step AuthenticationDetails, since that's a nested array and
# can't be counted in the same summarize as the row-level stats.
SIGNIN_KQL = f"""let upn = '{KQL_UPN}';
let look = @{{parameters('LookbackDays')}}d;
let AllSignins = union isfuzzy=true
(SigninLogs
 | where TimeGenerated > ago(look)
 | where tolower(tostring(column_ifexists('UserPrincipalName', ''))) == upn
 | extend SourceTable='Interactive'),
(AADNonInteractiveUserSignInLogs
 | where TimeGenerated > ago(look)
 | where tolower(tostring(column_ifexists('UserPrincipalName', ''))) == upn
 | extend SourceTable='NonInteractive');
let MainSummary = AllSignins
| extend SafeResult=tostring(column_ifexists('ResultType', '')),
         SafeRiskLevel=tostring(column_ifexists('RiskLevelDuringSignIn', 'none')),
         SafeRiskState=tostring(column_ifexists('RiskState', 'none')),
         SafeIP=tostring(column_ifexists('IPAddress', '')),
         SafeApp=tostring(column_ifexists('AppDisplayName', '')),
         SafeCity=tostring(parse_json(tostring(column_ifexists('LocationDetails', '{{}}'))).city),
         SafeCountry=tostring(parse_json(tostring(column_ifexists('LocationDetails', '{{}}'))).countryOrRegion),
         SafeDevice=tostring(parse_json(tostring(column_ifexists('DeviceDetail', '{{}}'))).displayName),
         SafeCA=tostring(column_ifexists('ConditionalAccessStatus', ''))
| summarize TotalSignins=count(),
            FailedSignins=countif(SafeResult != '0' and isnotempty(SafeResult)),
            RiskySignins=countif(SafeRiskState !in ('none', '')),
            HighRiskSignins=countif(tolower(SafeRiskLevel) == 'high'),
            CAFailures=countif(tolower(SafeCA) == 'failure'),
            Countries=make_set(SafeCountry, 10), Cities=make_set(SafeCity, 10),
            IPs=make_set(SafeIP, 15), Apps=make_set(SafeApp, 10), Devices=make_set(SafeDevice, 10),
            LastSignin=arg_max(TimeGenerated, SafeResult, SafeRiskLevel, SafeRiskState, SafeIP, SafeApp, SafeCity, SafeCountry, SafeDevice)
| extend LastSigninTime=LastSignin, LastResult=SafeResult, LastRiskLevel=SafeRiskLevel,
         LastRiskState=SafeRiskState, LastIP=SafeIP, LastApp=SafeApp, LastCity=SafeCity,
         LastCountry=SafeCountry, LastDevice=SafeDevice;
let MfaSummary = AllSignins
| mv-expand AuthStep=parse_json(tostring(column_ifexists('AuthenticationDetails', '[]')))
| extend StepMethod=tostring(AuthStep.authenticationMethod),
         StepSucceeded=tostring(AuthStep.succeeded),
         StepDetail=tostring(AuthStep.authenticationStepResultDetail)
| where StepMethod has 'MFA' or StepDetail has 'MFA' or StepDetail has 'fraud'
| summarize FailedMFA=countif(tolower(StepSucceeded) == 'false' and StepDetail !has 'fraud'),
            MFAFraud=countif(StepDetail has 'fraud');
datatable(Seed:int)[1]
| extend TotalSignins=tolong(coalesce(toscalar(MainSummary | project TotalSignins), 0)),
         FailedSignins=tolong(coalesce(toscalar(MainSummary | project FailedSignins), 0)),
         RiskySignins=tolong(coalesce(toscalar(MainSummary | project RiskySignins), 0)),
         HighRiskSignins=tolong(coalesce(toscalar(MainSummary | project HighRiskSignins), 0)),
         CAFailures=tolong(coalesce(toscalar(MainSummary | project CAFailures), 0)),
         Countries=tostring(coalesce(toscalar(MainSummary | project Countries), dynamic([]))),
         Cities=tostring(coalesce(toscalar(MainSummary | project Cities), dynamic([]))),
         IPs=tostring(coalesce(toscalar(MainSummary | project IPs), dynamic([]))),
         Apps=tostring(coalesce(toscalar(MainSummary | project Apps), dynamic([]))),
         Devices=tostring(coalesce(toscalar(MainSummary | project Devices), dynamic([]))),
         LastSigninTime=toscalar(MainSummary | project LastSigninTime),
         LastResult=tostring(coalesce(toscalar(MainSummary | project LastResult), '')),
         LastRiskLevel=tostring(coalesce(toscalar(MainSummary | project LastRiskLevel), '')),
         LastRiskState=tostring(coalesce(toscalar(MainSummary | project LastRiskState), '')),
         LastIP=tostring(coalesce(toscalar(MainSummary | project LastIP), '')),
         LastApp=tostring(coalesce(toscalar(MainSummary | project LastApp), '')),
         LastCity=tostring(coalesce(toscalar(MainSummary | project LastCity), '')),
         LastCountry=tostring(coalesce(toscalar(MainSummary | project LastCountry), '')),
         LastDevice=tostring(coalesce(toscalar(MainSummary | project LastDevice), '')),
         FailedMFA=tolong(coalesce(toscalar(MfaSummary | project FailedMFA), 0)),
         MFAFraud=tolong(coalesce(toscalar(MfaSummary | project MFAFraud), 0))
| project-away Seed"""


WORKSPACE_KQL = f"""let upn = '{KQL_UPN}';
let look = @{{parameters('LookbackDays')}}d;
let watchAlias = '@{{replace(parameters('UserContextWatchlistAlias'), decodeUriComponent('%27'), '')}}';
let TI = union isfuzzy=true
(ThreatIntelIndicators
 | extend SafeKey=tostring(column_ifexists('ObservableKey', '')),
          SafeValue=tolower(tostring(column_ifexists('ObservableValue', ''))),
          SafeConfidence=toint(column_ifexists('Confidence', 0)),
          SafeName=tostring(column_ifexists('Name', '')),
          SafeTags=tostring(column_ifexists('Tags', dynamic([]))),
          SafeModified=todatetime(column_ifexists('Modified', datetime(null))),
          SafeDeleted=tobool(column_ifexists('IsDeleted', false))
 | where SafeDeleted == false and SafeKey == 'email-addr:value' and SafeValue == upn
 | summarize arg_max(TimeGenerated, *) by Id
 | project Source=iff(SafeConfidence >= 70, 'Sentinel TI - high', 'Sentinel TI'),
           Detail=strcat('confidence ', SafeConfidence, '/100 | ', SafeName, ' | tags: ', SafeTags),
           Last=coalesce(SafeModified, TimeGenerated)),
(datatable(Source:string, Detail:string, Last:datetime)[]);
let ClientContext = union isfuzzy=true
(Watchlist
 | where isnotempty(watchAlias) and WatchlistAlias == watchAlias
 | where tolower(SearchKey) == upn
 | summarize arg_max(TimeGenerated, *) by SearchKey
 | extend W=todynamic(WatchlistItem)
 | extend Classification=tolower(coalesce(tostring(W.Classification), tostring(W.Risk), 'unclassified'))
 | project Source=iff(Classification in ('critical', 'high', 'compromised', 'knownbad', 'vip'),
                      'Client user context - critical', 'Client user context'),
           Detail=strcat('classification: ', Classification, ' | owner: ', coalesce(tostring(W.Owner), 'n/a'),
                         ' | department: ', coalesce(tostring(W.Department), 'n/a'),
                         ' | notes: ', coalesce(tostring(W.Description), tostring(W.Notes), 'none')),
           Last=coalesce(todatetime(W.LastUpdated), TimeGenerated)),
(datatable(Source:string, Detail:string, Last:datetime)[]);
let Alerts = union isfuzzy=true
(SecurityAlert
 | where TimeGenerated > ago(look)
 | extend EntityText=tolower(tostring(Entities))
 | where isnotempty(upn) and EntityText contains upn
 | summarize AlertCount=count(), High=countif(tolower(AlertSeverity) == 'high'),
             Names=make_set(AlertName, 15), Severities=make_set(AlertSeverity, 8),
             Products=make_set(ProductName, 8), Last=max(TimeGenerated)
 | project Source=iff(High > 0, 'Sentinel high alert', 'Sentinel alerts'),
           Detail=strcat(AlertCount, ' alert(s), ', High, ' high | ', tostring(Names),
                         ' | severity: ', tostring(Severities), ' | products: ', tostring(Products)), Last),
(datatable(Source:string, Detail:string, Last:datetime)[]);
union TI, ClientContext, Alerts
| where isnotempty(Source)
| order by Last desc
| take 60"""


TH = "text-align:left;padding:4px 10px;background:#f3f2f1;border:1px solid #e1dfdd;font-weight:600;white-space:nowrap"
TD = "padding:4px 10px;border:1px solid #e1dfdd;vertical-align:top"
TBL = "border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:12px;width:100%"
H4 = "margin:12px 0 4px 0;font-family:Segoe UI,Arial,sans-serif;font-size:13px"
CHIP = "display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;color:#ffffff;margin-left:6px;background:"


HEADER = (
    '<div style="font-family:Segoe UI,Arial,sans-serif;font-size:12px;color:#605e5c">'
    "Automated account enrichment &mdash; playbook <b>@{workflow()?['name']}</b> "
    "&middot; run @{formatDateTime(utcNow(), 'yyyy-MM-dd HH:mm')} UTC</div>"
)


# Every section below renders as ONE (or two, for the busiest sections) compact table
# row, self-collapsing to a single status-only row when that source is disabled,
# unpermissioned, or came back empty -- rather than a full sub-table of blank/n-a
# fields. Each is a bare "@..." expression (not "@{...}" interpolation), built with
# concat()/if() so the same string works whether the source's Condition_X_enabled took
# the "if" branch (real data or an HTTP failure) or the "else" branch (disabled): in
# both cases variables('XStatus') already carries the right one-line explanation.
PROFILE_ROW = (
    "@if(equals(variables('ProfileStatus'), 'available'), concat("
    "'<tr><th style=\"" + TH + "\">Profile</th><td style=\"" + TD + "\" colspan=\"3\">', "
    "string(coalesce(variables('ProfileJson')?['displayName'], 'n/a')), ' &lt;', "
    "string(coalesce(variables('ProfileJson')?['userPrincipalName'], 'n/a')), '&gt; &nbsp;|&nbsp; enabled: <b>', "
    "string(coalesce(variables('ProfileJson')?['accountEnabled'], 'n/a')), '</b> &nbsp;|&nbsp; ', "
    "string(coalesce(variables('ProfileJson')?['jobTitle'], 'n/a')), ', ', "
    "string(coalesce(variables('ProfileJson')?['department'], 'n/a')), ' &nbsp;|&nbsp; ', "
    "string(coalesce(variables('ProfileJson')?['officeLocation'], 'n/a')), ', ', "
    "string(coalesce(variables('ProfileJson')?['city'], 'n/a')), ', ', "
    "string(coalesce(variables('ProfileJson')?['country'], 'n/a')), ' &nbsp;|&nbsp; ph: ', "
    "string(coalesce(variables('ProfileJson')?['mobilePhone'], 'n/a')), '</td></tr>', "
    "'<tr><th style=\"" + TH + "\">Manager / AAD roles</th><td style=\"" + TD + "\" colspan=\"3\">', "
    "string(coalesce(variables('ManagerJson')?['displayName'], 'n/a')), ' (', "
    "string(coalesce(variables('ManagerJson')?['userPrincipalName'], 'n/a')), ') &nbsp;|&nbsp; roles: ', "
    "if(equals(variables('RolesStatus'), 'available'), string(variables('RolesJson')), variables('RolesStatus')), "
    "'</td></tr>'), "
    "concat('<tr><th style=\"" + TH + "\">Profile</th><td style=\"" + TD + "\" colspan=\"3\">', variables('ProfileStatus'), '</td></tr>'))"
)


MFA_ROW = (
    "@if(equals(variables('MfaStatus'), 'available'), concat("
    "'<tr><th style=\"" + TH + "\">MFA / SSPR</th><td style=\"" + TD + "\" colspan=\"3\">registered: <b>', "
    "string(coalesce(variables('MfaJson')?['isMfaRegistered'], 'n/a')), '</b> &nbsp;|&nbsp; capable: ', "
    "string(coalesce(variables('MfaJson')?['isMfaCapable'], 'n/a')), ' &nbsp;|&nbsp; SSPR: ', "
    "string(coalesce(variables('MfaJson')?['isSsprRegistered'], 'n/a')), '/', "
    "string(coalesce(variables('MfaJson')?['isSsprCapable'], 'n/a')), ' &nbsp;|&nbsp; passwordless: ', "
    "string(coalesce(variables('MfaJson')?['isPasswordlessCapable'], 'n/a')), ' &nbsp;|&nbsp; default: ', "
    "string(coalesce(variables('MfaJson')?['defaultMfaMethod'], 'n/a')), ' &nbsp;|&nbsp; admin: ', "
    "string(coalesce(variables('MfaJson')?['isAdmin'], 'n/a')), ' &nbsp;|&nbsp; methods: ', "
    "string(coalesce(variables('MfaJson')?['methodsRegistered'], '[]')), '</td></tr>'), "
    "concat('<tr><th style=\"" + TH + "\">MFA / SSPR</th><td style=\"" + TD + "\" colspan=\"3\">', variables('MfaStatus'), '</td></tr>'))"
)


RISK_ROW = (
    "@if(startsWith(variables('RiskStatus'), 'available'), concat("
    "'<tr><th style=\"" + TH + "\">Identity risk</th><td style=\"" + TD + "\" colspan=\"3\">level: <b>', "
    "string(coalesce(variables('RiskJson')?['riskLevel'], 'n/a')), '</b> &nbsp;|&nbsp; state: <b>', "
    "string(coalesce(variables('RiskJson')?['riskState'], 'n/a')), '</b> &nbsp;|&nbsp; detail: ', "
    "string(coalesce(variables('RiskJson')?['riskDetail'], 'n/a')), ' &nbsp;|&nbsp; events: ', "
    "string(length(variables('RiskDetectionsJson'))), "
    "if(greater(length(variables('RiskDetectionsJson')), 0), "
    "concat(' &nbsp;|&nbsp; recent: ', string(variables('RiskDetectionsJson'))), ''), "
    "'</td></tr>'), "
    "concat('<tr><th style=\"" + TH + "\">Identity risk</th><td style=\"" + TD + "\" colspan=\"3\">', variables('RiskStatus'), '</td></tr>'))"
)


OOO_ROW = (
    "@if(equals(variables('OOOStatus'), 'available'), concat("
    "'<tr><th style=\"" + TH + "\">Out-of-office</th><td style=\"" + TD + "\" colspan=\"3\">', "
    "string(coalesce(variables('OOOJson')?['status'], 'n/a')), "
    "if(equals(string(coalesce(variables('OOOJson')?['status'], '')), 'scheduled'), "
    "concat(' (', string(coalesce(variables('OOOJson')?['scheduledStartDateTime'], 'n/a')), ' to ', "
    "string(coalesce(variables('OOOJson')?['scheduledEndDateTime'], 'n/a')), ')'), ''), "
    "'</td></tr>'), "
    "concat('<tr><th style=\"" + TH + "\">Out-of-office</th><td style=\"" + TD + "\" colspan=\"3\">', variables('OOOStatus'), '</td></tr>'))"
)


DEVICES_ROW = (
    "@if(startsWith(variables('DevicesStatus'), 'available'), concat("
    "'<tr><th style=\"" + TH + "\">Registered devices</th><td style=\"" + TD + "\" colspan=\"3\">', "
    "variables('DevicesStatus'), "
    "if(greater(length(variables('DevicesJson')), 0), "
    "concat(' &nbsp;|&nbsp; ', variables('DevicesSummary')), ''), "
    "'</td></tr>'), "
    "concat('<tr><th style=\"" + TH + "\">Registered devices</th><td style=\"" + TD + "\" colspan=\"3\">', variables('DevicesStatus'), '</td></tr>'))"
)


SIGNIN_ROW = (
    "@if(startsWith(variables('SigninStatus'), 'available'), concat("
    "'<tr><th style=\"" + TH + "\">Sign-ins</th><td style=\"" + TD + "\" colspan=\"3\">', "
    "string(coalesce(variables('SigninJson')?['TotalSignins'], 0)), ' total, ', "
    "string(coalesce(variables('SigninJson')?['FailedSignins'], 0)), ' failed &nbsp;|&nbsp; risky: ', "
    "string(coalesce(variables('SigninJson')?['RiskySignins'], 0)), ' (', "
    "string(coalesce(variables('SigninJson')?['HighRiskSignins'], 0)), ' high) &nbsp;|&nbsp; CA fail: ', "
    "string(coalesce(variables('SigninJson')?['CAFailures'], 0)), ' &nbsp;|&nbsp; failed MFA: ', "
    "string(coalesce(variables('SigninJson')?['FailedMFA'], 0)), ' &nbsp;|&nbsp; <b>MFA fraud: ', "
    "string(coalesce(variables('SigninJson')?['MFAFraud'], 0)), '</b></td></tr>', "
    "'<tr><th style=\"" + TH + "\">Sign-in context</th><td style=\"" + TD + "\" colspan=\"3\">countries: ', "
    "string(coalesce(variables('SigninJson')?['Countries'], '[]')), ' &nbsp;|&nbsp; apps: ', "
    "string(coalesce(variables('SigninJson')?['Apps'], '[]')), ' &nbsp;|&nbsp; last: ', "
    "string(coalesce(variables('SigninJson')?['LastSigninTime'], 'n/a')), ' from ', "
    "string(coalesce(variables('SigninJson')?['LastCity'], 'n/a')), ', ', "
    "string(coalesce(variables('SigninJson')?['LastCountry'], 'n/a')), ' (', "
    "string(coalesce(variables('SigninJson')?['LastIP'], 'n/a')), ')</td></tr>'), "
    "concat('<tr><th style=\"" + TH + "\">Sign-ins</th><td style=\"" + TD + "\" colspan=\"3\">', variables('SigninStatus'), '</td></tr>'))"
)


VERDICT_STYLE = (
    "@if(equals(outputs('Compose_Verdict'), 'HIGH'), '%s#a4262c', "
    "if(equals(outputs('Compose_Verdict'), 'MEDIUM'), '%s#986f0b', "
    "if(equals(outputs('Compose_Verdict'), 'LOW'), '%s#107c10', '%s#605e5c')))"
    % (CHIP, CHIP, CHIP, CHIP)
)


# OOO + concurrent sign-in activity is a deliberate combined heuristic: sign-ins landing
# inside a user's own out-of-office window are a stronger tell than either signal alone.
VERDICT = (
    "@if(or("
    "equals(toLower(string(coalesce(variables('RiskJson')?['riskLevel'], ''))), 'high'), "
    "equals(toLower(string(coalesce(variables('RiskJson')?['riskState'], ''))), 'confirmedcompromised'), "
    "greater(int(coalesce(variables('SigninJson')?['HighRiskSignins'], 0)), 0), "
    "greater(int(coalesce(variables('SigninJson')?['MFAFraud'], 0)), 0), "
    "greater(length(body('Filter_High_Workspace_Findings')), 0), "
    "and(equals(toLower(string(coalesce(variables('OOOJson')?['status'], ''))), 'scheduled'), "
    "greater(int(coalesce(variables('SigninJson')?['TotalSignins'], 0)), 0))"
    "), 'HIGH', "
    "if(or("
    "equals(toLower(string(coalesce(variables('RiskJson')?['riskLevel'], ''))), 'medium'), "
    "equals(toLower(string(coalesce(variables('RiskJson')?['riskState'], ''))), 'atrisk'), "
    "greater(int(coalesce(variables('SigninJson')?['RiskySignins'], 0)), 0), "
    "equals(toLower(string(coalesce(variables('MfaJson')?['isMfaRegistered'], 'true'))), 'false'), "
    "equals(toLower(string(coalesce(variables('ProfileJson')?['accountEnabled'], 'true'))), 'false'), "
    "greater(length(outputs('Compose_Workspace_Rows')), 0)"
    "), 'MEDIUM', "
    "if(or(equals(toLower(string(coalesce(variables('RiskJson')?['riskState'], ''))), 'none'), "
    "equals(toLower(string(coalesce(variables('RiskJson')?['riskState'], ''))), 'confirmedsafe'), "
    "equals(int(coalesce(variables('ProfileHasRow'), 0)), 1)), "
    "'LOW', 'UNKNOWN')))"
)


VERDICT_REASON = (
    "@concat('Profile: ', variables('ProfileStatus'), "
    "' &middot; Risk: ', variables('RiskStatus'), "
    "' &middot; MFA: ', variables('MfaStatus'), "
    "' &middot; Sign-ins: ', variables('SigninStatus'), "
    "' &middot; OOO: ', variables('OOOStatus'), "
    "' &middot; workspace rows: ', string(length(outputs('Compose_Workspace_Rows'))))"
)


ACCOUNT_BLOCK = f"""<hr style="border:0;border-top:1px solid #e1dfdd;margin:16px 0">
<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;font-weight:600;margin-bottom:6px">
Account enrichment &mdash; <code>@{{outputs('Compose_UPN')}}</code>
<span style="@{{outputs('Compose_VerdictStyle')}}">@{{outputs('Compose_Verdict')}}</span>
</div>
<div style="font-family:Segoe UI,Arial,sans-serif;font-size:11px;color:#605e5c;margin-bottom:10px">@{{outputs('Compose_VerdictReason')}}</div>
<table style="{TBL}">
@{{variables('ProfileHtml')}}
@{{variables('MfaHtml')}}
@{{variables('RiskHtml')}}
@{{variables('OOOHtml')}}
@{{variables('DevicesHtml')}}
@{{variables('SigninHtml')}}
</table>
<div style="{H4}"><b>Sentinel workspace insights &mdash; last @{{parameters('LookbackDays')}} days</b></div>
<table style="{TBL}">
<tr><th style="{TH}">Source</th><th style="{TH}">Detail</th><th style="{TH}">Last seen (UTC)</th></tr>
@{{if(empty(outputs('Compose_Workspace_Rows')), concat('<tr><td style="{TD}" colspan="3">No matching workspace records, or the queried tables are not collected.</td></tr>'), join(body('Select_Workspace_Rows'), ''))}}
</table>"""


SENTINEL_CONN = "@parameters('$connections')['azuresentinel']['connectionId']"
LA_CONN = "@parameters('$connections')['azuremonitorlogs']['connectionId']"


def after(*names, states=("Succeeded",)):
    return {name: list(states) for name in names}


def graph_get(uri_expr):
    """Create a fail-open Microsoft Graph GET action."""
    return {
        "runAfter": {},
        "type": "Http",
        "inputs": {
            "method": "GET",
            "uri": uri_expr,
            "headers": {"Accept": "application/json"},
            "authentication": MICROSOFT_GRAPH_MANAGED_IDENTITY_AUTH,
        },
        "runtimeConfiguration": {"secureData": {"properties": ["inputs"]}},
    }


definition = {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "$connections": {"defaultValue": {}, "type": "Object"},
        "LookbackDays": {"type": "Int", "defaultValue": 14},
        "EnableUserProfile": {"type": "Bool", "defaultValue": True},
        "EnableRegisteredDevices": {"type": "Bool", "defaultValue": True},
        "EnableMfaMethods": {"type": "Bool", "defaultValue": True},
        "EnableIdentityProtection": {"type": "Bool", "defaultValue": True},
        "EnableMailboxSettings": {"type": "Bool", "defaultValue": True},
        "EnableSigninHistory": {"type": "Bool", "defaultValue": True},
        "UserContextWatchlistAlias": {"type": "String", "defaultValue": "UserContext"},
        "WorkspaceSubscriptionId": {"type": "String"},
        "WorkspaceResourceGroup": {"type": "String"},
        "WorkspaceName": {"type": "String"},
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
        "Init_HtmlBody": {
            "runAfter": {}, "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "HtmlBody", "type": "string", "value": HEADER}]},
        },
        "Init_ProfileJson": {
            "runAfter": after("Init_HtmlBody"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "ProfileJson", "type": "object", "value": {}}]},
        },
        "Init_ProfileHasRow": {
            "runAfter": after("Init_ProfileJson"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "ProfileHasRow", "type": "integer", "value": 0}]},
        },
        "Init_ProfileStatus": {
            "runAfter": after("Init_ProfileHasRow"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "ProfileStatus", "type": "string", "value": "disabled by deployment setting"}]},
        },
        "Init_ProfileHtml": {
            "runAfter": after("Init_ProfileStatus"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "ProfileHtml", "type": "string", "value": ""}]},
        },
        "Init_ManagerJson": {
            "runAfter": after("Init_ProfileHtml"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "ManagerJson", "type": "object", "value": {}}]},
        },
        "Init_RolesJson": {
            "runAfter": after("Init_ManagerJson"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "RolesJson", "type": "array", "value": []}]},
        },
        "Init_RolesStatus": {
            "runAfter": after("Init_RolesJson"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "RolesStatus", "type": "string", "value": "disabled by deployment setting"}]},
        },
        "Init_DevicesJson": {
            "runAfter": after("Init_RolesStatus"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "DevicesJson", "type": "array", "value": []}]},
        },
        "Init_DevicesStatus": {
            "runAfter": after("Init_DevicesJson"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "DevicesStatus", "type": "string", "value": "disabled by deployment setting"}]},
        },
        "Init_DevicesHtml": {
            "runAfter": after("Init_DevicesStatus"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "DevicesHtml", "type": "string", "value": ""}]},
        },
        "Init_DevicesSummary": {
            "runAfter": after("Init_DevicesHtml"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "DevicesSummary", "type": "string", "value": ""}]},
        },
        "Init_MfaJson": {
            "runAfter": after("Init_DevicesHtml"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "MfaJson", "type": "object", "value": {}}]},
        },
        "Init_MfaStatus": {
            "runAfter": after("Init_MfaJson"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "MfaStatus", "type": "string", "value": "disabled by deployment setting"}]},
        },
        "Init_MfaHtml": {
            "runAfter": after("Init_MfaStatus"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "MfaHtml", "type": "string", "value": ""}]},
        },
        "Init_RiskJson": {
            "runAfter": after("Init_MfaHtml"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "RiskJson", "type": "object", "value": {}}]},
        },
        "Init_RiskDetectionsJson": {
            "runAfter": after("Init_RiskJson"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "RiskDetectionsJson", "type": "array", "value": []}]},
        },
        "Init_RiskStatus": {
            "runAfter": after("Init_RiskDetectionsJson"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "RiskStatus", "type": "string", "value": "disabled by deployment setting"}]},
        },
        "Init_RiskHtml": {
            "runAfter": after("Init_RiskStatus"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "RiskHtml", "type": "string", "value": ""}]},
        },
        "Init_OOOJson": {
            "runAfter": after("Init_RiskHtml"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "OOOJson", "type": "object", "value": {}}]},
        },
        "Init_OOOStatus": {
            "runAfter": after("Init_OOOJson"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "OOOStatus", "type": "string", "value": "disabled by deployment setting"}]},
        },
        "Init_OOOHtml": {
            "runAfter": after("Init_OOOStatus"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "OOOHtml", "type": "string", "value": ""}]},
        },
        "Init_SigninJson": {
            "runAfter": after("Init_OOOHtml"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "SigninJson", "type": "object", "value": {}}]},
        },
        "Init_SigninStatus": {
            "runAfter": after("Init_SigninJson"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "SigninStatus", "type": "string", "value": "disabled by deployment setting"}]},
        },
        "Init_SigninHtml": {
            "runAfter": after("Init_SigninStatus"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "SigninHtml", "type": "string", "value": ""}]},
        },
        "Init_ResolvedObjectId": {
            "runAfter": after("Init_SigninHtml"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "ResolvedObjectId", "type": "string", "value": ""}]},
        },
        "Entities_-_Get_Accounts": {
            "runAfter": after("Init_ResolvedObjectId"), "type": "ApiConnection",
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
                "Reset_ProfileJson": {
                    "runAfter": {}, "type": "SetVariable",
                    "inputs": {"name": "ProfileJson", "value": {}},
                },
                "Reset_ProfileHasRow": {
                    "runAfter": after("Reset_ProfileJson"), "type": "SetVariable",
                    "inputs": {"name": "ProfileHasRow", "value": 0},
                },
                "Reset_ProfileStatus": {
                    "runAfter": after("Reset_ProfileHasRow"), "type": "SetVariable",
                    "inputs": {"name": "ProfileStatus", "value": "disabled by deployment setting"},
                },
                "Reset_ProfileHtml": {
                    "runAfter": after("Reset_ProfileStatus"), "type": "SetVariable",
                    "inputs": {"name": "ProfileHtml", "value": ""},
                },
                "Reset_ManagerJson": {
                    "runAfter": after("Reset_ProfileHtml"), "type": "SetVariable",
                    "inputs": {"name": "ManagerJson", "value": {}},
                },
                "Reset_RolesJson": {
                    "runAfter": after("Reset_ManagerJson"), "type": "SetVariable",
                    "inputs": {"name": "RolesJson", "value": []},
                },
                "Reset_RolesStatus": {
                    "runAfter": after("Reset_RolesJson"), "type": "SetVariable",
                    "inputs": {"name": "RolesStatus", "value": "disabled by deployment setting"},
                },
                "Reset_DevicesJson": {
                    "runAfter": after("Reset_RolesStatus"), "type": "SetVariable",
                    "inputs": {"name": "DevicesJson", "value": []},
                },
                "Reset_DevicesStatus": {
                    "runAfter": after("Reset_DevicesJson"), "type": "SetVariable",
                    "inputs": {"name": "DevicesStatus", "value": "disabled by deployment setting"},
                },
                "Reset_DevicesHtml": {
                    "runAfter": after("Reset_DevicesStatus"), "type": "SetVariable",
                    "inputs": {"name": "DevicesHtml", "value": ""},
                },
                "Reset_DevicesSummary": {
                    "runAfter": after("Reset_DevicesHtml"), "type": "SetVariable",
                    "inputs": {"name": "DevicesSummary", "value": ""},
                },
                "Reset_MfaJson": {
                    "runAfter": after("Reset_DevicesSummary"), "type": "SetVariable",
                    "inputs": {"name": "MfaJson", "value": {}},
                },
                "Reset_MfaStatus": {
                    "runAfter": after("Reset_MfaJson"), "type": "SetVariable",
                    "inputs": {"name": "MfaStatus", "value": "disabled by deployment setting"},
                },
                "Reset_MfaHtml": {
                    "runAfter": after("Reset_MfaStatus"), "type": "SetVariable",
                    "inputs": {"name": "MfaHtml", "value": ""},
                },
                "Reset_RiskJson": {
                    "runAfter": after("Reset_MfaHtml"), "type": "SetVariable",
                    "inputs": {"name": "RiskJson", "value": {}},
                },
                "Reset_RiskDetectionsJson": {
                    "runAfter": after("Reset_RiskJson"), "type": "SetVariable",
                    "inputs": {"name": "RiskDetectionsJson", "value": []},
                },
                "Reset_RiskStatus": {
                    "runAfter": after("Reset_RiskDetectionsJson"), "type": "SetVariable",
                    "inputs": {"name": "RiskStatus", "value": "disabled by deployment setting"},
                },
                "Reset_RiskHtml": {
                    "runAfter": after("Reset_RiskStatus"), "type": "SetVariable",
                    "inputs": {"name": "RiskHtml", "value": ""},
                },
                "Reset_OOOJson": {
                    "runAfter": after("Reset_RiskHtml"), "type": "SetVariable",
                    "inputs": {"name": "OOOJson", "value": {}},
                },
                "Reset_OOOStatus": {
                    "runAfter": after("Reset_OOOJson"), "type": "SetVariable",
                    "inputs": {"name": "OOOStatus", "value": "disabled by deployment setting"},
                },
                "Reset_OOOHtml": {
                    "runAfter": after("Reset_OOOStatus"), "type": "SetVariable",
                    "inputs": {"name": "OOOHtml", "value": ""},
                },
                "Reset_SigninJson": {
                    "runAfter": after("Reset_OOOHtml"), "type": "SetVariable",
                    "inputs": {"name": "SigninJson", "value": {}},
                },
                "Reset_SigninStatus": {
                    "runAfter": after("Reset_SigninJson"), "type": "SetVariable",
                    "inputs": {"name": "SigninStatus", "value": "disabled by deployment setting"},
                },
                "Reset_SigninHtml": {
                    "runAfter": after("Reset_SigninStatus"), "type": "SetVariable",
                    "inputs": {"name": "SigninHtml", "value": ""},
                },
                "Reset_ResolvedObjectId": {
                    "runAfter": after("Reset_SigninHtml"), "type": "SetVariable",
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
                        "items('For_each_Account_entity')?['displayName'], '')))"
                    ),
                },
                "Compose_User_Ref": {
                    "runAfter": after("Compose_Display_Name_Entity"), "type": "Compose",
                    "inputs": (
                        "@if(not(equals(outputs('Compose_AadUserId'), '')), outputs('Compose_AadUserId'), outputs('Compose_UPN'))"
                    ),
                },
                "Condition_Resolve_ObjectId": {
                    "runAfter": after("Compose_User_Ref"), "type": "If",
                    "expression": {
                        "and": [
                            {"equals": ["@outputs('Compose_AadUserId')", ""]},
                            {"not": {"equals": ["@outputs('Compose_UPN')", ""]}},
                            {"equals": ["@parameters('EnableIdentityProtection')", True]},
                        ]
                    },
                    "actions": {
                        "HTTP_Resolve_User_Id": graph_get(
                            "@{concat('https://graph.microsoft.com/v1.0/users/', "
                            "uriComponent(outputs('Compose_UPN')), '?$select=id')}"
                        ),
                        "Set_ResolvedObjectId": {
                            "runAfter": after("HTTP_Resolve_User_Id", states=("Succeeded", "Failed", "TimedOut")),
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
                    "inputs": (
                        "@if(not(equals(outputs('Compose_AadUserId'), '')), outputs('Compose_AadUserId'), variables('ResolvedObjectId'))"
                    ),
                },
                "Condition_UserProfile_enabled": {
                    "runAfter": after("Compose_Effective_Object_Id"), "type": "If",
                    "expression": {"and": [{"equals": ["@parameters('EnableUserProfile')", True]}]},
                    "actions": {
                        "HTTP_Graph_Profile": graph_get(
                            "@{concat('https://graph.microsoft.com/v1.0/users/', "
                            "uriComponent(outputs('Compose_User_Ref')), "
                            "'?$select=id,displayName,userPrincipalName,mail,jobTitle,department,"
                            "officeLocation,city,state,country,mobilePhone,accountEnabled,"
                            "createdDateTime,onPremisesSyncEnabled')}"
                        ),
                        "HTTP_Graph_Manager": graph_get(
                            "@{concat('https://graph.microsoft.com/v1.0/users/', "
                            "uriComponent(outputs('Compose_User_Ref')), "
                            "'/manager?$select=displayName,userPrincipalName')}"
                        ),
                        "Set_ManagerJson": {
                            "runAfter": after("HTTP_Graph_Manager", states=("Succeeded", "Failed", "TimedOut")),
                            "type": "SetVariable",
                            "inputs": {
                                "name": "ManagerJson",
                                "value": (
                                    "@if(equals(outputs('HTTP_Graph_Manager')?['statusCode'], 200), "
                                    "body('HTTP_Graph_Manager'), json('{}'))"
                                ),
                            },
                        },
                        # AAD directory-role membership. Requires Directory.Read.All in
                        # addition to User.Read.All; both are needed for EnableUserProfile.
                        "HTTP_Graph_Roles": graph_get(
                            "@{concat('https://graph.microsoft.com/v1.0/users/', "
                            "uriComponent(outputs('Compose_User_Ref')), "
                            "'/memberOf/microsoft.graph.directoryRole?$select=displayName')}"
                        ),
                        "Compose_Roles_Raw": {
                            "runAfter": after("HTTP_Graph_Roles", states=("Succeeded", "Failed", "TimedOut")),
                            "type": "Compose",
                            "inputs": (
                                "@if(equals(outputs('HTTP_Graph_Roles')?['statusCode'], 200), "
                                "coalesce(body('HTTP_Graph_Roles')?['value'], json('[]')), json('[]'))"
                            ),
                        },
                        "Select_Role_Names": {
                            "runAfter": after("Compose_Roles_Raw"), "type": "Select",
                            "inputs": {
                                "from": "@outputs('Compose_Roles_Raw')",
                                "select": "@item()?['displayName']",
                            },
                        },
                        "Set_RolesJson": {
                            "runAfter": after("Select_Role_Names"), "type": "SetVariable",
                            "inputs": {"name": "RolesJson", "value": "@body('Select_Role_Names')"},
                        },
                        "Set_RolesStatus": {
                            "runAfter": after("Set_RolesJson"), "type": "SetVariable",
                            "inputs": {
                                "name": "RolesStatus",
                                "value": (
                                    "@if(equals(outputs('HTTP_Graph_Roles')?['statusCode'], 200), 'available', "
                                    "concat('unavailable (HTTP ', string(coalesce(outputs('HTTP_Graph_Roles')?['statusCode'], 'no response')), ')'))"
                                ),
                            },
                        },
                        "Set_ProfileJson": {
                            "runAfter": after("HTTP_Graph_Profile", states=("Succeeded", "Failed", "TimedOut")),
                            "type": "SetVariable",
                            "inputs": {
                                "name": "ProfileJson",
                                "value": (
                                    "@if(equals(outputs('HTTP_Graph_Profile')?['statusCode'], 200), "
                                    "body('HTTP_Graph_Profile'), json('{}'))"
                                ),
                            },
                        },
                        "Set_ProfileHasRow": {
                            "runAfter": after("Set_ProfileJson"), "type": "SetVariable",
                            "inputs": {
                                "name": "ProfileHasRow",
                                "value": "@if(equals(outputs('HTTP_Graph_Profile')?['statusCode'], 200), 1, 0)",
                            },
                        },
                        "Set_ProfileStatus": {
                            "runAfter": after("Set_ProfileHasRow"), "type": "SetVariable",
                            "inputs": {
                                "name": "ProfileStatus",
                                "value": (
                                    "@if(equals(outputs('HTTP_Graph_Profile')?['statusCode'], 200), 'available', "
                                    "concat('unavailable (HTTP ', string(coalesce(outputs('HTTP_Graph_Profile')?['statusCode'], 'no response')), ')'))"
                                ),
                            },
                        },
                        "Set_ProfileHtml": {
                            "runAfter": after("Set_ProfileStatus", "Set_ManagerJson", "Set_RolesStatus"), "type": "SetVariable",
                            "inputs": {"name": "ProfileHtml", "value": PROFILE_ROW},
                        },
                    },
                    "else": {
                        "actions": {
                            "Set_ProfileHtml_disabled": {
                                "runAfter": {}, "type": "SetVariable",
                                "inputs": {"name": "ProfileHtml", "value": PROFILE_ROW},
                            }
                        }
                    },
                },
                "Condition_Devices_enabled": {
                    "runAfter": after("Condition_UserProfile_enabled"), "type": "If",
                    "expression": {"and": [{"equals": ["@parameters('EnableRegisteredDevices')", True]}]},
                    "actions": {
                        "HTTP_Graph_Devices": graph_get(
                            "@{concat('https://graph.microsoft.com/v1.0/users/', "
                            "uriComponent(outputs('Compose_User_Ref')), "
                            "'/registeredDevices?$select=id,displayName,operatingSystem,"
                            "operatingSystemVersion,trustType,approximateLastSignInDateTime,"
                            "isCompliant,isManaged&$top=50')}"
                        ),
                        "Set_DevicesJson": {
                            "runAfter": after("HTTP_Graph_Devices", states=("Succeeded", "Failed", "TimedOut")),
                            "type": "SetVariable",
                            "inputs": {
                                "name": "DevicesJson",
                                "value": (
                                    "@if(equals(outputs('HTTP_Graph_Devices')?['statusCode'], 200), "
                                    "coalesce(body('HTTP_Graph_Devices')?['value'], json('[]')), json('[]'))"
                                ),
                            },
                        },
                        "Select_Device_Rows": {
                            "runAfter": after("Set_DevicesJson"), "type": "Select",
                            "inputs": {
                                "from": "@variables('DevicesJson')",
                                "select": (
                                    "@concat(coalesce(item()?['displayName'], 'unknown'), ' (', "
                                    "coalesce(item()?['operatingSystem'], '?'), '; ', "
                                    "coalesce(item()?['trustType'], '?'), '; ', "
                                    "if(equals(item()?['isCompliant'], true), 'compliant', 'noncompliant'), "
                                    "if(equals(item()?['isManaged'], true), ', managed)', ')'))"
                                ),
                            },
                        },
                        "Set_DevicesSummary": {
                            "runAfter": after("Select_Device_Rows"), "type": "SetVariable",
                            "inputs": {
                                "name": "DevicesSummary",
                                "value": "@join(body('Select_Device_Rows'), ', ')",
                            },
                        },
                        "Set_DevicesStatus": {
                            "runAfter": after("Set_DevicesSummary"), "type": "SetVariable",
                            "inputs": {
                                "name": "DevicesStatus",
                                "value": (
                                    "@if(not(equals(outputs('HTTP_Graph_Devices')?['statusCode'], 200)), "
                                    "concat('unavailable (HTTP ', string(coalesce(outputs('HTTP_Graph_Devices')?['statusCode'], 'no response')), ')'), "
                                    "concat('available; ', string(length(variables('DevicesJson'))), ' device(s)'))"
                                ),
                            },
                        },
                        "Set_DevicesHtml": {
                            "runAfter": after("Set_DevicesStatus"), "type": "SetVariable",
                            "inputs": {"name": "DevicesHtml", "value": DEVICES_ROW},
                        },
                    },
                    "else": {
                        "actions": {
                            "Set_DevicesHtml_disabled": {
                                "runAfter": {}, "type": "SetVariable",
                                "inputs": {"name": "DevicesHtml", "value": DEVICES_ROW},
                            }
                        }
                    },
                },
                "Condition_Mfa_enabled": {
                    "runAfter": after("Condition_Devices_enabled"), "type": "If",
                    "expression": {"and": [{"equals": ["@parameters('EnableMfaMethods')", True]}]},
                    "actions": {
                        "HTTP_Graph_Mfa": graph_get(
                            "@{concat('https://graph.microsoft.com/v1.0/reports/authenticationMethods/"
                            "userRegistrationDetails/', uriComponent(outputs('Compose_User_Ref')))}"
                        ),
                        "Set_MfaJson": {
                            "runAfter": after("HTTP_Graph_Mfa", states=("Succeeded", "Failed", "TimedOut")),
                            "type": "SetVariable",
                            "inputs": {
                                "name": "MfaJson",
                                "value": (
                                    "@if(equals(outputs('HTTP_Graph_Mfa')?['statusCode'], 200), "
                                    "body('HTTP_Graph_Mfa'), json('{}'))"
                                ),
                            },
                        },
                        "Set_MfaStatus": {
                            "runAfter": after("Set_MfaJson"), "type": "SetVariable",
                            "inputs": {
                                "name": "MfaStatus",
                                "value": (
                                    "@if(equals(outputs('HTTP_Graph_Mfa')?['statusCode'], 200), 'available', "
                                    "concat('unavailable (HTTP ', string(coalesce(outputs('HTTP_Graph_Mfa')?['statusCode'], 'no response')), ')'))"
                                ),
                            },
                        },
                        "Set_MfaHtml": {
                            "runAfter": after("Set_MfaStatus"), "type": "SetVariable",
                            "inputs": {"name": "MfaHtml", "value": MFA_ROW},
                        },
                    },
                    "else": {
                        "actions": {
                            "Set_MfaHtml_disabled": {
                                "runAfter": {}, "type": "SetVariable",
                                "inputs": {"name": "MfaHtml", "value": MFA_ROW},
                            }
                        }
                    },
                },
                "Condition_IdentityProtection_enabled": {
                    "runAfter": after("Condition_Mfa_enabled"), "type": "If",
                    "expression": {
                        "and": [
                            {"equals": ["@parameters('EnableIdentityProtection')", True]},
                            {"not": {"equals": ["@outputs('Compose_Effective_Object_Id')", ""]}},
                        ]
                    },
                    "actions": {
                        "HTTP_Graph_RiskyUser": graph_get(
                            "@{concat('https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/', "
                            "uriComponent(outputs('Compose_Effective_Object_Id')))}"
                        ),
                        # Workflow Definition Language string literals only support single
                        # quotes, escaped by doubling ('' -> literal '); there is no
                        # double-quoted string form. 'userId eq ''' closes with an escaped
                        # quote (-> "userId eq '"), and '''' alone is a lone escaped quote.
                        "HTTP_Graph_RiskDetections": graph_get(
                            "@{concat('https://graph.microsoft.com/v1.0/identityProtection/riskDetections?"
                            "$filter=', uriComponent(concat('userId eq ''', outputs('Compose_Effective_Object_Id'), "
                            "'''')), '&$top=10&$orderby=detectedDateTime desc')}"
                        ),
                        "Set_RiskJson": {
                            "runAfter": after("HTTP_Graph_RiskyUser", states=("Succeeded", "Failed", "TimedOut")),
                            "type": "SetVariable",
                            "inputs": {
                                "name": "RiskJson",
                                "value": (
                                    "@if(equals(outputs('HTTP_Graph_RiskyUser')?['statusCode'], 200), "
                                    "body('HTTP_Graph_RiskyUser'), json('{}'))"
                                ),
                            },
                        },
                        "Set_RiskDetectionsJson": {
                            "runAfter": after("HTTP_Graph_RiskDetections", states=("Succeeded", "Failed", "TimedOut")),
                            "type": "SetVariable",
                            "inputs": {
                                "name": "RiskDetectionsJson",
                                "value": (
                                    "@if(equals(outputs('HTTP_Graph_RiskDetections')?['statusCode'], 200), "
                                    "coalesce(body('HTTP_Graph_RiskDetections')?['value'], json('[]')), json('[]'))"
                                ),
                            },
                        },
                        "Set_RiskStatus": {
                            "runAfter": after("Set_RiskJson", "Set_RiskDetectionsJson", states=("Succeeded", "Failed", "TimedOut")),
                            "type": "SetVariable",
                            "inputs": {
                                "name": "RiskStatus",
                                "value": (
                                    "@if(equals(outputs('HTTP_Graph_RiskyUser')?['statusCode'], 200), "
                                    "concat('available; risk level ', string(coalesce(variables('RiskJson')?['riskLevel'], 'unknown'))), "
                                    "if(equals(outputs('HTTP_Graph_RiskyUser')?['statusCode'], 404), "
                                    "'available; no risky-user record (never flagged)', "
                                    "concat('unavailable (HTTP ', string(coalesce(outputs('HTTP_Graph_RiskyUser')?['statusCode'], 'no response')), ')')))"
                                ),
                            },
                        },
                        "Set_RiskHtml": {
                            "runAfter": after("Set_RiskStatus"), "type": "SetVariable",
                            "inputs": {"name": "RiskHtml", "value": RISK_ROW},
                        },
                    },
                    "else": {
                        "actions": {
                            "Set_RiskHtml_disabled": {
                                "runAfter": {}, "type": "SetVariable",
                                "inputs": {"name": "RiskHtml", "value": RISK_ROW},
                            }
                        }
                    },
                },
                "Condition_Mailbox_enabled": {
                    "runAfter": after("Condition_IdentityProtection_enabled"), "type": "If",
                    "expression": {"and": [{"equals": ["@parameters('EnableMailboxSettings')", True]}]},
                    "actions": {
                        "HTTP_Graph_MailboxSettings": graph_get(
                            "@{concat('https://graph.microsoft.com/v1.0/users/', "
                            "uriComponent(outputs('Compose_User_Ref')), "
                            "'/mailboxSettings?$select=automaticRepliesSetting')}"
                        ),
                        "Set_OOOJson": {
                            "runAfter": after("HTTP_Graph_MailboxSettings", states=("Succeeded", "Failed", "TimedOut")),
                            "type": "SetVariable",
                            "inputs": {
                                "name": "OOOJson",
                                "value": (
                                    "@if(equals(outputs('HTTP_Graph_MailboxSettings')?['statusCode'], 200), "
                                    "coalesce(body('HTTP_Graph_MailboxSettings')?['automaticRepliesSetting'], json('{}')), json('{}'))"
                                ),
                            },
                        },
                        "Set_OOOStatus": {
                            "runAfter": after("Set_OOOJson"), "type": "SetVariable",
                            "inputs": {
                                "name": "OOOStatus",
                                "value": (
                                    "@if(equals(outputs('HTTP_Graph_MailboxSettings')?['statusCode'], 200), 'available', "
                                    "concat('unavailable (HTTP ', string(coalesce(outputs('HTTP_Graph_MailboxSettings')?['statusCode'], 'no response')), ')'))"
                                ),
                            },
                        },
                        "Set_OOOHtml": {
                            "runAfter": after("Set_OOOStatus"), "type": "SetVariable",
                            "inputs": {"name": "OOOHtml", "value": OOO_ROW},
                        },
                    },
                    "else": {
                        "actions": {
                            "Set_OOOHtml_disabled": {
                                "runAfter": {}, "type": "SetVariable",
                                "inputs": {"name": "OOOHtml", "value": OOO_ROW},
                            }
                        }
                    },
                },
                "Condition_Signin_enabled": {
                    "runAfter": after("Condition_Mailbox_enabled"), "type": "If",
                    "expression": {"and": [{"equals": ["@parameters('EnableSigninHistory')", True]}]},
                    "actions": {
                        "Run_KQL_Signin_Summary": {
                            "runAfter": {}, "type": "ApiConnection",
                            "inputs": {
                                "host": {"connection": {"name": LA_CONN}},
                                "method": "post",
                                "body": SIGNIN_KQL,
                                "path": "/queryData",
                                "queries": {
                                    "subscriptions": "@parameters('WorkspaceSubscriptionId')",
                                    "resourcegroups": "@parameters('WorkspaceResourceGroup')",
                                    "resourcetype": "Log Analytics Workspace",
                                    "resourcename": "@parameters('WorkspaceName')",
                                    "timerange": "Set in query",
                                },
                            },
                        },
                        "Compose_Signin_Rows": {
                            "runAfter": after("Run_KQL_Signin_Summary", states=("Succeeded", "Failed", "TimedOut")),
                            "type": "Compose",
                            "inputs": (
                                "@if(equals(actions('Run_KQL_Signin_Summary')?['status'], 'Succeeded'), "
                                "coalesce(body('Run_KQL_Signin_Summary')?['value'], json('[]')), json('[]'))"
                            ),
                        },
                        "Set_SigninJson": {
                            "runAfter": after("Compose_Signin_Rows"), "type": "SetVariable",
                            "inputs": {
                                "name": "SigninJson",
                                "value": "@if(greater(length(outputs('Compose_Signin_Rows')), 0), first(outputs('Compose_Signin_Rows')), json('{}'))",
                            },
                        },
                        "Set_SigninStatus": {
                            "runAfter": after("Set_SigninJson"), "type": "SetVariable",
                            "inputs": {
                                "name": "SigninStatus",
                                "value": (
                                    "@if(not(equals(actions('Run_KQL_Signin_Summary')?['status'], 'Succeeded')), "
                                    "'unavailable (workspace query failed; SigninLogs/AADNonInteractiveUserSignInLogs may not be collected)', "
                                    "if(greater(int(coalesce(variables('SigninJson')?['TotalSignins'], 0)), 0), 'available; sign-ins found', 'available; no sign-ins in range'))"
                                ),
                            },
                        },
                        "Set_SigninHtml": {
                            "runAfter": after("Set_SigninStatus"), "type": "SetVariable",
                            "inputs": {"name": "SigninHtml", "value": SIGNIN_ROW},
                        },
                    },
                    "else": {
                        "actions": {
                            "Set_SigninHtml_disabled": {
                                "runAfter": {}, "type": "SetVariable",
                                "inputs": {"name": "SigninHtml", "value": SIGNIN_ROW},
                            }
                        }
                    },
                },
                "Run_KQL_workspace_context": {
                    "runAfter": after("Condition_Signin_enabled"), "type": "ApiConnection",
                    "inputs": {
                        "host": {"connection": {"name": LA_CONN}},
                        "method": "post",
                        "body": WORKSPACE_KQL,
                        "path": "/queryData",
                        "queries": {
                            "subscriptions": "@parameters('WorkspaceSubscriptionId')",
                            "resourcegroups": "@parameters('WorkspaceResourceGroup')",
                            "resourcetype": "Log Analytics Workspace",
                            "resourcename": "@parameters('WorkspaceName')",
                            "timerange": "Set in query",
                        },
                    },
                },
                "Compose_Workspace_Rows": {
                    "runAfter": after("Run_KQL_workspace_context", states=("Succeeded", "Failed", "TimedOut")),
                    "type": "Compose",
                    "inputs": (
                        "@if(equals(actions('Run_KQL_workspace_context')?['status'], 'Succeeded'), "
                        "coalesce(body('Run_KQL_workspace_context')?['value'], json('[]')), json('[]'))"
                    ),
                },
                "Filter_High_Workspace_Findings": {
                    "runAfter": after("Compose_Workspace_Rows"), "type": "Query",
                    "inputs": {
                        "from": "@outputs('Compose_Workspace_Rows')",
                        "where": (
                            "@or(equals(item()?['Source'], 'Sentinel TI - high'), "
                            "equals(item()?['Source'], 'Sentinel high alert'), "
                            "equals(item()?['Source'], 'Client user context - critical'))"
                        ),
                    },
                },
                "Select_Workspace_Rows": {
                    "runAfter": after("Filter_High_Workspace_Findings"), "type": "Select",
                    "inputs": {
                        "from": "@outputs('Compose_Workspace_Rows')",
                        "select": (
                            f'<tr><td style="{TD}"><b>@{{item()?[\'Source\']}}</b></td>'
                            f'<td style="{TD}">@{{replace(replace(replace(replace(string(item()?[\'Detail\']), \'&\', \'&amp;\'), \'<\', \'&lt;\'), \'>\', \'&gt;\'), decodeUriComponent(\'%22\'), \'&quot;\')}}</td>'
                            f'<td style="{TD}">@{{item()?[\'Last\']}}</td></tr>'
                        ),
                    },
                },
                "Compose_Verdict": {
                    "runAfter": after("Select_Workspace_Rows"), "type": "Compose", "inputs": VERDICT,
                },
                "Compose_VerdictStyle": {
                    "runAfter": after("Compose_Verdict"), "type": "Compose", "inputs": VERDICT_STYLE,
                },
                "Compose_VerdictReason": {
                    "runAfter": after("Compose_VerdictStyle"), "type": "Compose", "inputs": VERDICT_REASON,
                },
                # Post one comment per entity, right here inside the loop, instead of
                # accumulating every entity's block into one shared HtmlBody and posting
                # it once after the loop -- see build_template.py's IP playbook for the
                # full rationale (Sentinel's /Incidents/Comment rejects any single
                # comment over 30,000 characters, and a shared comment made that trivial
                # to hit and failed the ENTIRE comment when it did).
                "Compose_Entity_Comment": {
                    "runAfter": after("Compose_VerdictReason"), "type": "Compose",
                    "inputs": HEADER + ACCOUNT_BLOCK,
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


template = {
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "metadata": {
        "title": "Enrich Account (user) entities and post a Sentinel incident comment",
        "description": "For each Account entity on a Microsoft Sentinel incident, queries Microsoft Graph for the user's profile (name, job title, office/city/state/country, manager, AAD directory roles), registered devices, MFA/SSPR registration posture, Entra ID Protection identity risk (risk level/state, risk event count, recent risk detections), and mailbox out-of-office status, cross-references Sentinel workspace sign-in logs for suspicious/risky sign-in activity (including failed-MFA and MFA-fraud-reported counts), searches Sentinel workspace TI and client context, calculates a triage verdict (including a combined out-of-office-plus-active-sign-in heuristic and MFA fraud as an automatic HIGH), and posts one formatted incident comment per account. Deliberately does not perform IP-address reputation/network-prevalence lookups — that's covered by the separate IP playbook.",
        "prerequisites": "A Microsoft Sentinel-enabled Log Analytics workspace ingesting SigninLogs/AADNonInteractiveUserSignInLogs, and one existing user-assigned managed identity. Microsoft Graph application permissions required: User.Read.All, Directory.Read.All, Device.Read.All, Reports.Read.All, IdentityRiskyUser.Read.All, MailboxSettings.Read.",
        "postDeployment": [
            "Grant the user-assigned managed identity Microsoft Sentinel Responder on the resource group holding the workspace.",
            "Grant the same identity Log Analytics Reader on the workspace.",
            "Grant the managed identity the six Microsoft Graph application permissions using app-role assignments, then allow time for token propagation.",
            "Authorise the Microsoft Sentinel and Azure Monitor Logs API connections.",
            "Attach the playbook to a Sentinel incident automation rule, or run it on demand from an incident.",
        ],
        "lastUpdateTime": "2026-09-01",
        "entities": ["Account"],
        "tags": ["Enrichment", "Account", "Entra ID", "Identity Protection", "MFA"],
        "support": {"tier": "community"},
    },
    "parameters": {
        "PlaybookName": {
            "type": "string", "defaultValue": "Enrich-Account-IncidentComment",
            "metadata": {"description": "Name of the Logic App playbook."},
        },
        "UserAssignedManagedIdentityResourceId": {
            "type": "string", "minLength": 1,
            "metadata": {"description": "Required. Full resource ID of the existing client-owned user-assigned managed identity used by the Logic App and all managed-identity connections."},
        },
        "WorkspaceName": {
            "type": "string", "metadata": {"description": "Log Analytics / Sentinel workspace name."},
        },
        "WorkspaceResourceGroup": {
            "type": "string", "defaultValue": "[resourceGroup().name]",
            "metadata": {"description": "Resource group of the Sentinel workspace."},
        },
        "WorkspaceSubscriptionId": {
            "type": "string", "defaultValue": "[subscription().subscriptionId]",
            "metadata": {"description": "Subscription of the Sentinel workspace."},
        },
        "LookbackDays": {
            "type": "int", "defaultValue": 14, "minValue": 1, "maxValue": 90,
            "metadata": {"description": "How far back to query Sentinel workspace sign-in and TI tables."},
        },
        "EnableUserProfile": {
            "type": "bool", "defaultValue": True,
            "metadata": {"description": "Query the user's Entra ID profile (name, job title, office/city/state/country, manager, AAD directory roles). Requires User.Read.All and Directory.Read.All."},
        },
        "EnableRegisteredDevices": {
            "type": "bool", "defaultValue": True,
            "metadata": {"description": "Query the user's registered devices. Requires Device.Read.All."},
        },
        "EnableMfaMethods": {
            "type": "bool", "defaultValue": True,
            "metadata": {"description": "Query MFA/SSPR/passwordless registration posture. Requires Reports.Read.All."},
        },
        "EnableIdentityProtection": {
            "type": "bool", "defaultValue": True,
            "metadata": {"description": "Query Entra ID Protection risky-user state and recent risk detections. Requires IdentityRiskyUser.Read.All."},
        },
        "EnableMailboxSettings": {
            "type": "bool", "defaultValue": True,
            "metadata": {"description": "Query the user's automatic-replies (out-of-office) status. Requires MailboxSettings.Read."},
        },
        "EnableSigninHistory": {
            "type": "bool", "defaultValue": True,
            "metadata": {"description": "Summarize sign-in activity from the Sentinel workspace. Requires only Log Analytics Reader, no Graph permission."},
        },
        "UserContextWatchlistAlias": {
            "type": "string", "defaultValue": "UserContext",
            "metadata": {"description": "Optional client user watchlist alias. Set blank to disable."},
        },
    },
    "variables": {
        "SentinelConnectionName": "[concat('MicrosoftSentinel-', parameters('PlaybookName'))]",
        "MonitorLogsConnectionName": "[concat('AzureMonitorLogs-', parameters('PlaybookName'))]",
    },
    "resources": [
        {
            "type": "Microsoft.Web/connections", "apiVersion": "2016-06-01",
            "name": "[variables('SentinelConnectionName')]", "location": "[resourceGroup().location]", "kind": "V1",
            "properties": {
                "displayName": "[variables('SentinelConnectionName')]",
                "customParameterValues": {},
                "parameterValueType": "Alternative",
                "api": {"id": "[concat('/subscriptions/', subscription().subscriptionId, '/providers/Microsoft.Web/locations/', resourceGroup().location, '/managedApis/azuresentinel')]"},
            },
        },
        {
            "type": "Microsoft.Web/connections", "apiVersion": "2016-06-01",
            "name": "[variables('MonitorLogsConnectionName')]", "location": "[resourceGroup().location]", "kind": "V1",
            "properties": {
                "displayName": "[variables('MonitorLogsConnectionName')]",
                "customParameterValues": {},
                "parameterValueSet": {"name": "managedIdentityAuth", "values": {}},
                "api": {"id": "[concat('/subscriptions/', subscription().subscriptionId, '/providers/Microsoft.Web/locations/', resourceGroup().location, '/managedApis/azuremonitorlogs')]"},
            },
        },
        {
            "type": "Microsoft.Logic/workflows", "apiVersion": "2017-07-01",
            "name": "[parameters('PlaybookName')]", "location": "[resourceGroup().location]",
            "identity": {
                "type": "UserAssigned",
                "userAssignedIdentities": {"[parameters('UserAssignedManagedIdentityResourceId')]": {}},
            },
            "tags": {
                "hidden-SentinelTemplateName": "Enrich-Account-IncidentComment",
                "hidden-SentinelTemplateVersion": "1.0",
            },
            "dependsOn": [
                "[resourceId('Microsoft.Web/connections', variables('SentinelConnectionName'))]",
                "[resourceId('Microsoft.Web/connections', variables('MonitorLogsConnectionName'))]",
            ],
            "properties": {
                "state": "Enabled",
                "definition": definition,
                "parameters": {
                    "$connections": {
                        "value": {
                            "azuresentinel": {
                                "connectionId": "[resourceId('Microsoft.Web/connections', variables('SentinelConnectionName'))]",
                                "connectionName": "[variables('SentinelConnectionName')]",
                                "id": "[concat('/subscriptions/', subscription().subscriptionId, '/providers/Microsoft.Web/locations/', resourceGroup().location, '/managedApis/azuresentinel')]",
                                "connectionProperties": {"authentication": CONNECTOR_MANAGED_IDENTITY_AUTH},
                            },
                            "azuremonitorlogs": {
                                "connectionId": "[resourceId('Microsoft.Web/connections', variables('MonitorLogsConnectionName'))]",
                                "connectionName": "[variables('MonitorLogsConnectionName')]",
                                "id": "[concat('/subscriptions/', subscription().subscriptionId, '/providers/Microsoft.Web/locations/', resourceGroup().location, '/managedApis/azuremonitorlogs')]",
                                "connectionProperties": {"authentication": CONNECTOR_MANAGED_IDENTITY_AUTH},
                            },
                        }
                    },
                    "LookbackDays": {"value": "[parameters('LookbackDays')]"},
                    "EnableUserProfile": {"value": "[parameters('EnableUserProfile')]"},
                    "EnableRegisteredDevices": {"value": "[parameters('EnableRegisteredDevices')]"},
                    "EnableMfaMethods": {"value": "[parameters('EnableMfaMethods')]"},
                    "EnableIdentityProtection": {"value": "[parameters('EnableIdentityProtection')]"},
                    "EnableMailboxSettings": {"value": "[parameters('EnableMailboxSettings')]"},
                    "EnableSigninHistory": {"value": "[parameters('EnableSigninHistory')]"},
                    "UserContextWatchlistAlias": {"value": "[parameters('UserContextWatchlistAlias')]"},
                    "WorkspaceSubscriptionId": {"value": "[parameters('WorkspaceSubscriptionId')]"},
                    "WorkspaceResourceGroup": {"value": "[parameters('WorkspaceResourceGroup')]"},
                    "WorkspaceName": {"value": "[parameters('WorkspaceName')]"},
                },
            },
        },
    ],
    "outputs": {
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
    },
}


output = pathlib.Path(__file__).parent / "azuredeploy-account.json"
output.write_text(json.dumps(template, indent=2), encoding="utf-8")
print(f"wrote {output} ({output.stat().st_size} bytes)")

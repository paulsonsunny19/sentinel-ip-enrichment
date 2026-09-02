#!/usr/bin/env python3
"""Generate azuredeploy-filehash.json for the Sentinel file-hash-enrichment playbook."""

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


KQL_HASH = "@{replace(toLower(outputs('Compose_Clean_Hash')), decodeUriComponent('%27'), '')}"


# Defender's FileProfile() enrichment function accepts a SHA1, SHA256, or MD5 hash and returns
# Microsoft's own file reputation/prevalence/signing data — the same native intelligence backing
# MDTI, but reached the way Defender XDR actually exposes file-hash intelligence today, since
# MDTI's public Graph schema (security/threatIntelligence/hosts/...) is host-based and has no
# hash-reputation endpoint. This is intentional; see README-FILEHASH.md.
DEFENDER_KQL = f"""let hash = '{KQL_HASH}';
let look = @{{parameters('DefenderLookbackDays')}}d;
let FileProfileRow = FileProfile(hash, 1);
let FileEventSummary = union isfuzzy=true
(DeviceFileEvents
 | where Timestamp > ago(look)
 | extend SafeSha256=tolower(tostring(column_ifexists('SHA256', ''))),
          SafeSha1=tolower(tostring(column_ifexists('SHA1', ''))),
          SafeMd5=tolower(tostring(column_ifexists('MD5', ''))),
          SafeDevice=tostring(column_ifexists('DeviceName', '')),
          SafeFileName=tostring(column_ifexists('FileName', '')),
          SafeFolder=tostring(column_ifexists('FolderPath', '')),
          SafeAction=tostring(column_ifexists('ActionType', ''))
 | where SafeSha256 == hash or SafeSha1 == hash or SafeMd5 == hash
 | summarize FileEvents=count(), FileDevices=make_set(SafeDevice, 20), FileNames=make_set(SafeFileName, 15),
             FolderPaths=make_set(SafeFolder, 10), FileActions=make_set(SafeAction, 10), LastFileEvent=max(Timestamp)),
(datatable(FileEvents:long, FileDevices:dynamic, FileNames:dynamic, FolderPaths:dynamic,
           FileActions:dynamic, LastFileEvent:datetime)[]);
let ProcessSummary = union isfuzzy=true
(DeviceProcessEvents
 | where Timestamp > ago(look)
 | extend SafeSha256=tolower(tostring(column_ifexists('SHA256', ''))),
          SafeSha1=tolower(tostring(column_ifexists('SHA1', ''))),
          SafeMd5=tolower(tostring(column_ifexists('MD5', ''))),
          SafeInitSha256=tolower(tostring(column_ifexists('InitiatingProcessSHA256', ''))),
          SafeInitSha1=tolower(tostring(column_ifexists('InitiatingProcessSHA1', ''))),
          SafeInitMd5=tolower(tostring(column_ifexists('InitiatingProcessMD5', ''))),
          SafeDevice=tostring(column_ifexists('DeviceName', '')),
          SafeCommandLine=tostring(column_ifexists('ProcessCommandLine', '')),
          SafeAccount=tostring(column_ifexists('AccountName', ''))
 | where SafeSha256 == hash or SafeSha1 == hash or SafeMd5 == hash
     or SafeInitSha256 == hash or SafeInitSha1 == hash or SafeInitMd5 == hash
 | summarize ProcessEvents=count(), ProcessDevices=make_set(SafeDevice, 20),
             CommandLines=make_set(SafeCommandLine, 15), ProcessUsers=make_set(SafeAccount, 20),
             LastProcessEvent=max(Timestamp)),
(datatable(ProcessEvents:long, ProcessDevices:dynamic, CommandLines:dynamic, ProcessUsers:dynamic,
           LastProcessEvent:datetime)[]);
let DetectionSummary = union isfuzzy=true
(DeviceEvents
 | where Timestamp > ago(look)
 | where ActionType has_any ('AntivirusDetection', 'AntivirusReport', 'AntivirusScanCompleted',
                              'AsrRuleBlocked', 'ExploitGuardBlocked')
 | extend SafeSha256=tolower(tostring(column_ifexists('SHA256', ''))),
          SafeSha1=tolower(tostring(column_ifexists('SHA1', ''))),
          SafeMd5=tolower(tostring(column_ifexists('MD5', ''))),
          SafeDevice=tostring(column_ifexists('DeviceName', '')),
          SafeAction=tostring(column_ifexists('ActionType', ''))
 | extend SafeThreat=tostring(coalesce(column_ifexists('ThreatName', ''),
                               tostring(parse_json(tostring(column_ifexists('AdditionalFields', '{{}}'))).ThreatName)))
 | where SafeSha256 == hash or SafeSha1 == hash or SafeMd5 == hash
 | summarize Detections=count(), DetectionDevices=make_set(SafeDevice, 20),
             ThreatNames=make_set(SafeThreat, 15), DetectionActions=make_set(SafeAction, 10),
             LastDetection=max(Timestamp)),
(datatable(Detections:long, DetectionDevices:dynamic, ThreatNames:dynamic, DetectionActions:dynamic,
           LastDetection:datetime)[]);
let EmailSummary = union isfuzzy=true
(EmailAttachmentInfo
 | where Timestamp > ago(look)
 | extend SafeSha256=tolower(tostring(column_ifexists('SHA256', ''))),
          SafeFileName=tostring(column_ifexists('FileName', '')),
          SafeFileType=tostring(column_ifexists('FileType', '')),
          SafeMessage=tostring(column_ifexists('NetworkMessageId', ''))
 | where SafeSha256 == hash
 | summarize EmailAttachments=count(), EmailMessages=dcount(SafeMessage),
             EmailFileNames=make_set(SafeFileName, 15), EmailFileTypes=make_set(SafeFileType, 10),
             LastEmailAttachment=max(Timestamp)),
(datatable(EmailAttachments:long, EmailMessages:long, EmailFileNames:dynamic, EmailFileTypes:dynamic,
           LastEmailAttachment:datetime)[]);
let AlertSummary = union isfuzzy=true
(AlertEvidence
 | where Timestamp > ago(look)
 | extend SafeSha256=tolower(tostring(column_ifexists('SHA256', ''))),
          SafeSha1=tolower(tostring(column_ifexists('SHA1', ''))),
          SafeMd5=tolower(tostring(column_ifexists('MD5', ''))),
          SafeTitle=tostring(column_ifexists('Title', '')),
          SafeSeverity=tostring(column_ifexists('Severity', '')),
          SafeService=tostring(column_ifexists('ServiceSource', '')),
          SafeRole=tostring(column_ifexists('EvidenceRole', '')),
          SafeAlertId=tostring(column_ifexists('AlertId', ''))
 | where SafeSha256 == hash or SafeSha1 == hash or SafeMd5 == hash
 | summarize Alerts=dcount(SafeAlertId), HighAlerts=dcountif(SafeAlertId, tolower(SafeSeverity) == 'high'),
             AlertTitles=make_set(SafeTitle, 15), AlertSeverities=make_set(SafeSeverity, 8),
             AlertServices=make_set(SafeService, 8), EvidenceRoles=make_set(SafeRole, 8),
             LastAlert=max(Timestamp)),
(datatable(Alerts:long, HighAlerts:long, AlertTitles:dynamic, AlertSeverities:dynamic,
           AlertServices:dynamic, EvidenceRoles:dynamic, LastAlert:datetime)[]);
datatable(Seed:int)[1]
| extend GlobalPrevalence=tolong(coalesce(toscalar(FileProfileRow | project P=column_ifexists('GlobalPrevalence', 0)), 0)),
         FileFirstSeen=toscalar(FileProfileRow | project P=column_ifexists('GlobalFirstSeen', datetime(null))),
         FileLastSeen=toscalar(FileProfileRow | project P=column_ifexists('GlobalLastSeen', datetime(null))),
         FileType=tostring(coalesce(toscalar(FileProfileRow | project P=column_ifexists('FileType', '')), '')),
         FileSize=tolong(coalesce(toscalar(FileProfileRow | project P=column_ifexists('Size', 0)), 0)),
         IsSigned=tostring(coalesce(toscalar(FileProfileRow | project P=column_ifexists('IsSigned', false)), false)),
         IsCertificateValid=tostring(coalesce(toscalar(FileProfileRow | project P=column_ifexists('IsCertificateValid', false)), false)),
         IsRootSignerMicrosoft=tostring(coalesce(toscalar(FileProfileRow | project P=column_ifexists('IsRootSignerMicrosoft', false)), false)),
         Signer=tostring(coalesce(toscalar(FileProfileRow | project P=column_ifexists('Signer', '')), '')),
         Issuer=tostring(coalesce(toscalar(FileProfileRow | project P=column_ifexists('Issuer', '')), '')),
         CompanyName=tostring(coalesce(toscalar(FileProfileRow | project P=column_ifexists('FilePublisher', '')), '')),
         FileHasRow=tolong(coalesce(toscalar(FileProfileRow | summarize C=count()), 0)),
         FileEvents=tolong(coalesce(toscalar(FileEventSummary | project FileEvents), 0)),
         FileDevices=tostring(coalesce(toscalar(FileEventSummary | project FileDevices), dynamic([]))),
         FileNames=tostring(coalesce(toscalar(FileEventSummary | project FileNames), dynamic([]))),
         FolderPaths=tostring(coalesce(toscalar(FileEventSummary | project FolderPaths), dynamic([]))),
         LastFileEvent=toscalar(FileEventSummary | project LastFileEvent),
         ProcessEvents=tolong(coalesce(toscalar(ProcessSummary | project ProcessEvents), 0)),
         ProcessDevices=tostring(coalesce(toscalar(ProcessSummary | project ProcessDevices), dynamic([]))),
         CommandLines=tostring(coalesce(toscalar(ProcessSummary | project CommandLines), dynamic([]))),
         ProcessUsers=tostring(coalesce(toscalar(ProcessSummary | project ProcessUsers), dynamic([]))),
         LastProcessEvent=toscalar(ProcessSummary | project LastProcessEvent),
         Detections=tolong(coalesce(toscalar(DetectionSummary | project Detections), 0)),
         DetectionDevices=tostring(coalesce(toscalar(DetectionSummary | project DetectionDevices), dynamic([]))),
         ThreatNames=tostring(coalesce(toscalar(DetectionSummary | project ThreatNames), dynamic([]))),
         LastDetection=toscalar(DetectionSummary | project LastDetection),
         EmailAttachments=tolong(coalesce(toscalar(EmailSummary | project EmailAttachments), 0)),
         EmailMessages=tolong(coalesce(toscalar(EmailSummary | project EmailMessages), 0)),
         EmailFileNames=tostring(coalesce(toscalar(EmailSummary | project EmailFileNames), dynamic([]))),
         LastEmailAttachment=toscalar(EmailSummary | project LastEmailAttachment),
         Alerts=tolong(coalesce(toscalar(AlertSummary | project Alerts), 0)),
         HighAlerts=tolong(coalesce(toscalar(AlertSummary | project HighAlerts), 0)),
         AlertTitles=tostring(coalesce(toscalar(AlertSummary | project AlertTitles), dynamic([]))),
         AlertSeverities=tostring(coalesce(toscalar(AlertSummary | project AlertSeverities), dynamic([]))),
         LastAlert=toscalar(AlertSummary | project LastAlert)
| extend TotalObservations=FileEvents + ProcessEvents + Detections + EmailAttachments + Alerts
| project-away Seed"""


WORKSPACE_KQL = f"""let hash = '{KQL_HASH}';
let look = @{{parameters('LookbackDays')}}d;
let watchAlias = '@{{replace(parameters('FileHashContextWatchlistAlias'), decodeUriComponent('%27'), '')}}';
let TI = union isfuzzy=true
(ThreatIntelIndicators
 | extend SafeValue=tolower(tostring(column_ifexists('ObservableValue', ''))),
          SafeConfidence=toint(column_ifexists('Confidence', 0)),
          SafeName=tostring(column_ifexists('Name', '')),
          SafeTags=tostring(column_ifexists('Tags', dynamic([]))),
          SafeModified=todatetime(column_ifexists('Modified', datetime(null))),
          SafeDeleted=tobool(column_ifexists('IsDeleted', false))
 | where SafeDeleted == false and SafeValue == hash
 | summarize arg_max(TimeGenerated, *) by Id
 | project Source=iff(SafeConfidence >= 70, 'Sentinel TI - high', 'Sentinel TI'),
           Detail=strcat('confidence ', SafeConfidence, '/100 | ', SafeName, ' | tags: ', SafeTags),
           Last=coalesce(SafeModified, TimeGenerated)),
(ThreatIntelligenceIndicator
 | extend SafeHash=tolower(tostring(column_ifexists('FileHashValue', ''))),
          SafeHashType=tostring(column_ifexists('FileHashType', '')),
          SafeConfidence=toint(column_ifexists('ConfidenceScore', 0)),
          SafeThreat=tostring(column_ifexists('ThreatType', '')),
          SafeDescription=tostring(column_ifexists('Description', '')),
          SafeActive=tobool(column_ifexists('Active', true))
 | where SafeActive == true and SafeHash == hash
 | summarize arg_max(TimeGenerated, *) by IndicatorId
 | project Source=iff(SafeConfidence >= 70, 'Sentinel TI - high', 'Sentinel TI - legacy'),
           Detail=strcat('confidence ', SafeConfidence, '/100 | ', SafeThreat, ' (', SafeHashType, ') | ', SafeDescription),
           Last=TimeGenerated),
(datatable(Source:string, Detail:string, Last:datetime)[]);
let ClientContext = union isfuzzy=true
(Watchlist
 | where isnotempty(watchAlias) and WatchlistAlias == watchAlias
 | where tolower(SearchKey) == hash
 | summarize arg_max(TimeGenerated, *) by SearchKey
 | extend W=todynamic(WatchlistItem)
 | extend Classification=tolower(coalesce(tostring(W.Classification), tostring(W.Risk), 'unclassified'))
 | project Source=iff(Classification in ('critical', 'high', 'malicious', 'knownbad', 'malware'),
                      'Client file hash context - critical', 'Client file hash context'),
           Detail=strcat('classification: ', Classification, ' | owner: ', coalesce(tostring(W.Owner), 'n/a'),
                         ' | campaign: ', coalesce(tostring(W.Campaign), 'n/a'),
                         ' | notes: ', coalesce(tostring(W.Description), tostring(W.Notes), 'none')),
           Last=coalesce(todatetime(W.LastUpdated), TimeGenerated)),
(datatable(Source:string, Detail:string, Last:datetime)[]);
let Alerts = union isfuzzy=true
(SecurityAlert
 | where TimeGenerated > ago(look)
 | extend EntityText=tolower(tostring(Entities))
 | where EntityText contains hash
 | summarize AlertCount=count(), High=countif(tolower(AlertSeverity) == 'high'),
             Names=make_set(AlertName, 15), Severities=make_set(AlertSeverity, 8),
             Products=make_set(ProductName, 8), Last=max(TimeGenerated)
 | project Source=iff(High > 0, 'Sentinel high alert', 'Sentinel alerts'),
           Detail=strcat(AlertCount, ' alert(s), ', High, ' high | ', tostring(Names),
                         ' | severity: ', tostring(Severities), ' | products: ', tostring(Products)), Last),
(datatable(Source:string, Detail:string, Last:datetime)[]);
let Observations = union isfuzzy=true
(DeviceFileEvents
 | where TimeGenerated > ago(look)
 | extend SafeSha256=tolower(tostring(column_ifexists('SHA256', ''))),
          SafeSha1=tolower(tostring(column_ifexists('SHA1', ''))),
          SafeMd5=tolower(tostring(column_ifexists('MD5', ''))),
          SafeDevice=tostring(column_ifexists('DeviceName', '')),
          SafeFileName=tostring(column_ifexists('FileName', ''))
 | where SafeSha256 == hash or SafeSha1 == hash or SafeMd5 == hash
 | summarize Count=count(), Devices=make_set(SafeDevice, 20), FileNames=make_set(SafeFileName, 15), Last=max(TimeGenerated)
 | project Source='Ingested device file events',
           Detail=strcat(Count, ' event(s) | devices: ', tostring(Devices), ' | names: ', tostring(FileNames)), Last),
(EmailAttachmentInfo
 | where TimeGenerated > ago(look)
 | extend SafeSha256=tolower(tostring(column_ifexists('SHA256', ''))),
          SafeFileName=tostring(column_ifexists('FileName', ''))
 | where SafeSha256 == hash
 | summarize Count=count(), FileNames=make_set(SafeFileName, 15), Last=max(TimeGenerated)
 | project Source='Ingested email attachments', Detail=strcat(Count, ' attachment(s) | names: ', tostring(FileNames)), Last),
(datatable(Source:string, Detail:string, Last:datetime)[]);
union TI, ClientContext, Alerts, Observations
| where isnotempty(Source)
| order by Last desc
| take 60"""


TH = "text-align:left;padding:4px 10px;background:#f3f2f1;border:1px solid #e1dfdd;font-weight:600;white-space:nowrap"
TD = "padding:4px 10px;border:1px solid #e1dfdd;vertical-align:top;word-break:break-word;overflow-wrap:anywhere;"
TBL = "border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:12px;width:100%"
H4 = "margin:12px 0 4px 0;font-family:Segoe UI,Arial,sans-serif;font-size:13px"
CHIP = "display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;color:#ffffff;margin-left:6px;background:"


HEADER = (
    '<div style="font-family:Segoe UI,Arial,sans-serif;font-size:12px;color:#605e5c">'
    "Automated file hash enrichment &mdash; playbook <b>@{workflow()?['name']}</b> "
    "&middot; run @{formatDateTime(utcNow(), 'yyyy-MM-dd HH:mm')} UTC</div>"
)


DEFENDER_BLOCK = f"""<div style="{H4}"><b>Microsoft Defender native file intelligence</b> <span style="font-weight:400;color:#605e5c">(Defender XDR Advanced Hunting &mdash; FileProfile())</span></div>
<table style="{TBL}">
<tr><th style="{TH}">Status</th><td style="{TD}" colspan="3">@{{variables('DefenderStatus')}}</td></tr>
<tr><th style="{TH}">Signing</th><td style="{TD}">signed: <b>@{{string(coalesce(variables('DefenderJson')?['IsSigned'], 'false'))}}</b> &nbsp;|&nbsp; certificate valid: <b>@{{string(coalesce(variables('DefenderJson')?['IsCertificateValid'], 'false'))}}</b> &nbsp;|&nbsp; Microsoft root: <b>@{{string(coalesce(variables('DefenderJson')?['IsRootSignerMicrosoft'], 'false'))}}</b></td><th style="{TH}">Signer / issuer</th><td style="{TD}">@{{string(coalesce(variables('DefenderJson')?['Signer'], 'n/a'))}} / @{{string(coalesce(variables('DefenderJson')?['Issuer'], 'n/a'))}}</td></tr>
<tr><th style="{TH}">File</th><td style="{TD}" colspan="3">type: @{{string(coalesce(variables('DefenderJson')?['FileType'], 'n/a'))}} &nbsp;|&nbsp; size: @{{string(coalesce(variables('DefenderJson')?['FileSize'], 'n/a'))}} bytes &nbsp;|&nbsp; publisher: @{{string(coalesce(variables('DefenderJson')?['CompanyName'], 'n/a'))}}</td></tr>
<tr><th style="{TH}">Global prevalence</th><td style="{TD}"><b>@{{string(coalesce(variables('DefenderJson')?['GlobalPrevalence'], 0))}}</b> device(s) org-wide (Microsoft telemetry)</td><th style="{TH}">First / last seen</th><td style="{TD}">@{{string(coalesce(variables('DefenderJson')?['FileFirstSeen'], 'n/a'))}} &nbsp;|&nbsp; @{{string(coalesce(variables('DefenderJson')?['FileLastSeen'], 'n/a'))}}</td></tr>
<tr><th style="{TH}">File events</th><td style="{TD}">@{{string(coalesce(variables('DefenderJson')?['FileEvents'], 0))}} event(s) &nbsp;|&nbsp; devices: @{{string(coalesce(variables('DefenderJson')?['FileDevices'], '[]'))}}</td><th style="{TH}">File names / paths</th><td style="{TD}">@{{string(coalesce(variables('DefenderJson')?['FileNames'], '[]'))}} &nbsp;|&nbsp; @{{string(coalesce(variables('DefenderJson')?['FolderPaths'], '[]'))}}</td></tr>
<tr><th style="{TH}">Process events</th><td style="{TD}">@{{string(coalesce(variables('DefenderJson')?['ProcessEvents'], 0))}} event(s) &nbsp;|&nbsp; devices: @{{string(coalesce(variables('DefenderJson')?['ProcessDevices'], '[]'))}}</td><th style="{TH}">Users / command lines</th><td style="{TD}">@{{string(coalesce(variables('DefenderJson')?['ProcessUsers'], '[]'))}} &nbsp;|&nbsp; @{{string(coalesce(variables('DefenderJson')?['CommandLines'], '[]'))}}</td></tr>
<tr><th style="{TH}">AV / EDR detections</th><td style="{TD}"><b>@{{string(coalesce(variables('DefenderJson')?['Detections'], 0))}}</b> detection(s)</td><th style="{TH}">Threat names</th><td style="{TD}">@{{string(coalesce(variables('DefenderJson')?['ThreatNames'], '[]'))}}</td></tr>
<tr><th style="{TH}">Email attachments</th><td style="{TD}">@{{string(coalesce(variables('DefenderJson')?['EmailAttachments'], 0))}} attachment(s) / @{{string(coalesce(variables('DefenderJson')?['EmailMessages'], 0))}} message(s)</td><th style="{TH}">Attachment names</th><td style="{TD}">@{{string(coalesce(variables('DefenderJson')?['EmailFileNames'], '[]'))}}</td></tr>
<tr><th style="{TH}">Alerts</th><td style="{TD}"><b>@{{string(coalesce(variables('DefenderJson')?['Alerts'], 0))}}</b> alert(s), <b>@{{string(coalesce(variables('DefenderJson')?['HighAlerts'], 0))}} high</b></td><th style="{TH}">Alert titles</th><td style="{TD}">@{{string(coalesce(variables('DefenderJson')?['AlertTitles'], '[]'))}}</td></tr>
</table>"""


DEFENDER_DISABLED_BLOCK = f"""<div style="{H4}"><b>Microsoft Defender native file intelligence</b></div>
<table style="{TBL}"><tr><td style="{TD}">Disabled by deployment setting.</td></tr></table>"""


VERDICT_STYLE = (
    "@if(equals(outputs('Compose_Verdict'), 'HIGH'), '%s#a4262c', "
    "if(equals(outputs('Compose_Verdict'), 'MEDIUM'), '%s#986f0b', "
    "if(equals(outputs('Compose_Verdict'), 'LOW'), '%s#107c10', '%s#605e5c')))"
    % (CHIP, CHIP, CHIP, CHIP)
)


VERDICT = (
    "@if(or("
    "greater(int(coalesce(variables('DefenderJson')?['Detections'], 0)), 0), "
    "greater(int(coalesce(variables('DefenderJson')?['HighAlerts'], 0)), 0), "
    "greater(length(body('Filter_High_Workspace_Findings')), 0)), 'HIGH', "
    "if(or("
    "greater(int(coalesce(variables('DefenderJson')?['TotalObservations'], 0)), 0), "
    "greater(int(coalesce(variables('DefenderJson')?['Alerts'], 0)), 0), "
    "greater(length(outputs('Compose_Workspace_Rows')), 0), "
    "and(equals(toLower(string(coalesce(variables('DefenderJson')?['IsSigned'], 'false'))), 'false'), "
    "greater(int(coalesce(variables('DefenderJson')?['FileHasRow'], 0)), 0), "
    "less(int(coalesce(variables('DefenderJson')?['GlobalPrevalence'], 0)), 10))"
    "), 'MEDIUM', "
    "if(and(equals(int(coalesce(variables('DefenderJson')?['FileHasRow'], 0)), 1), "
    "or(equals(toLower(string(coalesce(variables('DefenderJson')?['IsRootSignerMicrosoft'], 'false'))), 'true'), "
    "greaterOrEquals(int(coalesce(variables('DefenderJson')?['GlobalPrevalence'], 0)), 1000))), "
    "'LOW', 'UNKNOWN')))"
)


VERDICT_REASON = (
    "@concat('Defender: ', variables('DefenderStatus'), "
    "' &middot; observations: ', string(coalesce(variables('DefenderJson')?['TotalObservations'], 0)), "
    "' &middot; workspace rows: ', string(length(outputs('Compose_Workspace_Rows'))))"
)


HASH_BLOCK = f"""<hr style="border:0;border-top:1px solid #e1dfdd;margin:16px 0">
<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;font-weight:600;margin-bottom:6px">
File hash enrichment &mdash; <code>@{{outputs('Compose_Display_Hash')}}</code>
<span style="@{{outputs('Compose_VerdictStyle')}}">@{{outputs('Compose_Verdict')}}</span>
</div>
<div style="font-family:Segoe UI,Arial,sans-serif;font-size:11px;color:#605e5c;margin-bottom:10px">@{{outputs('Compose_VerdictReason')}}</div>
<table style="{TBL}">
<tr><th style="{TH}">Algorithm</th><td style="{TD}"><b>@{{outputs('Compose_Hash_Algorithm')}}</b></td></tr>
<tr><th style="{TH}">Hash</th><td style="{TD}">@{{outputs('Compose_Display_Hash')}}</td></tr>
</table>
@{{variables('DefenderHtml')}}
<div style="{H4}"><b>Sentinel workspace insights &mdash; last @{{parameters('LookbackDays')}} days</b></div>
<table style="{TBL}">
<tr><th style="{TH}">Source</th><th style="{TH}">Detail</th><th style="{TH}">Last seen (UTC)</th></tr>
@{{if(empty(outputs('Compose_Workspace_Rows')), concat('<tr><td style="{TD}" colspan="3">No matching workspace records, or the queried tables are not collected.</td></tr>'), join(body('Select_Workspace_Rows'), ''))}}
</table>"""


SENTINEL_CONN = "@parameters('$connections')['azuresentinel']['connectionId']"
LA_CONN = "@parameters('$connections')['azuremonitorlogs']['connectionId']"


def after(*names, states=("Succeeded",)):
    return {name: list(states) for name in names}


definition = {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "$connections": {"defaultValue": {}, "type": "Object"},
        "LookbackDays": {"type": "Int", "defaultValue": 14},
        "EnableDefenderAdvancedHunting": {"type": "Bool", "defaultValue": True},
        "DefenderLookbackDays": {"type": "Int", "defaultValue": 14},
        "FileHashContextWatchlistAlias": {"type": "String", "defaultValue": "FileHashContext"},
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
        "Init_DefenderJson": {
            "runAfter": after("Init_HtmlBody"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "DefenderJson", "type": "object", "value": {}}]},
        },
        "Init_DefenderStatus": {
            "runAfter": after("Init_DefenderJson"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "DefenderStatus", "type": "string", "value": "disabled by deployment setting"}]},
        },
        "Init_DefenderHtml": {
            "runAfter": after("Init_DefenderStatus"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "DefenderHtml", "type": "string", "value": ""}]},
        },
        "Entities_-_Get_File_Hashes": {
            "runAfter": after("Init_DefenderHtml"), "type": "ApiConnection",
            "inputs": {
                "host": {"connection": {"name": SENTINEL_CONN}},
                "method": "post",
                "body": "@triggerBody()?['object']?['properties']?['relatedEntities']",
                "path": "/entities/filehash",
            },
        },
        "For_each_FileHash_entity": {
            "foreach": "@coalesce(body('Entities_-_Get_File_Hashes')?['FileHashes'], json('[]'))",
            "runAfter": after("Entities_-_Get_File_Hashes"),
            "type": "Foreach",
            "runtimeConfiguration": {"concurrency": {"repetitions": 1}},
            "actions": {
                "Reset_DefenderJson": {
                    "runAfter": {}, "type": "SetVariable",
                    "inputs": {"name": "DefenderJson", "value": {}},
                },
                "Reset_DefenderStatus": {
                    "runAfter": after("Reset_DefenderJson"), "type": "SetVariable",
                    "inputs": {"name": "DefenderStatus", "value": "disabled by deployment setting"},
                },
                "Reset_DefenderHtml": {
                    "runAfter": after("Reset_DefenderStatus"), "type": "SetVariable",
                    "inputs": {"name": "DefenderHtml", "value": ""},
                },
                "Compose_Clean_Hash": {
                    "runAfter": after("Reset_DefenderHtml"), "type": "Compose",
                    "inputs": (
                        "@trim(string(coalesce(items('For_each_FileHash_entity')?['HashValue'], "
                        "items('For_each_FileHash_entity')?['hashValue'], "
                        "items('For_each_FileHash_entity')?['Value'], "
                        "items('For_each_FileHash_entity')?['value'], '')))"
                    ),
                },
                "Compose_Display_Hash": {
                    "runAfter": after("Compose_Clean_Hash"), "type": "Compose",
                    "inputs": (
                        "@replace(replace(replace(replace(outputs('Compose_Clean_Hash'), "
                        "'&', '&amp;'), '<', '&lt;'), '>', '&gt;'), decodeUriComponent('%22'), '&quot;')"
                    ),
                },
                "Compose_Hash_Algorithm": {
                    "runAfter": after("Compose_Display_Hash"), "type": "Compose",
                    "inputs": (
                        "@coalesce(items('For_each_FileHash_entity')?['Algorithm'], "
                        "items('For_each_FileHash_entity')?['algorithm'], "
                        "if(equals(length(outputs('Compose_Clean_Hash')), 64), 'SHA256', "
                        "if(equals(length(outputs('Compose_Clean_Hash')), 40), 'SHA1', "
                        "if(equals(length(outputs('Compose_Clean_Hash')), 32), 'MD5', 'Unknown'))))"
                    ),
                },
                "Condition_Defender_XDR_enabled": {
                    "runAfter": after("Compose_Hash_Algorithm"), "type": "If",
                    "expression": {"and": [{"equals": ["@parameters('EnableDefenderAdvancedHunting')", True]}]},
                    "actions": {
                        "HTTP_Defender_XDR_FileHash_Hunting": {
                            "runAfter": {}, "type": "Http",
                            "inputs": {
                                "method": "POST",
                                "uri": "https://graph.microsoft.com/v1.0/security/runHuntingQuery",
                                "headers": {"Content-Type": "application/json; charset=utf-8"},
                                "body": {"Query": DEFENDER_KQL, "Timespan": "P30D"},
                                "authentication": MICROSOFT_GRAPH_MANAGED_IDENTITY_AUTH,
                            },
                            "runtimeConfiguration": {"secureData": {"properties": ["inputs"]}},
                        },
                        "Compose_Defender_Rows": {
                            "runAfter": after("HTTP_Defender_XDR_FileHash_Hunting", states=("Succeeded", "Failed", "TimedOut")),
                            "type": "Compose",
                            "inputs": (
                                "@if(equals(outputs('HTTP_Defender_XDR_FileHash_Hunting')?['statusCode'], 200), "
                                "coalesce(body('HTTP_Defender_XDR_FileHash_Hunting')?['results'], json('[]')), json('[]'))"
                            ),
                        },
                        "Set_DefenderJson": {
                            "runAfter": after("Compose_Defender_Rows"), "type": "SetVariable",
                            "inputs": {
                                "name": "DefenderJson",
                                "value": "@if(greater(length(outputs('Compose_Defender_Rows')), 0), first(outputs('Compose_Defender_Rows')), json('{}'))",
                            },
                        },
                        "Set_DefenderStatus": {
                            "runAfter": after("Set_DefenderJson"), "type": "SetVariable",
                            "inputs": {
                                "name": "DefenderStatus",
                                "value": (
                                    "@if(not(equals(outputs('HTTP_Defender_XDR_FileHash_Hunting')?['statusCode'], 200)), "
                                    "concat('unavailable (HTTP ', string(coalesce(outputs('HTTP_Defender_XDR_FileHash_Hunting')?['statusCode'], 'no response')), ')'), "
                                    "if(equals(int(coalesce(variables('DefenderJson')?['FileHasRow'], 0)), 0), "
                                    "'available; no FileProfile record (unseen by Defender telemetry)', "
                                    "if(greater(int(coalesce(variables('DefenderJson')?['TotalObservations'], 0)), 0), 'activity found', 'no activity observed')))"
                                ),
                            },
                        },
                        "Set_DefenderHtml": {
                            "runAfter": after("Set_DefenderStatus"), "type": "SetVariable",
                            "inputs": {"name": "DefenderHtml", "value": DEFENDER_BLOCK},
                        },
                    },
                    "else": {
                        "actions": {
                            "Set_DefenderHtml_disabled": {
                                "runAfter": {}, "type": "SetVariable",
                                "inputs": {"name": "DefenderHtml", "value": DEFENDER_DISABLED_BLOCK},
                            }
                        }
                    },
                },
                "Run_KQL_workspace_context": {
                    "runAfter": after("Condition_Defender_XDR_enabled"), "type": "ApiConnection",
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
                            "equals(item()?['Source'], 'Client file hash context - critical'))"
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
                    "inputs": HEADER + HASH_BLOCK,
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
        "title": "Enrich file hash entities and post a Sentinel incident comment",
        "description": "For each FileHash entity on a Microsoft Sentinel incident, queries Defender XDR Advanced Hunting's native FileProfile() enrichment function for Microsoft's own file reputation, prevalence, and code-signing data, correlates DeviceFileEvents, DeviceProcessEvents, AV/EDR detections, EmailAttachmentInfo attachments and AlertEvidence, searches Sentinel workspace telemetry and client context, calculates a triage verdict, and posts one formatted incident comment.",
        "prerequisites": "A Microsoft Sentinel-enabled Log Analytics workspace and one existing user-assigned managed identity. Microsoft Graph application permission ThreatHunting.Read.All is required for Defender Advanced Hunting.",
        "postDeployment": [
            "Grant the user-assigned managed identity Microsoft Sentinel Responder on the resource group holding the workspace.",
            "Grant the same identity Log Analytics Reader on the workspace.",
            "Grant the managed identity the Microsoft Graph application permission ThreatHunting.Read.All using an app-role assignment, then allow time for token propagation.",
            "Authorise the Microsoft Sentinel and Azure Monitor Logs API connections.",
            "Attach the playbook to a Sentinel incident automation rule, or run it on demand from an incident.",
        ],
        "lastUpdateTime": "2026-09-01",
        "entities": ["FileHash"],
        "tags": ["Enrichment", "FileHash", "Defender XDR", "FileProfile"],
        "support": {"tier": "community"},
    },
    "parameters": {
        "PlaybookName": {
            "type": "string", "defaultValue": "Enrich-FileHash-IncidentComment",
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
            "metadata": {"description": "How far back to query Sentinel workspace tables."},
        },
        "EnableDefenderAdvancedHunting": {
            "type": "bool", "defaultValue": True,
            "metadata": {"description": "Query Defender XDR Advanced Hunting (including the FileProfile() enrichment function) through Microsoft Graph. Requires ThreatHunting.Read.All application permission."},
        },
        "DefenderLookbackDays": {
            "type": "int", "defaultValue": 14, "minValue": 1, "maxValue": 30,
            "metadata": {"description": "Defender Advanced Hunting activity lookback from 1 to 30 days. FileProfile() reputation/prevalence itself is not bounded by this window."},
        },
        "FileHashContextWatchlistAlias": {
            "type": "string", "defaultValue": "FileHashContext",
            "metadata": {"description": "Optional client file-hash watchlist alias. Set blank to disable."},
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
                "hidden-SentinelTemplateName": "Enrich-FileHash-IncidentComment",
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
                    "EnableDefenderAdvancedHunting": {"value": "[parameters('EnableDefenderAdvancedHunting')]"},
                    "DefenderLookbackDays": {"value": "[parameters('DefenderLookbackDays')]"},
                    "FileHashContextWatchlistAlias": {"value": "[parameters('FileHashContextWatchlistAlias')]"},
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


output = pathlib.Path(__file__).parent / "azuredeploy-filehash.json"
output.write_text(json.dumps(template, indent=2), encoding="utf-8")
print(f"wrote {output} ({output.stat().st_size} bytes)")

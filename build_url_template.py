#!/usr/bin/env python3
"""Generate azuredeploy-url.json for the Sentinel URL-enrichment playbook."""

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


KQL_URL = "@{replace(toLower(outputs('Compose_Normalized_URL')), decodeUriComponent('%27'), '')}"
KQL_HOST = "@{replace(toLower(outputs('Compose_URL_Host')), decodeUriComponent('%27'), '')}"


DEFENDER_KQL = f"""let url = '{KQL_URL}';
let host = '{KQL_HOST}';
let look = @{{parameters('DefenderLookbackDays')}}d;
let ClickSummary = union isfuzzy=true
(UrlClickEvents
 | where Timestamp > ago(look)
 | extend SafeUrl=tolower(tostring(column_ifexists('Url', ''))),
          SafeChain=tolower(tostring(column_ifexists('UrlChain', ''))),
          SafeAction=tostring(column_ifexists('ActionType', '')),
          SafeUser=tostring(column_ifexists('AccountUpn', '')),
          SafeWorkload=tostring(column_ifexists('Workload', '')),
          SafeThreat=tostring(column_ifexists('ThreatTypes', '')),
          SafeIP=tostring(column_ifexists('IPAddress', '')),
          SafeClickedThrough=tobool(column_ifexists('IsClickedThrough', false))
 | where SafeUrl == url or SafeUrl contains host or SafeChain contains url or SafeChain contains host
 | summarize UrlClicks=count(), ThreatClicks=countif(isnotempty(SafeThreat)),
             ClickedThrough=countif(SafeClickedThrough == true), ClickUsers=make_set(SafeUser, 20),
             ClickActions=make_set(SafeAction, 10), ClickWorkloads=make_set(SafeWorkload, 10),
             ClickThreatTypes=make_set(SafeThreat, 10), ClickIPs=make_set(SafeIP, 12), LastClick=max(Timestamp)),
(datatable(UrlClicks:long, ThreatClicks:long, ClickedThrough:long, ClickUsers:dynamic,
           ClickActions:dynamic, ClickWorkloads:dynamic, ClickThreatTypes:dynamic, ClickIPs:dynamic,
           LastClick:datetime)[]);
let EmailSummary = union isfuzzy=true
(EmailUrlInfo
 | where Timestamp > ago(look)
 | extend SafeUrl=tolower(tostring(column_ifexists('Url', ''))),
          SafeDomain=tolower(tostring(column_ifexists('UrlDomain', ''))),
          SafeLocation=tostring(column_ifexists('UrlLocation', '')),
          SafeMessage=tostring(column_ifexists('NetworkMessageId', ''))
 | where SafeUrl == url or SafeUrl contains host or SafeDomain == host
 | summarize EmailReferences=count(), EmailMessages=dcount(SafeMessage),
             UrlLocations=make_set(SafeLocation, 10), LastEmailReference=max(Timestamp)),
(datatable(EmailReferences:long, EmailMessages:long, UrlLocations:dynamic, LastEmailReference:datetime)[]);
let DeviceSummary = union isfuzzy=true
(DeviceNetworkEvents
 | where Timestamp > ago(look)
 | extend SafeRemoteUrl=tolower(tostring(column_ifexists('RemoteUrl', ''))),
          SafeDevice=tostring(column_ifexists('DeviceName', '')),
          SafeRemoteIP=tostring(column_ifexists('RemoteIP', '')),
          SafeProcess=tostring(column_ifexists('InitiatingProcessFileName', ''))
 | where SafeRemoteUrl == url or SafeRemoteUrl contains host
 | summarize DeviceConnections=count(), Devices=make_set(SafeDevice, 20),
             RemoteIPs=make_set(SafeRemoteIP, 15), NetworkProcesses=make_set(SafeProcess, 15),
             LastDeviceConnection=max(Timestamp)),
(datatable(DeviceConnections:long, Devices:dynamic, RemoteIPs:dynamic, NetworkProcesses:dynamic,
           LastDeviceConnection:datetime)[]);
let AlertSummary = union isfuzzy=true
(AlertEvidence
 | where Timestamp > ago(look)
 | extend SafeRemoteUrl=tolower(tostring(column_ifexists('RemoteUrl', ''))),
          SafeTitle=tostring(column_ifexists('Title', '')),
          SafeSeverity=tostring(column_ifexists('Severity', '')),
          SafeService=tostring(column_ifexists('ServiceSource', '')),
          SafeRole=tostring(column_ifexists('EvidenceRole', '')),
          SafeAlertId=tostring(column_ifexists('AlertId', ''))
 | where SafeRemoteUrl == url or SafeRemoteUrl contains host
 | summarize Alerts=dcount(SafeAlertId), HighAlerts=dcountif(SafeAlertId, tolower(SafeSeverity) == 'high'),
             AlertTitles=make_set(SafeTitle, 15), AlertSeverities=make_set(SafeSeverity, 8),
             AlertServices=make_set(SafeService, 8), EvidenceRoles=make_set(SafeRole, 8),
             LastAlert=max(Timestamp)),
(datatable(Alerts:long, HighAlerts:long, AlertTitles:dynamic, AlertSeverities:dynamic,
           AlertServices:dynamic, EvidenceRoles:dynamic, LastAlert:datetime)[]);
datatable(Seed:int)[1]
| extend UrlClicks=tolong(coalesce(toscalar(ClickSummary | project UrlClicks), 0)),
         ThreatClicks=tolong(coalesce(toscalar(ClickSummary | project ThreatClicks), 0)),
         ClickedThrough=tolong(coalesce(toscalar(ClickSummary | project ClickedThrough), 0)),
         ClickUsers=tostring(coalesce(toscalar(ClickSummary | project ClickUsers), dynamic([]))),
         ClickActions=tostring(coalesce(toscalar(ClickSummary | project ClickActions), dynamic([]))),
         ClickWorkloads=tostring(coalesce(toscalar(ClickSummary | project ClickWorkloads), dynamic([]))),
         ClickThreatTypes=tostring(coalesce(toscalar(ClickSummary | project ClickThreatTypes), dynamic([]))),
         ClickIPs=tostring(coalesce(toscalar(ClickSummary | project ClickIPs), dynamic([]))),
         LastClick=toscalar(ClickSummary | project LastClick),
         EmailReferences=tolong(coalesce(toscalar(EmailSummary | project EmailReferences), 0)),
         EmailMessages=tolong(coalesce(toscalar(EmailSummary | project EmailMessages), 0)),
         UrlLocations=tostring(coalesce(toscalar(EmailSummary | project UrlLocations), dynamic([]))),
         LastEmailReference=toscalar(EmailSummary | project LastEmailReference),
         DeviceConnections=tolong(coalesce(toscalar(DeviceSummary | project DeviceConnections), 0)),
         Devices=tostring(coalesce(toscalar(DeviceSummary | project Devices), dynamic([]))),
         RemoteIPs=tostring(coalesce(toscalar(DeviceSummary | project RemoteIPs), dynamic([]))),
         NetworkProcesses=tostring(coalesce(toscalar(DeviceSummary | project NetworkProcesses), dynamic([]))),
         LastDeviceConnection=toscalar(DeviceSummary | project LastDeviceConnection),
         Alerts=tolong(coalesce(toscalar(AlertSummary | project Alerts), 0)),
         HighAlerts=tolong(coalesce(toscalar(AlertSummary | project HighAlerts), 0)),
         AlertTitles=tostring(coalesce(toscalar(AlertSummary | project AlertTitles), dynamic([]))),
         AlertSeverities=tostring(coalesce(toscalar(AlertSummary | project AlertSeverities), dynamic([]))),
         AlertServices=tostring(coalesce(toscalar(AlertSummary | project AlertServices), dynamic([]))),
         EvidenceRoles=tostring(coalesce(toscalar(AlertSummary | project EvidenceRoles), dynamic([]))),
         LastAlert=toscalar(AlertSummary | project LastAlert)
| extend TotalObservations=UrlClicks + EmailReferences + DeviceConnections + Alerts
| project-away Seed"""


WORKSPACE_KQL = f"""let url = '{KQL_URL}';
let host = '{KQL_HOST}';
let look = @{{parameters('LookbackDays')}}d;
let watchAlias = '@{{replace(parameters('URLContextWatchlistAlias'), decodeUriComponent('%27'), '')}}';
let TI = union isfuzzy=true
(ThreatIntelIndicators
 | extend SafeKey=tostring(column_ifexists('ObservableKey', '')),
          SafeValue=tolower(tostring(column_ifexists('ObservableValue', ''))),
          SafeConfidence=toint(column_ifexists('Confidence', 0)),
          SafeName=tostring(column_ifexists('Name', '')),
          SafeTags=tostring(column_ifexists('Tags', dynamic([]))),
          SafeModified=todatetime(column_ifexists('Modified', datetime(null))),
          SafeDeleted=tobool(column_ifexists('IsDeleted', false))
 | where SafeDeleted == false and SafeKey in ('url:value', 'domain-name:value')
 | where SafeValue == url or SafeValue == host
 | summarize arg_max(TimeGenerated, *) by Id
 | project Source=iff(SafeConfidence >= 70, 'Sentinel TI - high', 'Sentinel TI'),
           Detail=strcat('confidence ', SafeConfidence, '/100 | ', SafeName, ' | tags: ', SafeTags),
           Last=coalesce(SafeModified, TimeGenerated)),
(ThreatIntelligenceIndicator
 | extend SafeUrl=tolower(tostring(column_ifexists('Url', ''))),
          SafeDomain=tolower(tostring(column_ifexists('DomainName', ''))),
          SafeConfidence=toint(column_ifexists('ConfidenceScore', 0)),
          SafeThreat=tostring(column_ifexists('ThreatType', '')),
          SafeDescription=tostring(column_ifexists('Description', '')),
          SafeActive=tobool(column_ifexists('Active', true)),
          SafeExpiration=todatetime(column_ifexists('ExpirationDateTime', datetime(null)))
 | where SafeActive == true and (SafeUrl == url or SafeDomain == host)
 | summarize arg_max(TimeGenerated, *) by IndicatorId
 | project Source=iff(SafeConfidence >= 70, 'Sentinel TI - high', 'Sentinel TI - legacy'),
           Detail=strcat('confidence ', SafeConfidence, '/100 | ', SafeThreat, ' | ', SafeDescription),
           Last=TimeGenerated),
(datatable(Source:string, Detail:string, Last:datetime)[]);
let ClientContext = union isfuzzy=true
(Watchlist
 | where isnotempty(watchAlias) and WatchlistAlias == watchAlias
 | where tolower(SearchKey) == url or tolower(SearchKey) == host
 | summarize arg_max(TimeGenerated, *) by SearchKey
 | extend W=todynamic(WatchlistItem)
 | extend Classification=tolower(coalesce(tostring(W.Classification), tostring(W.Risk), 'unclassified'))
 | project Source=iff(Classification in ('critical', 'high', 'malicious', 'knownbad', 'phishing'),
                      'Client URL context - critical', 'Client URL context'),
           Detail=strcat('classification: ', Classification, ' | owner: ', coalesce(tostring(W.Owner), 'n/a'),
                         ' | campaign: ', coalesce(tostring(W.Campaign), 'n/a'),
                         ' | notes: ', coalesce(tostring(W.Description), tostring(W.Notes), 'none')),
           Last=coalesce(todatetime(W.LastUpdated), TimeGenerated)),
(datatable(Source:string, Detail:string, Last:datetime)[]);
let Alerts = union isfuzzy=true
(SecurityAlert
 | where TimeGenerated > ago(look)
 | extend EntityText=tolower(tostring(Entities))
 | where EntityText contains url or EntityText contains host
 | summarize AlertCount=count(), High=countif(tolower(AlertSeverity) == 'high'),
             Names=make_set(AlertName, 15), Severities=make_set(AlertSeverity, 8),
             Products=make_set(ProductName, 8), Last=max(TimeGenerated)
 | project Source=iff(High > 0, 'Sentinel high alert', 'Sentinel alerts'),
           Detail=strcat(AlertCount, ' alert(s), ', High, ' high | ', tostring(Names),
                         ' | severity: ', tostring(Severities), ' | products: ', tostring(Products)), Last),
(datatable(Source:string, Detail:string, Last:datetime)[]);
let Observations = union isfuzzy=true
(UrlClickEvents
 | where TimeGenerated > ago(look)
 | extend SafeUrl=tolower(tostring(column_ifexists('Url', ''))),
          SafeChain=tolower(tostring(column_ifexists('UrlChain', ''))),
          SafeUser=tostring(column_ifexists('AccountUpn', '')),
          SafeAction=tostring(column_ifexists('ActionType', '')),
          SafeThreat=tostring(column_ifexists('ThreatTypes', ''))
 | where SafeUrl == url or SafeUrl contains host or SafeChain contains url or SafeChain contains host
 | summarize Count=count(), Users=make_set(SafeUser, 20), Actions=make_set(SafeAction, 10),
             Threats=make_set(SafeThreat, 10), Last=max(TimeGenerated)
 | project Source='Safe Links clicks',
           Detail=strcat(Count, ' click(s) | users: ', tostring(Users), ' | actions: ', tostring(Actions),
                         ' | threats: ', tostring(Threats)), Last),
(EmailUrlInfo
 | where TimeGenerated > ago(look)
 | extend SafeUrl=tolower(tostring(column_ifexists('Url', ''))),
          SafeDomain=tolower(tostring(column_ifexists('UrlDomain', ''))),
          SafeLocation=tostring(column_ifexists('UrlLocation', ''))
 | where SafeUrl == url or SafeUrl contains host or SafeDomain == host
 | summarize Count=count(), Locations=make_set(SafeLocation, 10), Last=max(TimeGenerated)
 | project Source='Email URL references', Detail=strcat(Count, ' reference(s) | locations: ', tostring(Locations)), Last),
(DeviceNetworkEvents
 | where TimeGenerated > ago(look)
 | extend SafeUrl=tolower(tostring(column_ifexists('RemoteUrl', ''))),
          SafeDevice=tostring(column_ifexists('DeviceName', '')),
          SafeProcess=tostring(column_ifexists('InitiatingProcessFileName', ''))
 | where SafeUrl == url or SafeUrl contains host
 | summarize Count=count(), Devices=make_set(SafeDevice, 20), Processes=make_set(SafeProcess, 15), Last=max(TimeGenerated)
 | project Source='Device URL connections',
           Detail=strcat(Count, ' connection(s) | devices: ', tostring(Devices), ' | processes: ', tostring(Processes)), Last),
(CommonSecurityLog
 | where TimeGenerated > ago(look)
 | extend SafeUrl=tolower(tostring(column_ifexists('RequestURL', ''))),
          SafeHost=tolower(tostring(column_ifexists('DestinationHostName', ''))),
          SafeDevice=tostring(column_ifexists('DeviceName', '')),
          SafeAction=tostring(column_ifexists('DeviceAction', ''))
 | where SafeUrl == url or SafeUrl contains host or SafeHost == host
 | summarize Count=count(), Devices=make_set(SafeDevice, 15), Actions=make_set(SafeAction, 10), Last=max(TimeGenerated)
 | project Source='CommonSecurityLog web activity',
           Detail=strcat(Count, ' event(s) | devices: ', tostring(Devices), ' | actions: ', tostring(Actions)), Last),
(datatable(Source:string, Detail:string, Last:datetime)[]);
union TI, ClientContext, Alerts, Observations
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
    "Automated URL enrichment &mdash; playbook <b>@{workflow()?['name']}</b> "
    "&middot; run @{formatDateTime(utcNow(), 'yyyy-MM-dd HH:mm')} UTC</div>"
)


MDTI_BLOCK = f"""<div style="{H4}"><b>Microsoft Threat Intelligence</b> <span style="font-weight:400;color:#605e5c">(Microsoft Graph)</span></div>
<table style="{TBL}">
<tr><th style="{TH}">Status</th><td style="{TD}">@{{variables('MDTIStatus')}}</td><th style="{TH}">Defender search</th><td style="{TD}"><a href="https://security.microsoft.com/search?query=@{{uriComponent(outputs('Compose_URL_Host'))}}">open host intelligence</a></td></tr>
<tr><th style="{TH}">Reputation</th><td style="{TD}" colspan="3">@{{if(equals(outputs('HTTP_MDTI_Reputation')?['statusCode'], 200), concat('<b>', string(coalesce(body('HTTP_MDTI_Reputation')?['classification'], 'unknown')), '</b> &nbsp;|&nbsp; score <b>', string(coalesce(body('HTTP_MDTI_Reputation')?['score'], 'n/a')), '</b>/100 &nbsp;|&nbsp; rules/reports: ', string(coalesce(body('HTTP_MDTI_Reputation')?['rules'], json('[]')))), concat('unavailable (HTTP ', string(coalesce(outputs('HTTP_MDTI_Reputation')?['statusCode'], 'no response')), ')'))}}</td></tr>
<tr><th style="{TH}">Host</th><td style="{TD}" colspan="3">@{{if(equals(outputs('HTTP_MDTI_Host')?['statusCode'], 200), concat('first seen: ', string(coalesce(body('HTTP_MDTI_Host')?['firstSeenDateTime'], 'n/a')), ' &nbsp;|&nbsp; last seen: ', string(coalesce(body('HTTP_MDTI_Host')?['lastSeenDateTime'], 'n/a')), ' &nbsp;|&nbsp; registrar: ', string(coalesce(body('HTTP_MDTI_Host')?['registrar'], 'n/a')), ' &nbsp;|&nbsp; registrant: ', string(coalesce(body('HTTP_MDTI_Host')?['registrant'], 'n/a'))), concat('unavailable (HTTP ', string(coalesce(outputs('HTTP_MDTI_Host')?['statusCode'], 'no response')), ')'))}}</td></tr>
<tr><th style="{TH}">WHOIS</th><td style="{TD}" colspan="3">@{{if(equals(outputs('HTTP_MDTI_WHOIS')?['statusCode'], 200), concat('registered: ', string(coalesce(body('HTTP_MDTI_WHOIS')?['registrationDateTime'], 'n/a')), ' &nbsp;|&nbsp; expires: ', string(coalesce(body('HTTP_MDTI_WHOIS')?['expirationDateTime'], 'n/a')), ' &nbsp;|&nbsp; registrar: ', string(coalesce(body('HTTP_MDTI_WHOIS')?['registrar']?['organization'], 'n/a')), ' &nbsp;|&nbsp; registrant: ', string(coalesce(body('HTTP_MDTI_WHOIS')?['registrant']?['organization'], 'n/a')), ' &nbsp;|&nbsp; abuse: ', string(coalesce(body('HTTP_MDTI_WHOIS')?['abuse']?['email'], 'n/a')), ' &nbsp;|&nbsp; nameservers: ', string(coalesce(body('HTTP_MDTI_WHOIS')?['nameservers'], json('[]')))), concat('unavailable (HTTP ', string(coalesce(outputs('HTTP_MDTI_WHOIS')?['statusCode'], 'no response')), ')'))}}</td></tr>
<tr><th style="{TH}">Passive DNS</th><td style="{TD}" colspan="3">@{{if(equals(outputs('HTTP_MDTI_Passive_DNS')?['statusCode'], 200), concat(string(length(coalesce(body('HTTP_MDTI_Passive_DNS')?['value'], json('[]')))), ' record(s): ', string(coalesce(body('HTTP_MDTI_Passive_DNS')?['value'], json('[]')))), concat('unavailable (HTTP ', string(coalesce(outputs('HTTP_MDTI_Passive_DNS')?['statusCode'], 'no response')), ')'))}}</td></tr>
<tr><th style="{TH}">Trackers</th><td style="{TD}">@{{if(equals(outputs('HTTP_MDTI_Trackers')?['statusCode'], 200), concat(string(length(coalesce(body('HTTP_MDTI_Trackers')?['value'], json('[]')))), ' item(s): ', string(coalesce(body('HTTP_MDTI_Trackers')?['value'], json('[]')))), concat('unavailable HTTP ', string(coalesce(outputs('HTTP_MDTI_Trackers')?['statusCode'], 'n/a'))))}}</td><th style="{TH}">Cookies</th><td style="{TD}">@{{if(equals(outputs('HTTP_MDTI_Cookies')?['statusCode'], 200), concat(string(length(coalesce(body('HTTP_MDTI_Cookies')?['value'], json('[]')))), ' item(s): ', string(coalesce(body('HTTP_MDTI_Cookies')?['value'], json('[]')))), concat('unavailable HTTP ', string(coalesce(outputs('HTTP_MDTI_Cookies')?['statusCode'], 'n/a'))))}}</td></tr>
<tr><th style="{TH}">Components</th><td style="{TD}" colspan="3">@{{if(equals(outputs('HTTP_MDTI_Components')?['statusCode'], 200), concat(string(length(coalesce(body('HTTP_MDTI_Components')?['value'], json('[]')))), ' item(s): ', string(coalesce(body('HTTP_MDTI_Components')?['value'], json('[]')))), concat('unavailable (HTTP ', string(coalesce(outputs('HTTP_MDTI_Components')?['statusCode'], 'no response')), ')'))}}</td></tr>
</table>"""


MDTI_DISABLED_BLOCK = f"""<div style="{H4}"><b>Microsoft Threat Intelligence</b></div>
<table style="{TBL}"><tr><td style="{TD}">Disabled by deployment setting.</td></tr></table>"""


DEFENDER_BLOCK = f"""<div style="{H4}"><b>Defender XDR URL activity &mdash; last @{{parameters('DefenderLookbackDays')}} days</b></div>
<table style="{TBL}">
<tr><th style="{TH}">Status</th><td style="{TD}" colspan="3">@{{variables('DefenderStatus')}}</td></tr>
<tr><th style="{TH}">Safe Links clicks</th><td style="{TD}"><b>@{{string(coalesce(variables('DefenderJson')?['UrlClicks'], 0))}}</b> total &nbsp;|&nbsp; @{{string(coalesce(variables('DefenderJson')?['ThreatClicks'], 0))}} threat-tagged &nbsp;|&nbsp; <b>@{{string(coalesce(variables('DefenderJson')?['ClickedThrough'], 0))}} clicked through</b></td><th style="{TH}">Users</th><td style="{TD}">@{{string(coalesce(variables('DefenderJson')?['ClickUsers'], '[]'))}}</td></tr>
<tr><th style="{TH}">Click context</th><td style="{TD}" colspan="3">actions: @{{string(coalesce(variables('DefenderJson')?['ClickActions'], '[]'))}} &nbsp;|&nbsp; workloads: @{{string(coalesce(variables('DefenderJson')?['ClickWorkloads'], '[]'))}} &nbsp;|&nbsp; threats: @{{string(coalesce(variables('DefenderJson')?['ClickThreatTypes'], '[]'))}} &nbsp;|&nbsp; IPs: @{{string(coalesce(variables('DefenderJson')?['ClickIPs'], '[]'))}}</td></tr>
<tr><th style="{TH}">Email references</th><td style="{TD}">@{{string(coalesce(variables('DefenderJson')?['EmailReferences'], 0))}} reference(s) / @{{string(coalesce(variables('DefenderJson')?['EmailMessages'], 0))}} message(s) &nbsp;|&nbsp; locations: @{{string(coalesce(variables('DefenderJson')?['UrlLocations'], '[]'))}}</td><th style="{TH}">Last email reference</th><td style="{TD}">@{{string(coalesce(variables('DefenderJson')?['LastEmailReference'], 'n/a'))}}</td></tr>
<tr><th style="{TH}">Device connections</th><td style="{TD}">@{{string(coalesce(variables('DefenderJson')?['DeviceConnections'], 0))}} connection(s) &nbsp;|&nbsp; devices: @{{string(coalesce(variables('DefenderJson')?['Devices'], '[]'))}}</td><th style="{TH}">Processes / IPs</th><td style="{TD}">@{{string(coalesce(variables('DefenderJson')?['NetworkProcesses'], '[]'))}} &nbsp;|&nbsp; @{{string(coalesce(variables('DefenderJson')?['RemoteIPs'], '[]'))}}</td></tr>
<tr><th style="{TH}">Alerts</th><td style="{TD}"><b>@{{string(coalesce(variables('DefenderJson')?['Alerts'], 0))}}</b> alert(s), <b>@{{string(coalesce(variables('DefenderJson')?['HighAlerts'], 0))}} high</b></td><th style="{TH}">Alert titles</th><td style="{TD}">@{{string(coalesce(variables('DefenderJson')?['AlertTitles'], '[]'))}}</td></tr>
</table>"""


DEFENDER_DISABLED_BLOCK = f"""<div style="{H4}"><b>Defender XDR URL activity</b></div>
<table style="{TBL}"><tr><td style="{TD}">Disabled by deployment setting.</td></tr></table>"""


VT_BLOCK = f"""<div style="{H4}"><b>VirusTotal</b> <span style="font-weight:400;color:#605e5c">(community engine consensus)</span></div>
<table style="{TBL}">
<tr><th style="{TH}">Status</th><td style="{TD}">@{{variables('VTStatus')}}</td><th style="{TH}">Link</th><td style="{TD}"><a href="https://www.virustotal.com/gui/url/@{{outputs('Compose_VT_URL_Id')}}">open in VirusTotal</a></td></tr>
<tr><th style="{TH}">Detections</th><td style="{TD}" colspan="3">malicious: <b>@{{string(coalesce(variables('VTJson')?['last_analysis_stats']?['malicious'], 0))}}</b> &nbsp;|&nbsp; suspicious: @{{string(coalesce(variables('VTJson')?['last_analysis_stats']?['suspicious'], 0))}} &nbsp;|&nbsp; harmless: @{{string(coalesce(variables('VTJson')?['last_analysis_stats']?['harmless'], 0))}} &nbsp;|&nbsp; undetected: @{{string(coalesce(variables('VTJson')?['last_analysis_stats']?['undetected'], 0))}}</td></tr>
<tr><th style="{TH}">Reputation</th><td style="{TD}">@{{string(coalesce(variables('VTJson')?['reputation'], 'n/a'))}}</td><th style="{TH}">Categories</th><td style="{TD}">@{{string(coalesce(variables('VTJson')?['categories'], json('{{}}')))}}</td></tr>
</table>"""


VT_DISABLED_BLOCK = f"""<div style="{H4}"><b>VirusTotal</b></div>
<table style="{TBL}"><tr><td style="{TD}">Skipped &mdash; no API key supplied at deployment. The free public API forbids business-workflow use; supply a Premium key to enable.</td></tr></table>"""


SAFEBROWSING_BLOCK = f"""<div style="{H4}"><b>Google Safe Browsing</b></div>
<table style="{TBL}">
<tr><th style="{TH}">Status</th><td style="{TD}" colspan="3">@{{variables('SafeBrowsingStatus')}}</td></tr>
<tr><th style="{TH}">Matches</th><td style="{TD}" colspan="3"><b>@{{string(length(variables('SafeBrowsingJson')))}}</b> threat match(es): @{{string(variables('SafeBrowsingJson'))}}</td></tr>
</table>"""


SAFEBROWSING_DISABLED_BLOCK = f"""<div style="{H4}"><b>Google Safe Browsing</b></div>
<table style="{TBL}"><tr><td style="{TD}">Skipped &mdash; no API key supplied at deployment.</td></tr></table>"""


URLSCAN_BLOCK = f"""<div style="{H4}"><b>urlscan.io</b> <span style="font-weight:400;color:#605e5c">(prior public scans)</span></div>
<table style="{TBL}">
<tr><th style="{TH}">Status</th><td style="{TD}">@{{variables('UrlscanStatus')}}</td><th style="{TH}">Search</th><td style="{TD}"><a href="https://urlscan.io/search/#domain:@{{outputs('Compose_URL_Host')}}">open in urlscan.io</a></td></tr>
<tr><th style="{TH}">Results</th><td style="{TD}" colspan="3"><b>@{{string(coalesce(variables('UrlscanJson')?['Total'], 0))}}</b> scan(s) found &nbsp;|&nbsp; <b>@{{string(coalesce(variables('UrlscanJson')?['MaliciousCount'], 0))}} flagged malicious</b></td></tr>
<tr><th style="{TH}">Most recent scan</th><td style="{TD}" colspan="3">@{{string(coalesce(variables('UrlscanJson')?['First']?['page']?['url'], 'n/a'))}} &nbsp;|&nbsp; IP: @{{string(coalesce(variables('UrlscanJson')?['First']?['page']?['ip'], 'n/a'))}} &nbsp;|&nbsp; ASN: @{{string(coalesce(variables('UrlscanJson')?['First']?['page']?['asn'], 'n/a'))}} @{{string(coalesce(variables('UrlscanJson')?['First']?['page']?['asnname'], ''))}} &nbsp;|&nbsp; country: @{{string(coalesce(variables('UrlscanJson')?['First']?['page']?['country'], 'n/a'))}}</td></tr>
</table>"""


URLSCAN_DISABLED_BLOCK = f"""<div style="{H4}"><b>urlscan.io</b></div>
<table style="{TBL}"><tr><td style="{TD}">Disabled by deployment setting.</td></tr></table>"""


PHISHTANK_BLOCK = f"""<div style="{H4}"><b>PhishTank</b></div>
<table style="{TBL}">
<tr><th style="{TH}">Status</th><td style="{TD}">@{{variables('PhishTankStatus')}}</td><th style="{TH}">Detail</th><td style="{TD}">@{{if(empty(coalesce(variables('PhishTankJson')?['phish_detail_page'], '')), 'n/a', concat('<a href=\"', variables('PhishTankJson')?['phish_detail_page'], '\">open in PhishTank</a>'))}}</td></tr>
<tr><th style="{TH}">In database</th><td style="{TD}">@{{string(coalesce(variables('PhishTankJson')?['in_database'], false))}}</td><th style="{TH}">Verified phish</th><td style="{TD}"><b>@{{string(coalesce(variables('PhishTankJson')?['valid'], 'n/a'))}}</b> (verified: @{{string(coalesce(variables('PhishTankJson')?['verified'], 'n/a'))}})</td></tr>
</table>"""


PHISHTANK_DISABLED_BLOCK = f"""<div style="{H4}"><b>PhishTank</b></div>
<table style="{TBL}"><tr><td style="{TD}">Disabled by deployment setting.</td></tr></table>"""


VERDICT_STYLE = (
    "@if(equals(outputs('Compose_Verdict'), 'HIGH'), '%s#a4262c', "
    "if(equals(outputs('Compose_Verdict'), 'MEDIUM'), '%s#986f0b', "
    "if(equals(outputs('Compose_Verdict'), 'LOW'), '%s#107c10', '%s#605e5c')))"
    % (CHIP, CHIP, CHIP, CHIP)
)


VERDICT = (
    "@if(or("
    "equals(toLower(string(coalesce(variables('MDTIReputation')?['classification'], ''))), 'malicious'), "
    "greaterOrEquals(int(coalesce(variables('MDTIReputation')?['score'], 0)), 70), "
    "greater(int(coalesce(variables('DefenderJson')?['ThreatClicks'], 0)), 0), "
    "greater(int(coalesce(variables('DefenderJson')?['HighAlerts'], 0)), 0), "
    "greater(length(body('Filter_High_Workspace_Findings')), 0), "
    "greater(int(coalesce(variables('VTJson')?['last_analysis_stats']?['malicious'], 0)), 0), "
    "greater(length(variables('SafeBrowsingJson')), 0), "
    "greater(int(coalesce(variables('UrlscanJson')?['MaliciousCount'], 0)), 0), "
    "and(equals(toLower(string(coalesce(variables('PhishTankJson')?['in_database'], false))), 'true'), "
    "equals(toLower(string(coalesce(variables('PhishTankJson')?['valid'], ''))), 'y')"
    ")), 'HIGH', "
    "if(or("
    "equals(toLower(string(coalesce(variables('MDTIReputation')?['classification'], ''))), 'suspicious'), "
    "greaterOrEquals(int(coalesce(variables('MDTIReputation')?['score'], 0)), 40), "
    "greater(int(coalesce(variables('DefenderJson')?['ClickedThrough'], 0)), 0), "
    "greater(int(coalesce(variables('DefenderJson')?['Alerts'], 0)), 0), "
    "greater(int(coalesce(variables('DefenderJson')?['TotalObservations'], 0)), 0), "
    "greater(length(outputs('Compose_Workspace_Rows')), 0), "
    "greater(int(coalesce(variables('VTJson')?['last_analysis_stats']?['suspicious'], 0)), 0), "
    "greater(int(coalesce(variables('UrlscanJson')?['Total'], 0)), 0), "
    "equals(toLower(string(coalesce(variables('PhishTankJson')?['in_database'], false))), 'true')"
    "), 'MEDIUM', "
    "if(or(equals(toLower(string(coalesce(variables('MDTIReputation')?['classification'], ''))), 'benign'), "
    "equals(toLower(string(coalesce(variables('MDTIReputation')?['classification'], ''))), 'neutral')), "
    "'LOW', 'UNKNOWN')))"
)


VERDICT_REASON = (
    "@concat('MDTI: ', variables('MDTIStatus'), "
    "' &middot; Defender: ', variables('DefenderStatus'), "
    "' &middot; VT: ', variables('VTStatus'), "
    "' &middot; Safe Browsing: ', variables('SafeBrowsingStatus'), "
    "' &middot; urlscan.io: ', variables('UrlscanStatus'), "
    "' &middot; PhishTank: ', variables('PhishTankStatus'), "
    "' &middot; observations: ', string(coalesce(variables('DefenderJson')?['TotalObservations'], 0)), "
    "' &middot; workspace rows: ', string(length(outputs('Compose_Workspace_Rows'))))"
)


URL_BLOCK = f"""<hr style="border:0;border-top:1px solid #e1dfdd;margin:16px 0">
<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;font-weight:600;margin-bottom:6px">
URL enrichment &mdash; <code>@{{outputs('Compose_Display_URL')}}</code>
<span style="@{{outputs('Compose_VerdictStyle')}}">@{{outputs('Compose_Verdict')}}</span>
</div>
<div style="font-family:Segoe UI,Arial,sans-serif;font-size:11px;color:#605e5c;margin-bottom:10px">@{{outputs('Compose_VerdictReason')}}</div>
<table style="{TBL}">
<tr><th style="{TH}">Normalized URL</th><td style="{TD}">@{{outputs('Compose_Display_URL')}}</td></tr>
<tr><th style="{TH}">Host</th><td style="{TD}"><b>@{{outputs('Compose_URL_Host')}}</b></td></tr>
</table>
@{{variables('MDTIHtml')}}
@{{variables('DefenderHtml')}}
@{{variables('VTHtml')}}
@{{variables('SafeBrowsingHtml')}}
@{{variables('UrlscanHtml')}}
@{{variables('PhishTankHtml')}}
<div style="{H4}"><b>Sentinel workspace insights &mdash; last @{{parameters('LookbackDays')}} days</b></div>
<table style="{TBL}">
<tr><th style="{TH}">Source</th><th style="{TH}">Detail</th><th style="{TH}">Last seen (UTC)</th></tr>
@{{if(empty(outputs('Compose_Workspace_Rows')), concat('<tr><td style="{TD}" colspan="3">No matching workspace records, or the queried tables are not collected.</td></tr>'), join(body('Select_Workspace_Rows'), ''))}}
</table>"""


SENTINEL_CONN = "@parameters('$connections')['azuresentinel']['connectionId']"
LA_CONN = "@parameters('$connections')['azuremonitorlogs']['connectionId']"


def after(*names, states=("Succeeded",)):
    return {name: list(states) for name in names}


def graph_get(name, suffix, query=""):
    """Create a fail-open Microsoft Graph MDTI GET action for the current URL host."""
    return {
        "runAfter": {},
        "type": "Http",
        "inputs": {
            "method": "GET",
            "uri": (
                "@{concat('https://graph.microsoft.com/v1.0/security/threatIntelligence/hosts/', "
                "uriComponent(outputs('Compose_URL_Host')), '" + suffix + query + "')}"
            ),
            "headers": {"Accept": "application/json"},
            "authentication": MICROSOFT_GRAPH_MANAGED_IDENTITY_AUTH,
        },
        "runtimeConfiguration": {"secureData": {"properties": ["inputs"]}},
    }


mdti_http_names = (
    "HTTP_MDTI_Host",
    "HTTP_MDTI_Reputation",
    "HTTP_MDTI_WHOIS",
    "HTTP_MDTI_Passive_DNS",
    "HTTP_MDTI_Trackers",
    "HTTP_MDTI_Cookies",
    "HTTP_MDTI_Components",
)


definition = {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "$connections": {"defaultValue": {}, "type": "Object"},
        "LookbackDays": {"type": "Int", "defaultValue": 14},
        "EnableMicrosoftThreatIntelligence": {"type": "Bool", "defaultValue": True},
        "EnableDefenderAdvancedHunting": {"type": "Bool", "defaultValue": True},
        "DefenderLookbackDays": {"type": "Int", "defaultValue": 14},
        "URLContextWatchlistAlias": {"type": "String", "defaultValue": "URLContext"},
        "VirusTotalApiKey": {"type": "SecureString", "defaultValue": ""},
        "GoogleSafeBrowsingApiKey": {"type": "SecureString", "defaultValue": ""},
        "EnableUrlscanSearch": {"type": "Bool", "defaultValue": True},
        "UrlscanApiKey": {"type": "SecureString", "defaultValue": ""},
        "EnablePhishTank": {"type": "Bool", "defaultValue": True},
        "PhishTankAppKey": {"type": "SecureString", "defaultValue": ""},
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
        "Init_MDTIReputation": {
            "runAfter": after("Init_HtmlBody"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "MDTIReputation", "type": "object", "value": {}}]},
        },
        "Init_MDTIStatus": {
            "runAfter": after("Init_MDTIReputation"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "MDTIStatus", "type": "string", "value": "disabled by deployment setting"}]},
        },
        "Init_MDTIHtml": {
            "runAfter": after("Init_MDTIStatus"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "MDTIHtml", "type": "string", "value": ""}]},
        },
        "Init_DefenderJson": {
            "runAfter": after("Init_MDTIHtml"), "type": "InitializeVariable",
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
        "Init_VTJson": {
            "runAfter": after("Init_DefenderHtml"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "VTJson", "type": "object", "value": {}}]},
        },
        "Init_VTStatus": {
            "runAfter": after("Init_VTJson"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "VTStatus", "type": "string", "value": "skipped, no API key"}]},
        },
        "Init_VTHtml": {
            "runAfter": after("Init_VTStatus"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "VTHtml", "type": "string", "value": ""}]},
        },
        "Init_SafeBrowsingJson": {
            "runAfter": after("Init_VTHtml"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "SafeBrowsingJson", "type": "array", "value": []}]},
        },
        "Init_SafeBrowsingStatus": {
            "runAfter": after("Init_SafeBrowsingJson"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "SafeBrowsingStatus", "type": "string", "value": "skipped, no API key"}]},
        },
        "Init_SafeBrowsingHtml": {
            "runAfter": after("Init_SafeBrowsingStatus"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "SafeBrowsingHtml", "type": "string", "value": ""}]},
        },
        "Init_UrlscanJson": {
            "runAfter": after("Init_SafeBrowsingHtml"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "UrlscanJson", "type": "object", "value": {}}]},
        },
        "Init_UrlscanStatus": {
            "runAfter": after("Init_UrlscanJson"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "UrlscanStatus", "type": "string", "value": "disabled by deployment setting"}]},
        },
        "Init_UrlscanHtml": {
            "runAfter": after("Init_UrlscanStatus"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "UrlscanHtml", "type": "string", "value": ""}]},
        },
        "Init_PhishTankJson": {
            "runAfter": after("Init_UrlscanHtml"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "PhishTankJson", "type": "object", "value": {}}]},
        },
        "Init_PhishTankStatus": {
            "runAfter": after("Init_PhishTankJson"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "PhishTankStatus", "type": "string", "value": "disabled by deployment setting"}]},
        },
        "Init_PhishTankHtml": {
            "runAfter": after("Init_PhishTankStatus"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "PhishTankHtml", "type": "string", "value": ""}]},
        },
        "Entities_-_Get_URLs": {
            "runAfter": after("Init_PhishTankHtml"), "type": "ApiConnection",
            "inputs": {
                "host": {"connection": {"name": SENTINEL_CONN}},
                "method": "post",
                "body": "@triggerBody()?['object']?['properties']?['relatedEntities']",
                "path": "/entities/url",
            },
        },
        "For_each_URL_entity": {
            "foreach": "@coalesce(body('Entities_-_Get_URLs')?['URLs'], json('[]'))",
            "runAfter": after("Entities_-_Get_URLs"),
            "type": "Foreach",
            "runtimeConfiguration": {"concurrency": {"repetitions": 1}},
            "actions": {
                "Reset_MDTIReputation": {
                    "runAfter": {}, "type": "SetVariable",
                    "inputs": {"name": "MDTIReputation", "value": {}},
                },
                "Reset_MDTIStatus": {
                    "runAfter": after("Reset_MDTIReputation"), "type": "SetVariable",
                    "inputs": {"name": "MDTIStatus", "value": "disabled by deployment setting"},
                },
                "Reset_MDTIHtml": {
                    "runAfter": after("Reset_MDTIStatus"), "type": "SetVariable",
                    "inputs": {"name": "MDTIHtml", "value": ""},
                },
                "Reset_DefenderJson": {
                    "runAfter": after("Reset_MDTIHtml"), "type": "SetVariable",
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
                "Reset_VTJson": {
                    "runAfter": after("Reset_DefenderHtml"), "type": "SetVariable",
                    "inputs": {"name": "VTJson", "value": {}},
                },
                "Reset_VTStatus": {
                    "runAfter": after("Reset_VTJson"), "type": "SetVariable",
                    "inputs": {"name": "VTStatus", "value": "skipped, no API key"},
                },
                "Reset_VTHtml": {
                    "runAfter": after("Reset_VTStatus"), "type": "SetVariable",
                    "inputs": {"name": "VTHtml", "value": ""},
                },
                "Reset_SafeBrowsingJson": {
                    "runAfter": after("Reset_VTHtml"), "type": "SetVariable",
                    "inputs": {"name": "SafeBrowsingJson", "value": []},
                },
                "Reset_SafeBrowsingStatus": {
                    "runAfter": after("Reset_SafeBrowsingJson"), "type": "SetVariable",
                    "inputs": {"name": "SafeBrowsingStatus", "value": "skipped, no API key"},
                },
                "Reset_SafeBrowsingHtml": {
                    "runAfter": after("Reset_SafeBrowsingStatus"), "type": "SetVariable",
                    "inputs": {"name": "SafeBrowsingHtml", "value": ""},
                },
                "Reset_UrlscanJson": {
                    "runAfter": after("Reset_SafeBrowsingHtml"), "type": "SetVariable",
                    "inputs": {"name": "UrlscanJson", "value": {}},
                },
                "Reset_UrlscanStatus": {
                    "runAfter": after("Reset_UrlscanJson"), "type": "SetVariable",
                    "inputs": {"name": "UrlscanStatus", "value": "disabled by deployment setting"},
                },
                "Reset_UrlscanHtml": {
                    "runAfter": after("Reset_UrlscanStatus"), "type": "SetVariable",
                    "inputs": {"name": "UrlscanHtml", "value": ""},
                },
                "Reset_PhishTankJson": {
                    "runAfter": after("Reset_UrlscanHtml"), "type": "SetVariable",
                    "inputs": {"name": "PhishTankJson", "value": {}},
                },
                "Reset_PhishTankStatus": {
                    "runAfter": after("Reset_PhishTankJson"), "type": "SetVariable",
                    "inputs": {"name": "PhishTankStatus", "value": "disabled by deployment setting"},
                },
                "Reset_PhishTankHtml": {
                    "runAfter": after("Reset_PhishTankStatus"), "type": "SetVariable",
                    "inputs": {"name": "PhishTankHtml", "value": ""},
                },
                "Compose_Clean_URL": {
                    "runAfter": after("Reset_PhishTankHtml"), "type": "Compose",
                    "inputs": (
                        "@replace(replace(replace(trim(string(coalesce(items('For_each_URL_entity')?['Url'], "
                        "items('For_each_URL_entity')?['url'], ''))), '[.]', '.'), 'hxxps://', 'https://'), "
                        "'hxxp://', 'http://')"
                    ),
                },
                "Compose_Normalized_URL": {
                    "runAfter": after("Compose_Clean_URL"), "type": "Compose",
                    "inputs": (
                        "@if(or(startsWith(toLower(outputs('Compose_Clean_URL')), 'http://'), "
                        "startsWith(toLower(outputs('Compose_Clean_URL')), 'https://')), "
                        "outputs('Compose_Clean_URL'), concat('https://', outputs('Compose_Clean_URL')))"
                    ),
                },
                "Compose_Display_URL": {
                    "runAfter": after("Compose_Normalized_URL"), "type": "Compose",
                    "inputs": (
                        "@replace(replace(replace(replace(outputs('Compose_Normalized_URL'), "
                        "'&', '&amp;'), '<', '&lt;'), '>', '&gt;'), decodeUriComponent('%22'), '&quot;')"
                    ),
                },
                "Compose_URL_Host": {
                    "runAfter": after("Compose_Display_URL"), "type": "Compose",
                    "inputs": "@toLower(uriHost(outputs('Compose_Normalized_URL')))",
                },
                "Condition_MDTI_enabled": {
                    "runAfter": after("Compose_URL_Host"), "type": "If",
                    "expression": {"and": [{"equals": ["@parameters('EnableMicrosoftThreatIntelligence')", True]}]},
                    "actions": {
                        "HTTP_MDTI_Host": graph_get("HTTP_MDTI_Host", ""),
                        "HTTP_MDTI_Reputation": graph_get("HTTP_MDTI_Reputation", "/reputation"),
                        "HTTP_MDTI_WHOIS": graph_get("HTTP_MDTI_WHOIS", "/whois"),
                        "HTTP_MDTI_Passive_DNS": graph_get(
                            "HTTP_MDTI_Passive_DNS",
                            "/passiveDns?%24filter=recordType%20eq%20%27A%27&%24orderby=lastSeenDateTime%20desc&%24top=10",
                        ),
                        "HTTP_MDTI_Trackers": graph_get("HTTP_MDTI_Trackers", "/trackers?%24top=10"),
                        "HTTP_MDTI_Cookies": graph_get("HTTP_MDTI_Cookies", "/cookies?%24top=10"),
                        "HTTP_MDTI_Components": graph_get("HTTP_MDTI_Components", "/components?%24top=10"),
                        "Set_MDTIReputation": {
                            "runAfter": after("HTTP_MDTI_Reputation", states=("Succeeded", "Failed", "TimedOut")),
                            "type": "SetVariable",
                            "inputs": {
                                "name": "MDTIReputation",
                                "value": (
                                    "@if(equals(outputs('HTTP_MDTI_Reputation')?['statusCode'], 200), "
                                    "body('HTTP_MDTI_Reputation'), json('{}'))"
                                ),
                            },
                        },
                        "Set_MDTIStatus": {
                            "runAfter": after(
                                "HTTP_MDTI_Host", "HTTP_MDTI_WHOIS", "HTTP_MDTI_Passive_DNS",
                                "HTTP_MDTI_Trackers", "HTTP_MDTI_Cookies", "HTTP_MDTI_Components",
                                "Set_MDTIReputation", states=("Succeeded", "Failed", "TimedOut"),
                            ),
                            "type": "SetVariable",
                            "inputs": {
                                "name": "MDTIStatus",
                                "value": (
                                    "@if(equals(outputs('HTTP_MDTI_Reputation')?['statusCode'], 200), "
                                    "concat('available; classification ', string(coalesce(body('HTTP_MDTI_Reputation')?['classification'], 'unknown')), "
                                    "', score ', string(coalesce(body('HTTP_MDTI_Reputation')?['score'], 'n/a'))), "
                                    "if(equals(outputs('HTTP_MDTI_Host')?['statusCode'], 200), 'available; reputation not returned', "
                                    "concat('unavailable (host HTTP ', string(coalesce(outputs('HTTP_MDTI_Host')?['statusCode'], 'no response')), "
                                    "', reputation HTTP ', string(coalesce(outputs('HTTP_MDTI_Reputation')?['statusCode'], 'no response')), ')')))"
                                ),
                            },
                        },
                        "Set_MDTIHtml": {
                            "runAfter": after("Set_MDTIStatus"), "type": "SetVariable",
                            "inputs": {"name": "MDTIHtml", "value": MDTI_BLOCK},
                        },
                    },
                    "else": {
                        "actions": {
                            "Set_MDTIHtml_disabled": {
                                "runAfter": {}, "type": "SetVariable",
                                "inputs": {"name": "MDTIHtml", "value": MDTI_DISABLED_BLOCK},
                            }
                        }
                    },
                },
                "Condition_Defender_XDR_enabled": {
                    "runAfter": after("Condition_MDTI_enabled"), "type": "If",
                    "expression": {"and": [{"equals": ["@parameters('EnableDefenderAdvancedHunting')", True]}]},
                    "actions": {
                        "HTTP_Defender_XDR_URL_Hunting": {
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
                            "runAfter": after("HTTP_Defender_XDR_URL_Hunting", states=("Succeeded", "Failed", "TimedOut")),
                            "type": "Compose",
                            "inputs": (
                                "@if(equals(outputs('HTTP_Defender_XDR_URL_Hunting')?['statusCode'], 200), "
                                "coalesce(body('HTTP_Defender_XDR_URL_Hunting')?['results'], json('[]')), json('[]'))"
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
                                    "@if(not(equals(outputs('HTTP_Defender_XDR_URL_Hunting')?['statusCode'], 200)), "
                                    "concat('unavailable (HTTP ', string(coalesce(outputs('HTTP_Defender_XDR_URL_Hunting')?['statusCode'], 'no response')), ')'), "
                                    "if(greater(int(coalesce(variables('DefenderJson')?['TotalObservations'], 0)), 0), 'activity found', 'no activity observed'))"
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
                "Condition_VirusTotal_key_present": {
                    "runAfter": after("Condition_Defender_XDR_enabled"), "type": "If",
                    "expression": {"and": [{"not": {"equals": ["@parameters('VirusTotalApiKey')", ""]}}]},
                    "actions": {
                        "Compose_VT_URL_Id": {
                            "runAfter": {}, "type": "Compose",
                            "inputs": (
                                "@replace(replace(replace(base64(outputs('Compose_Normalized_URL')), "
                                "'+', '-'), '/', '_'), '=', '')"
                            ),
                        },
                        "HTTP_VirusTotal": {
                            "runAfter": after("Compose_VT_URL_Id"), "type": "Http",
                            "inputs": {
                                "method": "GET",
                                "uri": "@{concat('https://www.virustotal.com/api/v3/urls/', outputs('Compose_VT_URL_Id'))}",
                                "headers": {"x-apikey": "@parameters('VirusTotalApiKey')"},
                            },
                            "runtimeConfiguration": {"secureData": {"properties": ["inputs"]}},
                        },
                        "Set_VTJson": {
                            "runAfter": after("HTTP_VirusTotal", states=("Succeeded", "Failed", "TimedOut")),
                            "type": "SetVariable",
                            "inputs": {
                                "name": "VTJson",
                                "value": (
                                    "@if(equals(outputs('HTTP_VirusTotal')?['statusCode'], 200), "
                                    "coalesce(body('HTTP_VirusTotal')?['data']?['attributes'], json('{}')), json('{}'))"
                                ),
                            },
                        },
                        "Set_VTStatus": {
                            "runAfter": after("Set_VTJson"), "type": "SetVariable",
                            "inputs": {
                                "name": "VTStatus",
                                "value": (
                                    "@if(equals(outputs('HTTP_VirusTotal')?['statusCode'], 200), "
                                    "concat('available; ', string(coalesce(variables('VTJson')?['last_analysis_stats']?['malicious'], 0)), ' malicious of ', "
                                    "string(add(add(add(add(int(coalesce(variables('VTJson')?['last_analysis_stats']?['malicious'], 0)), "
                                    "int(coalesce(variables('VTJson')?['last_analysis_stats']?['suspicious'], 0))), "
                                    "int(coalesce(variables('VTJson')?['last_analysis_stats']?['harmless'], 0))), "
                                    "int(coalesce(variables('VTJson')?['last_analysis_stats']?['undetected'], 0))), 0)), ' engines'), "
                                    "concat('unavailable (HTTP ', string(coalesce(outputs('HTTP_VirusTotal')?['statusCode'], 'no response')), ')'))"
                                ),
                            },
                        },
                        "Set_VTHtml": {
                            "runAfter": after("Set_VTStatus"), "type": "SetVariable",
                            "inputs": {"name": "VTHtml", "value": VT_BLOCK},
                        },
                    },
                    "else": {
                        "actions": {
                            "Set_VTHtml_disabled": {
                                "runAfter": {}, "type": "SetVariable",
                                "inputs": {"name": "VTHtml", "value": VT_DISABLED_BLOCK},
                            }
                        }
                    },
                },
                "Condition_SafeBrowsing_key_present": {
                    "runAfter": after("Condition_VirusTotal_key_present"), "type": "If",
                    "expression": {"and": [{"not": {"equals": ["@parameters('GoogleSafeBrowsingApiKey')", ""]}}]},
                    "actions": {
                        "HTTP_SafeBrowsing": {
                            "runAfter": {}, "type": "Http",
                            "inputs": {
                                "method": "POST",
                                "uri": "@{concat('https://safebrowsing.googleapis.com/v4/threatMatches:find?key=', parameters('GoogleSafeBrowsingApiKey'))}",
                                "headers": {"Content-Type": "application/json; charset=utf-8"},
                                "body": {
                                    "client": {"clientId": "sentinel-url-enrichment", "clientVersion": "1.0"},
                                    "threatInfo": {
                                        "threatTypes": [
                                            "MALWARE", "SOCIAL_ENGINEERING",
                                            "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION",
                                        ],
                                        "platformTypes": ["ANY_PLATFORM"],
                                        "threatEntryTypes": ["URL"],
                                        "threatEntries": [{"url": "@{outputs('Compose_Normalized_URL')}"}],
                                    },
                                },
                            },
                            "runtimeConfiguration": {"secureData": {"properties": ["inputs"]}},
                        },
                        "Set_SafeBrowsingJson": {
                            "runAfter": after("HTTP_SafeBrowsing", states=("Succeeded", "Failed", "TimedOut")),
                            "type": "SetVariable",
                            "inputs": {
                                "name": "SafeBrowsingJson",
                                "value": (
                                    "@if(equals(outputs('HTTP_SafeBrowsing')?['statusCode'], 200), "
                                    "coalesce(body('HTTP_SafeBrowsing')?['matches'], json('[]')), json('[]'))"
                                ),
                            },
                        },
                        "Set_SafeBrowsingStatus": {
                            "runAfter": after("Set_SafeBrowsingJson"), "type": "SetVariable",
                            "inputs": {
                                "name": "SafeBrowsingStatus",
                                "value": (
                                    "@if(not(equals(outputs('HTTP_SafeBrowsing')?['statusCode'], 200)), "
                                    "concat('unavailable (HTTP ', string(coalesce(outputs('HTTP_SafeBrowsing')?['statusCode'], 'no response')), ')'), "
                                    "if(greater(length(variables('SafeBrowsingJson')), 0), 'available; threat match found', 'available; no match'))"
                                ),
                            },
                        },
                        "Set_SafeBrowsingHtml": {
                            "runAfter": after("Set_SafeBrowsingStatus"), "type": "SetVariable",
                            "inputs": {"name": "SafeBrowsingHtml", "value": SAFEBROWSING_BLOCK},
                        },
                    },
                    "else": {
                        "actions": {
                            "Set_SafeBrowsingHtml_disabled": {
                                "runAfter": {}, "type": "SetVariable",
                                "inputs": {"name": "SafeBrowsingHtml", "value": SAFEBROWSING_DISABLED_BLOCK},
                            }
                        }
                    },
                },
                "Condition_Urlscan_enabled": {
                    "runAfter": after("Condition_SafeBrowsing_key_present"), "type": "If",
                    "expression": {"and": [{"equals": ["@parameters('EnableUrlscanSearch')", True]}]},
                    "actions": {
                        "HTTP_Urlscan": {
                            "runAfter": {}, "type": "Http",
                            "inputs": {
                                "method": "GET",
                                "uri": "@{concat('https://urlscan.io/api/v1/search/?q=domain:%22', outputs('Compose_URL_Host'), '%22&size=10')}",
                                "headers": {"API-Key": "@parameters('UrlscanApiKey')", "Accept": "application/json"},
                            },
                            "runtimeConfiguration": {"secureData": {"properties": ["inputs"]}},
                        },
                        "Compose_Urlscan_Results": {
                            "runAfter": after("HTTP_Urlscan", states=("Succeeded", "Failed", "TimedOut")),
                            "type": "Compose",
                            "inputs": (
                                "@if(equals(outputs('HTTP_Urlscan')?['statusCode'], 200), "
                                "coalesce(body('HTTP_Urlscan')?['results'], json('[]')), json('[]'))"
                            ),
                        },
                        "Filter_Urlscan_Malicious": {
                            "runAfter": after("Compose_Urlscan_Results"), "type": "Query",
                            "inputs": {
                                "from": "@outputs('Compose_Urlscan_Results')",
                                "where": "@equals(item()?['verdicts']?['overall']?['malicious'], true)",
                            },
                        },
                        "Set_UrlscanJson": {
                            "runAfter": after("Filter_Urlscan_Malicious"), "type": "SetVariable",
                            "inputs": {
                                "name": "UrlscanJson",
                                "value": {
                                    "Total": "@length(outputs('Compose_Urlscan_Results'))",
                                    "MaliciousCount": "@length(body('Filter_Urlscan_Malicious'))",
                                    "First": "@if(greater(length(outputs('Compose_Urlscan_Results')), 0), first(outputs('Compose_Urlscan_Results')), json('{}'))",
                                },
                            },
                        },
                        "Set_UrlscanStatus": {
                            "runAfter": after("Set_UrlscanJson"), "type": "SetVariable",
                            "inputs": {
                                "name": "UrlscanStatus",
                                "value": (
                                    "@if(not(equals(outputs('HTTP_Urlscan')?['statusCode'], 200)), "
                                    "concat('unavailable (HTTP ', string(coalesce(outputs('HTTP_Urlscan')?['statusCode'], 'no response')), ')'), "
                                    "if(greater(int(coalesce(variables('UrlscanJson')?['Total'], 0)), 0), 'available; prior scans found', 'available; no prior scans'))"
                                ),
                            },
                        },
                        "Set_UrlscanHtml": {
                            "runAfter": after("Set_UrlscanStatus"), "type": "SetVariable",
                            "inputs": {"name": "UrlscanHtml", "value": URLSCAN_BLOCK},
                        },
                    },
                    "else": {
                        "actions": {
                            "Set_UrlscanHtml_disabled": {
                                "runAfter": {}, "type": "SetVariable",
                                "inputs": {"name": "UrlscanHtml", "value": URLSCAN_DISABLED_BLOCK},
                            }
                        }
                    },
                },
                "Condition_PhishTank_enabled": {
                    "runAfter": after("Condition_Urlscan_enabled"), "type": "If",
                    "expression": {"and": [{"equals": ["@parameters('EnablePhishTank')", True]}]},
                    "actions": {
                        "HTTP_PhishTank": {
                            "runAfter": {}, "type": "Http",
                            "inputs": {
                                "method": "POST",
                                "uri": "https://checkurl.phishtank.com/checkurl/",
                                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                                "body": (
                                    "@{concat('url=', uriComponent(outputs('Compose_Normalized_URL')), '&format=json', "
                                    "if(equals(parameters('PhishTankAppKey'), ''), '', "
                                    "concat('&app_key=', parameters('PhishTankAppKey'))))}"
                                ),
                            },
                            "runtimeConfiguration": {"secureData": {"properties": ["inputs"]}},
                        },
                        "Set_PhishTankJson": {
                            "runAfter": after("HTTP_PhishTank", states=("Succeeded", "Failed", "TimedOut")),
                            "type": "SetVariable",
                            "inputs": {
                                "name": "PhishTankJson",
                                "value": (
                                    "@if(equals(outputs('HTTP_PhishTank')?['statusCode'], 200), "
                                    "coalesce(body('HTTP_PhishTank')?['results'], json('{}')), json('{}'))"
                                ),
                            },
                        },
                        "Set_PhishTankStatus": {
                            "runAfter": after("Set_PhishTankJson"), "type": "SetVariable",
                            "inputs": {
                                "name": "PhishTankStatus",
                                "value": (
                                    "@if(not(equals(outputs('HTTP_PhishTank')?['statusCode'], 200)), "
                                    "concat('unavailable (HTTP ', string(coalesce(outputs('HTTP_PhishTank')?['statusCode'], 'no response')), ')'), "
                                    "if(equals(toLower(string(coalesce(variables('PhishTankJson')?['in_database'], false))), 'true'), "
                                    "'available; in database', 'available; not in database'))"
                                ),
                            },
                        },
                        "Set_PhishTankHtml": {
                            "runAfter": after("Set_PhishTankStatus"), "type": "SetVariable",
                            "inputs": {"name": "PhishTankHtml", "value": PHISHTANK_BLOCK},
                        },
                    },
                    "else": {
                        "actions": {
                            "Set_PhishTankHtml_disabled": {
                                "runAfter": {}, "type": "SetVariable",
                                "inputs": {"name": "PhishTankHtml", "value": PHISHTANK_DISABLED_BLOCK},
                            }
                        }
                    },
                },
                "Run_KQL_workspace_context": {
                    "runAfter": after("Condition_PhishTank_enabled"), "type": "ApiConnection",
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
                            "equals(item()?['Source'], 'Client URL context - critical'))"
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
                    "inputs": HEADER + URL_BLOCK,
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
        "title": "Enrich URL entities and post a Sentinel incident comment",
        "description": "For each URL entity on a Microsoft Sentinel incident, extracts and normalizes the host, queries Microsoft Threat Intelligence through Microsoft Graph for reputation, attributed rules and reports, WHOIS, passive DNS, trackers, cookies and web components, queries Defender XDR Advanced Hunting for Safe Links clicks, email references, device connections and alert evidence, optionally queries VirusTotal, Google Safe Browsing, urlscan.io and PhishTank for community/vendor reputation, searches Sentinel workspace telemetry and client context, calculates a triage verdict, and posts one formatted incident comment.",
        "prerequisites": "A Microsoft Sentinel-enabled Log Analytics workspace and one existing user-assigned managed identity. Microsoft Graph application permission ThreatIntelligence.Read.All is required for MDTI and ThreatHunting.Read.All is required for Defender Advanced Hunting. VirusTotal and Google Safe Browsing are optional and need their own API keys; urlscan.io and PhishTank work without a key.",
        "postDeployment": [
            "Grant the user-assigned managed identity Microsoft Sentinel Responder on the resource group holding the workspace.",
            "Grant the same identity Log Analytics Reader on the workspace.",
            "Grant the managed identity Microsoft Graph application permissions ThreatIntelligence.Read.All and ThreatHunting.Read.All using app-role assignments, then allow time for token propagation.",
            "Authorise the Microsoft Sentinel and Azure Monitor Logs API connections.",
            "Optionally supply a VirusTotal Premium key and/or a Google Safe Browsing key at deployment to enable those sources.",
            "Attach the playbook to a Sentinel incident automation rule, or run it on demand from an incident.",
        ],
        "lastUpdateTime": "2026-09-01",
        "entities": ["Url"],
        "tags": [
            "Enrichment", "URL", "Microsoft Threat Intelligence", "Defender XDR",
            "VirusTotal", "Google Safe Browsing", "urlscan.io", "PhishTank",
        ],
        "support": {"tier": "community"},
    },
    "parameters": {
        "PlaybookName": {
            "type": "string", "defaultValue": "Enrich-URL-IncidentComment",
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
        "EnableMicrosoftThreatIntelligence": {
            "type": "bool", "defaultValue": True,
            "metadata": {"description": "Query Microsoft Threat Intelligence host enrichment through Microsoft Graph. Requires ThreatIntelligence.Read.All application permission."},
        },
        "EnableDefenderAdvancedHunting": {
            "type": "bool", "defaultValue": True,
            "metadata": {"description": "Query Defender XDR Advanced Hunting through Microsoft Graph. Requires ThreatHunting.Read.All application permission."},
        },
        "DefenderLookbackDays": {
            "type": "int", "defaultValue": 14, "minValue": 1, "maxValue": 30,
            "metadata": {"description": "Defender Advanced Hunting lookback from 1 to 30 days."},
        },
        "URLContextWatchlistAlias": {
            "type": "string", "defaultValue": "URLContext",
            "metadata": {"description": "Optional client URL/domain watchlist alias. Set blank to disable."},
        },
        "VirusTotalApiKey": {
            "type": "securestring", "defaultValue": "",
            "metadata": {"description": "Optional VirusTotal API key. Leave blank to skip. The free public API forbids business-workflow use, so supply a Premium key."},
        },
        "GoogleSafeBrowsingApiKey": {
            "type": "securestring", "defaultValue": "",
            "metadata": {"description": "Optional Google Safe Browsing v4 API key (free, from Google Cloud Console). Leave blank to skip."},
        },
        "EnableUrlscanSearch": {
            "type": "bool", "defaultValue": True,
            "metadata": {"description": "Search urlscan.io for prior public scans of the URL's host. Free, no key required; a key only raises the rate limit."},
        },
        "UrlscanApiKey": {
            "type": "securestring", "defaultValue": "",
            "metadata": {"description": "Optional urlscan.io API key to raise the search rate limit. Leave blank to use the unauthenticated limit."},
        },
        "EnablePhishTank": {
            "type": "bool", "defaultValue": True,
            "metadata": {"description": "Check the URL against PhishTank's phishing verification database."},
        },
        "PhishTankAppKey": {
            "type": "securestring", "defaultValue": "",
            "metadata": {"description": "Optional PhishTank application key to raise the rate limit. Leave blank to use the unauthenticated limit."},
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
                "hidden-SentinelTemplateName": "Enrich-URL-IncidentComment",
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
                    "EnableMicrosoftThreatIntelligence": {"value": "[parameters('EnableMicrosoftThreatIntelligence')]"},
                    "EnableDefenderAdvancedHunting": {"value": "[parameters('EnableDefenderAdvancedHunting')]"},
                    "DefenderLookbackDays": {"value": "[parameters('DefenderLookbackDays')]"},
                    "URLContextWatchlistAlias": {"value": "[parameters('URLContextWatchlistAlias')]"},
                    "VirusTotalApiKey": {"value": "[parameters('VirusTotalApiKey')]"},
                    "GoogleSafeBrowsingApiKey": {"value": "[parameters('GoogleSafeBrowsingApiKey')]"},
                    "EnableUrlscanSearch": {"value": "[parameters('EnableUrlscanSearch')]"},
                    "UrlscanApiKey": {"value": "[parameters('UrlscanApiKey')]"},
                    "EnablePhishTank": {"value": "[parameters('EnablePhishTank')]"},
                    "PhishTankAppKey": {"value": "[parameters('PhishTankAppKey')]"},
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


output = pathlib.Path(__file__).parent / "azuredeploy-url.json"
output.write_text(json.dumps(template, indent=2), encoding="utf-8")
print(f"wrote {output} ({output.stat().st_size} bytes)")

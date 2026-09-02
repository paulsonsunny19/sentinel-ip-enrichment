#!/usr/bin/env python3
"""Generate azuredeploy-device.json for the Sentinel device-enrichment playbook."""

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


HOST_NAME = "@{string(coalesce(items('For_each_host_entity')?['HostName'], items('For_each_host_entity')?['NetBiosName'], 'unknown'))}"
KQL_HOST = "@{replace(toLower(string(coalesce(items('For_each_host_entity')?['HostName'], items('For_each_host_entity')?['NetBiosName'], ''))), decodeUriComponent('%27'), '')}"
KQL_DOMAIN = "@{replace(toLower(string(coalesce(items('For_each_host_entity')?['DnsDomain'], ''))), decodeUriComponent('%27'), '')}"
KQL_AZURE_ID = "@{replace(toLower(string(coalesce(items('For_each_host_entity')?['AzureID'], ''))), decodeUriComponent('%27'), '')}"


DEFENDER_KQL = f"""let host = '{KQL_HOST}';
let domain = '{KQL_DOMAIN}';
let azureId = '{KQL_AZURE_ID}';
let shortName = tostring(split(host, '.')[0]);
let fqdn = iff(isempty(domain) or host contains '.', host, strcat(host, '.', domain));
let look = @{{parameters('DefenderLookbackDays')}}d;
let Candidates = materialize(
    DeviceInfo
    | where Timestamp > ago(30d)
    | extend NormalizedName = tolower(DeviceName),
             NormalizedShortName = tolower(tostring(split(DeviceName, '.')[0])),
             NormalizedAzureResourceId = tolower(tostring(column_ifexists('AzureResourceId', '')))
    | where NormalizedName == fqdn or NormalizedName == host or NormalizedShortName == shortName
        or (isnotempty(azureId) and NormalizedAzureResourceId == azureId)
    | summarize arg_max(Timestamp, *) by DeviceId
    | extend MatchRank = case(isnotempty(azureId) and NormalizedAzureResourceId == azureId, 4,
                              NormalizedName == fqdn, 3, NormalizedName == host, 2,
                              NormalizedShortName == shortName, 1, 0)
    | sort by MatchRank desc, Timestamp desc
    | take 1);
let DeviceIds = Candidates | project DeviceId;
let AlertSummary = AlertEvidence
    | where Timestamp > ago(look)
    | where DeviceId in (DeviceIds)
    | summarize Alerts=dcount(AlertId),
                HighSeverityAlerts=dcountif(AlertId, tolower(Severity) == 'high'),
                MediumSeverityAlerts=dcountif(AlertId, tolower(Severity) == 'medium'),
                AlertTitles=make_set(Title, 10), AlertSeverities=make_set(Severity, 5),
                AlertSources=make_set(ServiceSource, 6), AttackTechniques=make_set(AttackTechniques, 10),
                LastAlert=max(Timestamp);
let VulnerabilitySummary = DeviceTvmSoftwareVulnerabilities
    | where DeviceId in (DeviceIds)
    | summarize Vulnerabilities=dcount(CveId),
                CriticalVulnerabilities=dcountif(CveId, tolower(VulnerabilitySeverityLevel) == 'critical'),
                HighVulnerabilities=dcountif(CveId, tolower(VulnerabilitySeverityLevel) == 'high'),
                MediumVulnerabilities=dcountif(CveId, tolower(VulnerabilitySeverityLevel) == 'medium'),
                ZeroDayVulnerabilities=dcountif(CveId, tostring(CveTags) has 'ZeroDay'),
                NoSecurityUpdateVulnerabilities=dcountif(CveId, tostring(CveTags) has 'NoSecurityUpdate');
let TopVulnerabilitySummary = DeviceTvmSoftwareVulnerabilities
    | where DeviceId in (DeviceIds)
    | extend SeverityRank=case(tolower(VulnerabilitySeverityLevel) == 'critical', 4,
                               tolower(VulnerabilitySeverityLevel) == 'high', 3,
                               tolower(VulnerabilitySeverityLevel) == 'medium', 2, 1)
    | sort by SeverityRank desc, CveId asc
    | take 10
    | summarize Values=make_list(strcat(CveId, ' (', VulnerabilitySeverityLevel, ') - ', SoftwareName, ' ', SoftwareVersion), 10);
let LatestConfigurations = DeviceTvmSecureConfigurationAssessment
    | where DeviceId in (DeviceIds)
    | summarize arg_max(Timestamp, *) by DeviceId, ConfigurationId;
let ConfigurationSummary = LatestConfigurations
    | summarize ConfigurationGaps=countif(IsApplicable == true and IsCompliant == false),
                HighImpactConfigurationGaps=countif(IsApplicable == true and IsCompliant == false and ConfigurationImpact >= 7.0),
                ConfigurationCategories=make_set_if(ConfigurationSubcategory, IsApplicable == true and IsCompliant == false, 10);
let TopConfigurationGapSummary = LatestConfigurations
    | where IsApplicable == true and IsCompliant == false
    | sort by ConfigurationImpact desc
    | take 8
    | summarize Values=make_list(strcat(ConfigurationSubcategory, ' [', ConfigurationId, '] impact ', tostring(ConfigurationImpact)), 8);
let LogonSummary = DeviceLogonEvents
    | where Timestamp > ago(look)
    | where DeviceId in (DeviceIds)
    | summarize Logons=count(), FailedLogons=countif(isnotempty(FailureReason) or ActionType has 'Fail'),
                LogonAccounts=make_set(strcat(AccountDomain, '/', AccountName), 10),
                LocalAdminAccounts=make_set_if(strcat(AccountDomain, '/', AccountName), IsLocalAdmin == true, 10),
                LogonTypes=make_set(LogonType, 8), LogonRemoteIPs=make_set(RemoteIP, 10), LastLogon=max(Timestamp);
let IdentityLogonSummary = IdentityLogonEvents
    | where Timestamp > ago(look)
    | where tolower(DeviceName) == tolower(tostring(toscalar(Candidates | project DeviceName)))
        or tolower(DestinationDeviceName) == tolower(tostring(toscalar(Candidates | project DeviceName)))
    | summarize IdentityLogons=count(), IdentityFailedLogons=countif(isnotempty(FailureReason) or ActionType has 'Fail'),
                IdentityAccounts=make_set(coalesce(AccountUpn, AccountName), 10),
                IdentityProtocols=make_set(Protocol, 8), LastIdentityLogon=max(Timestamp);
let NetworkSummary = DeviceNetworkEvents
    | where Timestamp > ago(look)
    | where DeviceId in (DeviceIds)
    | summarize NetworkEvents=count(), PublicRemoteConnections=countif(RemoteIPType == 'Public'),
                RemoteIPs=make_set(RemoteIP, 12), RemoteUrls=make_set(RemoteUrl, 10),
                RemotePorts=make_set(RemotePort, 10), NetworkProcesses=make_set(InitiatingProcessFileName, 10),
                LastNetworkEvent=max(Timestamp);
let ProcessSummary = DeviceProcessEvents
    | where Timestamp > ago(look)
    | where DeviceId in (DeviceIds)
    | summarize ProcessEvents=count(), DistinctProcesses=dcount(FileName),
                PowerShellEvents=countif(FileName in~ ('powershell.exe', 'pwsh.exe', 'powershell_ise.exe')),
                ElevatedProcessEvents=countif(ProcessTokenElevation == 'TokenElevationTypeFull'),
                ProcessNames=make_set(FileName, 12), ProcessAccounts=make_set(coalesce(AccountUpn, AccountName), 10),
                LastProcessEvent=max(Timestamp);
let SecurityControlSummary = DeviceEvents
    | where Timestamp > ago(look)
    | where DeviceId in (DeviceIds)
    | where ActionType has_any ('Antivirus', 'Exploit', 'Tamper', 'NetworkProtection', 'SmartScreen', 'Asr', 'EDR')
    | summarize SecurityControlEvents=count(), SecurityControlActions=make_set(ActionType, 12),
                SecurityControlFiles=make_set(FileName, 10), LastSecurityControlEvent=max(Timestamp);
let NetworkInfoSummary = DeviceNetworkInfo
    | where Timestamp > ago(look)
    | where DeviceId in (DeviceIds)
    | summarize arg_max(Timestamp, *) by DeviceId, NetworkAdapterName
    | extend SafeNetworkAdapterDnsSuffix=tostring(column_ifexists('NetworkAdapterDnsSuffix', ''))
    | summarize LocalIPAddresses=make_set(IPAddresses, 10), MacAddresses=make_set(MacAddress, 10),
                ConnectedNetworks=make_set(ConnectedNetworks, 8),
                DnsSuffixes=make_set_if(SafeNetworkAdapterDnsSuffix, isnotempty(SafeNetworkAdapterDnsSuffix), 8);
Candidates
| extend Alerts=toint(coalesce(toscalar(AlertSummary | project Alerts), 0)),
         HighSeverityAlerts=toint(coalesce(toscalar(AlertSummary | project HighSeverityAlerts), 0)),
         MediumSeverityAlerts=toint(coalesce(toscalar(AlertSummary | project MediumSeverityAlerts), 0)),
         AlertTitles=tostring(coalesce(toscalar(AlertSummary | project AlertTitles), dynamic([]))),
         AlertSeverities=tostring(coalesce(toscalar(AlertSummary | project AlertSeverities), dynamic([]))),
         AlertSources=tostring(coalesce(toscalar(AlertSummary | project AlertSources), dynamic([]))),
         AttackTechniques=tostring(coalesce(toscalar(AlertSummary | project AttackTechniques), dynamic([]))),
         LastAlert=toscalar(AlertSummary | project LastAlert),
         Vulnerabilities=toint(coalesce(toscalar(VulnerabilitySummary | project Vulnerabilities), 0)),
         CriticalVulnerabilities=toint(coalesce(toscalar(VulnerabilitySummary | project CriticalVulnerabilities), 0)),
         HighVulnerabilities=toint(coalesce(toscalar(VulnerabilitySummary | project HighVulnerabilities), 0)),
         MediumVulnerabilities=toint(coalesce(toscalar(VulnerabilitySummary | project MediumVulnerabilities), 0)),
         ZeroDayVulnerabilities=toint(coalesce(toscalar(VulnerabilitySummary | project ZeroDayVulnerabilities), 0)),
         NoSecurityUpdateVulnerabilities=toint(coalesce(toscalar(VulnerabilitySummary | project NoSecurityUpdateVulnerabilities), 0)),
         TopVulnerabilities=tostring(coalesce(toscalar(TopVulnerabilitySummary | project Values), dynamic([]))),
         ConfigurationGaps=toint(coalesce(toscalar(ConfigurationSummary | project ConfigurationGaps), 0)),
         HighImpactConfigurationGaps=toint(coalesce(toscalar(ConfigurationSummary | project HighImpactConfigurationGaps), 0)),
         ConfigurationCategories=tostring(coalesce(toscalar(ConfigurationSummary | project ConfigurationCategories), dynamic([]))),
         TopConfigurationGaps=tostring(coalesce(toscalar(TopConfigurationGapSummary | project Values), dynamic([]))),
         Logons=toint(coalesce(toscalar(LogonSummary | project Logons), 0)),
         FailedLogons=toint(coalesce(toscalar(LogonSummary | project FailedLogons), 0)),
         LogonAccounts=tostring(coalesce(toscalar(LogonSummary | project LogonAccounts), dynamic([]))),
         LocalAdminAccounts=tostring(coalesce(toscalar(LogonSummary | project LocalAdminAccounts), dynamic([]))),
         LogonTypes=tostring(coalesce(toscalar(LogonSummary | project LogonTypes), dynamic([]))),
         LogonRemoteIPs=tostring(coalesce(toscalar(LogonSummary | project LogonRemoteIPs), dynamic([]))),
         LastLogon=toscalar(LogonSummary | project LastLogon),
         IdentityLogons=toint(coalesce(toscalar(IdentityLogonSummary | project IdentityLogons), 0)),
         IdentityFailedLogons=toint(coalesce(toscalar(IdentityLogonSummary | project IdentityFailedLogons), 0)),
         IdentityAccounts=tostring(coalesce(toscalar(IdentityLogonSummary | project IdentityAccounts), dynamic([]))),
         IdentityProtocols=tostring(coalesce(toscalar(IdentityLogonSummary | project IdentityProtocols), dynamic([]))),
         LastIdentityLogon=toscalar(IdentityLogonSummary | project LastIdentityLogon),
         NetworkEvents=toint(coalesce(toscalar(NetworkSummary | project NetworkEvents), 0)),
         PublicRemoteConnections=toint(coalesce(toscalar(NetworkSummary | project PublicRemoteConnections), 0)),
         RemoteIPs=tostring(coalesce(toscalar(NetworkSummary | project RemoteIPs), dynamic([]))),
         RemoteUrls=tostring(coalesce(toscalar(NetworkSummary | project RemoteUrls), dynamic([]))),
         RemotePorts=tostring(coalesce(toscalar(NetworkSummary | project RemotePorts), dynamic([]))),
         NetworkProcesses=tostring(coalesce(toscalar(NetworkSummary | project NetworkProcesses), dynamic([]))),
         LastNetworkEvent=toscalar(NetworkSummary | project LastNetworkEvent),
         ProcessEvents=toint(coalesce(toscalar(ProcessSummary | project ProcessEvents), 0)),
         DistinctProcesses=toint(coalesce(toscalar(ProcessSummary | project DistinctProcesses), 0)),
         PowerShellEvents=toint(coalesce(toscalar(ProcessSummary | project PowerShellEvents), 0)),
         ElevatedProcessEvents=toint(coalesce(toscalar(ProcessSummary | project ElevatedProcessEvents), 0)),
         ProcessNames=tostring(coalesce(toscalar(ProcessSummary | project ProcessNames), dynamic([]))),
         ProcessAccounts=tostring(coalesce(toscalar(ProcessSummary | project ProcessAccounts), dynamic([]))),
         LastProcessEvent=toscalar(ProcessSummary | project LastProcessEvent),
         SecurityControlEvents=toint(coalesce(toscalar(SecurityControlSummary | project SecurityControlEvents), 0)),
         SecurityControlActions=tostring(coalesce(toscalar(SecurityControlSummary | project SecurityControlActions), dynamic([]))),
         SecurityControlFiles=tostring(coalesce(toscalar(SecurityControlSummary | project SecurityControlFiles), dynamic([]))),
         LastSecurityControlEvent=toscalar(SecurityControlSummary | project LastSecurityControlEvent),
         LocalIPAddresses=tostring(coalesce(toscalar(NetworkInfoSummary | project LocalIPAddresses), dynamic([]))),
         MacAddresses=tostring(coalesce(toscalar(NetworkInfoSummary | project MacAddresses), dynamic([]))),
         ConnectedNetworks=tostring(coalesce(toscalar(NetworkInfoSummary | project ConnectedNetworks), dynamic([]))),
         DnsSuffixes=tostring(coalesce(toscalar(NetworkInfoSummary | project DnsSuffixes), dynamic([])))
| project DeviceId, DeviceName, LastSeen=Timestamp,
          ClientVersion=tostring(column_ifexists('ClientVersion', '')),
          PublicIP=tostring(column_ifexists('PublicIP', '')),
          OSPlatform=tostring(column_ifexists('OSPlatform', '')),
          OSVersion=tostring(column_ifexists('OSVersion', '')),
          OSBuild=tostring(column_ifexists('OSBuild', '')),
          OSArchitecture=tostring(column_ifexists('OSArchitecture', '')),
          OSDistribution=tostring(column_ifexists('OSDistribution', '')),
          OSVersionInfo=tostring(column_ifexists('OSVersionInfo', '')),
          DeviceCategory=tostring(column_ifexists('DeviceCategory', '')),
          DeviceType=tostring(column_ifexists('DeviceType', '')),
          DeviceSubtype=tostring(column_ifexists('DeviceSubtype', '')),
          Vendor=tostring(column_ifexists('Vendor', '')),
          Model=tostring(column_ifexists('Model', '')),
          IsAzureADJoined=tostring(column_ifexists('IsAzureADJoined', '')),
          JoinType=tostring(column_ifexists('JoinType', '')),
          AadDeviceId=tostring(column_ifexists('AadDeviceId', '')),
          LoggedOnUsers=tostring(column_ifexists('LoggedOnUsers', '')),
          MachineGroup=tostring(column_ifexists('MachineGroup', '')),
          OnboardingStatus=tostring(column_ifexists('OnboardingStatus', '')),
          SensorHealthState=tostring(column_ifexists('SensorHealthState', '')),
          ExposureLevel=tostring(column_ifexists('ExposureLevel', '')),
          AssetValue=tostring(column_ifexists('AssetValue', '')),
          IsInternetFacing=tostring(column_ifexists('IsInternetFacing', '')),
          IsExcluded=tostring(column_ifexists('IsExcluded', '')),
          ExclusionReason=tostring(column_ifexists('ExclusionReason', '')),
          MitigationStatus=tostring(column_ifexists('MitigationStatus', '')),
          RegistryDeviceTag=tostring(column_ifexists('RegistryDeviceTag', '')),
          DeviceManualTags=tostring(column_ifexists('DeviceManualTags', '')),
          DeviceDynamicTags=tostring(column_ifexists('DeviceDynamicTags', '')),
          ConnectivityType=tostring(column_ifexists('ConnectivityType', '')),
          AzureResourceId=tostring(column_ifexists('AzureResourceId', '')),
          CloudPlatforms=tostring(column_ifexists('CloudPlatforms', '')),
          Site=tostring(column_ifexists('Site', '')),
          LocalIPAddresses, MacAddresses,
          ConnectedNetworks, DnsSuffixes, Alerts, HighSeverityAlerts, MediumSeverityAlerts, AlertTitles,
          AlertSeverities, AlertSources, AttackTechniques, LastAlert, Vulnerabilities, CriticalVulnerabilities,
          HighVulnerabilities, MediumVulnerabilities, ZeroDayVulnerabilities, NoSecurityUpdateVulnerabilities,
          TopVulnerabilities, ConfigurationGaps, HighImpactConfigurationGaps, ConfigurationCategories,
          TopConfigurationGaps, Logons, FailedLogons, LogonAccounts, LocalAdminAccounts, LogonTypes,
          LogonRemoteIPs, LastLogon, IdentityLogons, IdentityFailedLogons, IdentityAccounts,
          IdentityProtocols, LastIdentityLogon, NetworkEvents, PublicRemoteConnections, RemoteIPs,
          RemoteUrls, RemotePorts, NetworkProcesses, LastNetworkEvent, ProcessEvents, DistinctProcesses,
          PowerShellEvents, ElevatedProcessEvents, ProcessNames, ProcessAccounts, LastProcessEvent,
          SecurityControlEvents, SecurityControlActions, SecurityControlFiles, LastSecurityControlEvent"""


WORKSPACE_KQL = f"""let host = '{KQL_HOST}';
let domain = '{KQL_DOMAIN}';
let fqdn = iff(isempty(domain) or host contains '.', host, strcat(host, '.', domain));
let azureId = '{KQL_AZURE_ID}';
let look = @{{parameters('LookbackDays')}}d;
let watchAlias = '@{{replace(parameters('DeviceContextWatchlistAlias'), decodeUriComponent('%27'), '')}}';
let ClientContext = union isfuzzy=true
(Watchlist
 | where isnotempty(watchAlias) and WatchlistAlias == watchAlias
 | where tolower(SearchKey) == host or tolower(SearchKey) == fqdn
 | summarize arg_max(TimeGenerated, *) by SearchKey
 | extend W=todynamic(WatchlistItem)
 | extend Classification=tolower(coalesce(tostring(W.Classification), tostring(W.Criticality), 'unclassified'))
 | project Source=iff(Classification in ('critical', 'crown-jewel', 'high', 'knownbad', 'compromised'), 'Client device context - critical', 'Client device context'),
           Detail=strcat('classification: ', Classification, ' | owner: ', coalesce(tostring(W.Owner), 'n/a'),
                         ' | environment: ', coalesce(tostring(W.Environment), 'n/a'),
                         ' | function: ', coalesce(tostring(W.BusinessFunction), 'n/a'),
                         ' | patch group: ', coalesce(tostring(W.PatchGroup), 'n/a'),
                         ' | notes: ', coalesce(tostring(W.Description), tostring(W.Notes), 'none')),
           Last=coalesce(LastUpdatedTimeUTC, TimeGenerated));
let Alerts = union isfuzzy=true
(SecurityAlert
 | where TimeGenerated > ago(look)
 | extend EntityText=tolower(tostring(Entities)), Compromised=tolower(tostring(CompromisedEntity))
 | where Compromised in (host, fqdn) or EntityText has host
 | summarize AlertCount=count(), High=countif(tolower(AlertSeverity) == 'high'),
             Names=make_set(AlertName, 10), Severities=make_set(AlertSeverity, 5),
             Products=make_set(ProductName, 6), Last=max(TimeGenerated)
 | where AlertCount > 0
 | project Source=iff(High > 0, 'Sentinel high alert', 'Sentinel alerts'),
           Detail=strcat(AlertCount, ' alert(s), ', High, ' high | ', tostring(Names),
                         ' | severity: ', tostring(Severities), ' | products: ', tostring(Products)), Last);
let Endpoint = union isfuzzy=true
(SecurityEvent
 | where TimeGenerated > ago(look)
 | where tolower(Computer) in (host, fqdn) or tolower(tostring(split(Computer, '.')[0])) == tostring(split(host, '.')[0])
 | summarize Events=count(), EventIds=make_set(EventID, 12), Accounts=make_set(coalesce(TargetUserName, SubjectUserName), 10), Last=max(TimeGenerated)
 | where Events > 0
 | project Source='SecurityEvent', Detail=strcat(Events, ' event(s) | IDs: ', tostring(EventIds), ' | accounts: ', tostring(Accounts)), Last),
(WindowsEvent
 | where TimeGenerated > ago(look)
 | where tolower(Computer) in (host, fqdn) or tolower(tostring(split(Computer, '.')[0])) == tostring(split(host, '.')[0])
 | summarize Events=count(), EventIds=make_set(EventID, 12), Providers=make_set(Provider, 8), Last=max(TimeGenerated)
 | where Events > 0
 | project Source='WindowsEvent', Detail=strcat(Events, ' event(s) | IDs: ', tostring(EventIds), ' | providers: ', tostring(Providers)), Last),
(Syslog
 | where TimeGenerated > ago(look)
 | where tolower(Computer) in (host, fqdn) or tolower(tostring(split(Computer, '.')[0])) == tostring(split(host, '.')[0])
 | summarize Events=count(), Facilities=make_set(Facility, 8), Severities=make_set(SeverityLevel, 8), Processes=make_set(ProcessName, 10), Last=max(TimeGenerated)
 | where Events > 0
 | project Source='Syslog', Detail=strcat(Events, ' event(s) | facilities: ', tostring(Facilities), ' | severity: ', tostring(Severities), ' | processes: ', tostring(Processes)), Last),
(Heartbeat
 | where TimeGenerated > ago(look)
 | where tolower(Computer) in (host, fqdn) or tolower(tostring(split(Computer, '.')[0])) == tostring(split(host, '.')[0])
 | extend HBOS=tostring(column_ifexists('OSName', '')), HBVersion=tostring(column_ifexists('OSVersion', '')),
          HBAgent=tostring(column_ifexists('AgentVersion', '')), HBIP=tostring(column_ifexists('ComputerIP', ''))
 | summarize Last=max(TimeGenerated), OS=take_any(HBOS), Version=take_any(HBVersion),
             Agent=take_any(HBAgent), IP=take_any(HBIP), Solutions=make_set(Solutions, 8)
 | where isnotempty(Last)
 | project Source='Heartbeat', Detail=strcat('last heartbeat | OS: ', OS, ' ', Version, ' | agent: ', Agent,
                                             ' | IP: ', IP, ' | solutions: ', tostring(Solutions)), Last),
(SigninLogs
 | where TimeGenerated > ago(look)
 | extend D=parse_json(tostring(DeviceDetail)), SigninDevice=tolower(tostring(D.displayName))
 | where SigninDevice in (host, fqdn) or tostring(split(SigninDevice, '.')[0]) == tostring(split(host, '.')[0])
 | summarize Signins=count(), Failures=countif(ResultType != '0'), Users=make_set(UserPrincipalName, 10),
             Apps=make_set(AppDisplayName, 8), Risk=make_set(RiskLevelDuringSignIn, 5), Last=max(TimeGenerated)
 | where Signins > 0
 | project Source='Entra device sign-ins', Detail=strcat(Signins, ' sign-in(s), ', Failures, ' failed | users: ',
                           tostring(Users), ' | apps: ', tostring(Apps), ' | risk: ', tostring(Risk)), Last),
(AzureActivity
 | where TimeGenerated > ago(look)
 | extend ActivityResource=tolower(coalesce(tostring(column_ifexists('_ResourceId', '')), tostring(column_ifexists('ResourceId', ''))))
 | where isnotempty(azureId) and ActivityResource == azureId
 | summarize Operations=count(), Callers=make_set(Caller, 8), Names=make_set(OperationNameValue, 10), Last=max(TimeGenerated)
 | where Operations > 0
 | project Source='Azure resource activity', Detail=strcat(Operations, ' operation(s) | callers: ', tostring(Callers), ' | operations: ', tostring(Names)), Last);
union isfuzzy=true ClientContext, Alerts, Endpoint
| where isnotempty(Source)
| order by Last desc
| take 50"""


TH = "text-align:left;padding:4px 10px;background:#f3f2f1;border:1px solid #e1dfdd;font-weight:600;white-space:nowrap"
TD = "padding:4px 10px;border:1px solid #e1dfdd;vertical-align:top;word-break:break-word;overflow-wrap:anywhere;"
TBL = "border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:12px;width:100%"
H4 = "margin:12px 0 4px 0;font-family:Segoe UI,Arial,sans-serif;font-size:13px"


def host_value(field, default="n/a"):
    return "@{string(coalesce(items('For_each_host_entity')?['%s'], '%s'))}" % (field, default)


def defender_value(field, default="n/a"):
    return "@{string(coalesce(variables('DefenderJson')?['%s'], '%s'))}" % (field, default)


HEADER = (
    '<div style="font-family:Segoe UI,Arial,sans-serif;font-size:12px;color:#605e5c">'
    "Automated device enrichment &mdash; playbook <b>@{workflow()?['name']}</b> "
    "&middot; run @{formatDateTime(utcNow(), 'yyyy-MM-dd HH:mm')} UTC</div>"
)


DEFENDER_FOUND_BLOCK = f"""<div style="{H4}"><b>Defender XDR device profile</b> <span style="font-weight:400;color:#605e5c">(direct Microsoft Graph Advanced Hunting)</span></div>
<table style="{TBL}">
<tr><th style="{TH}">Defender device</th><td style="{TD}"><a href="https://security.microsoft.com/machines/{defender_value('DeviceId')}">{defender_value('DeviceName')}</a></td><th style="{TH}">Device ID</th><td style="{TD}"><code>{defender_value('DeviceId')}</code></td></tr>
<tr><th style="{TH}">OS</th><td style="{TD}">{defender_value('OSPlatform')} {defender_value('OSVersion')} (build {defender_value('OSBuild')}, {defender_value('OSArchitecture')})</td><th style="{TH}">Type</th><td style="{TD}">{defender_value('DeviceCategory')} / {defender_value('DeviceType')} / {defender_value('DeviceSubtype')}</td></tr>
<tr><th style="{TH}">Vendor / model</th><td style="{TD}">{defender_value('Vendor')} / {defender_value('Model')}</td><th style="{TH}">Last seen</th><td style="{TD}">{defender_value('LastSeen')}</td></tr>
<tr><th style="{TH}">Onboarding / sensor</th><td style="{TD}"><b>{defender_value('OnboardingStatus')}</b> / <b>{defender_value('SensorHealthState')}</b></td><th style="{TH}">Agent / connectivity</th><td style="{TD}">{defender_value('ClientVersion')} / {defender_value('ConnectivityType')}</td></tr>
<tr><th style="{TH}">Exposure / asset value</th><td style="{TD}"><b>{defender_value('ExposureLevel')}</b> / {defender_value('AssetValue')}</td><th style="{TH}">Internet-facing</th><td style="{TD}"><b>{defender_value('IsInternetFacing','false')}</b> &nbsp;|&nbsp; public IP: {defender_value('PublicIP')}</td></tr>
<tr><th style="{TH}">Entra join</th><td style="{TD}">{defender_value('IsAzureADJoined','false')} / {defender_value('JoinType')} &nbsp;|&nbsp; ID: <code>{defender_value('AadDeviceId')}</code></td><th style="{TH}">Machine group / site</th><td style="{TD}">{defender_value('MachineGroup')} / {defender_value('Site')}</td></tr>
<tr><th style="{TH}">Cloud resource</th><td style="{TD}" colspan="3">{defender_value('CloudPlatforms')} &nbsp;|&nbsp; <code>{defender_value('AzureResourceId')}</code></td></tr>
<tr><th style="{TH}">Local addresses</th><td style="{TD}" colspan="3">{defender_value('LocalIPAddresses','[]')} &nbsp;|&nbsp; MAC: {defender_value('MacAddresses','[]')}</td></tr>
<tr><th style="{TH}">Logged-on users</th><td style="{TD}" colspan="3">{defender_value('LoggedOnUsers','[]')}</td></tr>
<tr><th style="{TH}">Tags</th><td style="{TD}" colspan="3">registry: {defender_value('RegistryDeviceTag')} &nbsp;|&nbsp; manual: {defender_value('DeviceManualTags')} &nbsp;|&nbsp; dynamic: {defender_value('DeviceDynamicTags')}</td></tr>
</table>

<div style="{H4}"><b>Defender alerts and recent activity &mdash; last @{{parameters('DefenderLookbackDays')}} days</b></div>
<table style="{TBL}">
<tr><th style="{TH}">Alerts</th><td style="{TD}"><b>{defender_value('Alerts','0')}</b> total &nbsp;|&nbsp; <b>{defender_value('HighSeverityAlerts','0')}</b> high &nbsp;|&nbsp; {defender_value('MediumSeverityAlerts','0')} medium</td><th style="{TH}">Last alert</th><td style="{TD}">{defender_value('LastAlert')}</td></tr>
<tr><th style="{TH}">Alert titles</th><td style="{TD}" colspan="3">{defender_value('AlertTitles','[]')} &nbsp;|&nbsp; techniques: {defender_value('AttackTechniques','[]')}</td></tr>
<tr><th style="{TH}">Endpoint logons</th><td style="{TD}">{defender_value('Logons','0')} total / <b>{defender_value('FailedLogons','0')} failed</b> &nbsp;|&nbsp; types: {defender_value('LogonTypes','[]')}</td><th style="{TH}">Last logon</th><td style="{TD}">{defender_value('LastLogon')}</td></tr>
<tr><th style="{TH}">Logon accounts</th><td style="{TD}" colspan="3">{defender_value('LogonAccounts','[]')} &nbsp;|&nbsp; local admins: {defender_value('LocalAdminAccounts','[]')} &nbsp;|&nbsp; remote IPs: {defender_value('LogonRemoteIPs','[]')}</td></tr>
<tr><th style="{TH}">Identity logons</th><td style="{TD}">{defender_value('IdentityLogons','0')} total / <b>{defender_value('IdentityFailedLogons','0')} failed</b> &nbsp;|&nbsp; accounts: {defender_value('IdentityAccounts','[]')}</td><th style="{TH}">Protocols</th><td style="{TD}">{defender_value('IdentityProtocols','[]')}</td></tr>
<tr><th style="{TH}">Network</th><td style="{TD}">{defender_value('NetworkEvents','0')} event(s), {defender_value('PublicRemoteConnections','0')} public remote &nbsp;|&nbsp; IPs: {defender_value('RemoteIPs','[]')}</td><th style="{TH}">Last network event</th><td style="{TD}">{defender_value('LastNetworkEvent')}</td></tr>
<tr><th style="{TH}">Processes</th><td style="{TD}">{defender_value('ProcessEvents','0')} event(s), {defender_value('DistinctProcesses','0')} distinct, {defender_value('PowerShellEvents','0')} PowerShell, {defender_value('ElevatedProcessEvents','0')} elevated &nbsp;|&nbsp; {defender_value('ProcessNames','[]')}</td><th style="{TH}">Last process</th><td style="{TD}">{defender_value('LastProcessEvent')}</td></tr>
<tr><th style="{TH}">Security controls</th><td style="{TD}" colspan="3">{defender_value('SecurityControlEvents','0')} event(s) &nbsp;|&nbsp; actions: {defender_value('SecurityControlActions','[]')} &nbsp;|&nbsp; files: {defender_value('SecurityControlFiles','[]')}</td></tr>
</table>

<div style="{H4}"><b>Defender Vulnerability Management posture</b></div>
<table style="{TBL}">
<tr><th style="{TH}">Vulnerabilities</th><td style="{TD}"><b>{defender_value('CriticalVulnerabilities','0')} critical</b> / <b>{defender_value('HighVulnerabilities','0')} high</b> / {defender_value('MediumVulnerabilities','0')} medium / {defender_value('Vulnerabilities','0')} unique total</td><th style="{TH}">Special tags</th><td style="{TD}">{defender_value('ZeroDayVulnerabilities','0')} zero-day / {defender_value('NoSecurityUpdateVulnerabilities','0')} without security update</td></tr>
<tr><th style="{TH}">Top vulnerabilities</th><td style="{TD}" colspan="3">{defender_value('TopVulnerabilities','[]')}</td></tr>
<tr><th style="{TH}">Configuration gaps</th><td style="{TD}"><b>{defender_value('HighImpactConfigurationGaps','0')} high-impact</b> / {defender_value('ConfigurationGaps','0')} total</td><th style="{TH}">Categories</th><td style="{TD}">{defender_value('ConfigurationCategories','[]')}</td></tr>
<tr><th style="{TH}">Top configuration gaps</th><td style="{TD}" colspan="3">{defender_value('TopConfigurationGaps','[]')}</td></tr>
</table>"""


DEFENDER_UNAVAILABLE_BLOCK = f"""<div style="{H4}"><b>Defender XDR device enrichment</b></div>
<table style="{TBL}"><tr><td style="{TD}">Status: <b>@{{variables('DefenderStatus')}}</b>. If unavailable, confirm the Logic App managed identity has Microsoft Graph application permission <b>ThreatHunting.Read.All</b>, Defender for Endpoint is deployed, the device is onboarded, and the tenant has hunting quota available. Sentinel workspace enrichment continues independently.</td></tr></table>"""


CHIP = "display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;color:#ffffff;margin-left:6px;background:"
VERDICT_STYLE = (
    "@if(equals(outputs('Compose_Verdict'), 'HIGH'), '%s#a4262c', "
    "if(equals(outputs('Compose_Verdict'), 'MEDIUM'), '%s#986f0b', "
    "if(equals(outputs('Compose_Verdict'), 'LOW'), '%s#107c10', '%s#605e5c')))"
    % (CHIP, CHIP, CHIP, CHIP)
)


VERDICT = (
    "@if(or("
    "greater(int(coalesce(variables('DefenderJson')?['HighSeverityAlerts'], 0)), 0), "
    "greater(int(coalesce(variables('DefenderJson')?['CriticalVulnerabilities'], 0)), 0), "
    "and(equals(toLower(string(coalesce(variables('DefenderJson')?['ExposureLevel'], ''))), 'high'), "
    "equals(toLower(string(coalesce(variables('DefenderJson')?['IsInternetFacing'], 'false'))), 'true')), "
    "greater(length(body('Filter_High_Workspace_Alerts')), 0)), 'HIGH', "
    "if(or("
    "greater(int(coalesce(variables('DefenderJson')?['MediumSeverityAlerts'], 0)), 0), "
    "greater(int(coalesce(variables('DefenderJson')?['HighVulnerabilities'], 0)), 0), "
    "greater(int(coalesce(variables('DefenderJson')?['HighImpactConfigurationGaps'], 0)), 0), "
    "equals(toLower(string(coalesce(variables('DefenderJson')?['ExposureLevel'], ''))), 'high'), "
    "equals(toLower(string(coalesce(variables('DefenderJson')?['ExposureLevel'], ''))), 'medium'), "
    "equals(toLower(string(coalesce(variables('DefenderJson')?['IsInternetFacing'], 'false'))), 'true'), "
    "and(not(empty(string(coalesce(variables('DefenderJson')?['SensorHealthState'], '')))), "
    "not(equals(toLower(string(variables('DefenderJson')?['SensorHealthState'])), 'active'))), "
    "and(not(empty(string(coalesce(variables('DefenderJson')?['OnboardingStatus'], '')))), "
    "not(equals(toLower(string(variables('DefenderJson')?['OnboardingStatus'])), 'onboarded'))), "
    "greater(length(body('Filter_Critical_Client_Context')), 0)), 'MEDIUM', "
    "if(and(empty(variables('DefenderJson')), empty(outputs('Compose_Workspace_Rows'))), 'UNKNOWN', 'LOW')))"
)


VERDICT_REASON = (
    "@concat('Defender status: ', variables('DefenderStatus'), "
    "' &middot; alerts H/M: ', string(coalesce(variables('DefenderJson')?['HighSeverityAlerts'], 0)), '/', "
    "string(coalesce(variables('DefenderJson')?['MediumSeverityAlerts'], 0)), "
    "' &middot; vulnerabilities C/H: ', string(coalesce(variables('DefenderJson')?['CriticalVulnerabilities'], 0)), '/', "
    "string(coalesce(variables('DefenderJson')?['HighVulnerabilities'], 0)), "
    "' &middot; exposure: ', string(coalesce(variables('DefenderJson')?['ExposureLevel'], 'unknown')), "
    "' &middot; internet-facing: ', string(coalesce(variables('DefenderJson')?['IsInternetFacing'], 'unknown')), "
    "' &middot; ', string(length(outputs('Compose_Workspace_Rows'))), ' workspace insight row(s)')"
)


DEVICE_BLOCK = f"""<hr style="border:0;border-top:1px solid #e1dfdd;margin:16px 0">
<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;font-weight:600;margin-bottom:6px">
Device enrichment &mdash; <code>{HOST_NAME}</code>
<span style="@{{outputs('Compose_VerdictStyle')}}">@{{outputs('Compose_Verdict')}}</span>
</div>
<div style="font-family:Segoe UI,Arial,sans-serif;font-size:11px;color:#605e5c;margin-bottom:10px">@{{outputs('Compose_VerdictReason')}}</div>

<div style="{H4}"><b>Sentinel host entity</b></div>
<table style="{TBL}">
<tr><th style="{TH}">Hostname</th><td style="{TD}">{host_value('HostName')}</td><th style="{TH}">DNS / NT domain</th><td style="{TD}">{host_value('DnsDomain')} / {host_value('NTDomain')}</td></tr>
<tr><th style="{TH}">NetBIOS</th><td style="{TD}">{host_value('NetBiosName')}</td><th style="{TH}">OS</th><td style="{TD}">{host_value('OSFamily')} {host_value('OSVersion')}</td></tr>
<tr><th style="{TH}">Domain joined</th><td style="{TD}">{host_value('IsDomainJoined','unknown')}</td><th style="{TH}">OMS agent ID</th><td style="{TD}"><code>{host_value('OMSAgentID')}</code></td></tr>
<tr><th style="{TH}">Azure resource ID</th><td style="{TD}" colspan="3"><code>{host_value('AzureID')}</code></td></tr>
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
        "DeviceContextWatchlistAlias": {"type": "String", "defaultValue": "DeviceContext"},
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
        "Entities_-_Get_Hosts": {
            "runAfter": after("Init_DefenderHtml"), "type": "ApiConnection",
            "inputs": {
                "host": {"connection": {"name": SENTINEL_CONN}},
                "method": "post",
                "body": "@triggerBody()?['object']?['properties']?['relatedEntities']",
                "path": "/entities/host",
            },
        },
        "For_each_host_entity": {
            "foreach": "@body('Entities_-_Get_Hosts')?['Hosts']",
            "runAfter": after("Entities_-_Get_Hosts"),
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
                "Condition_Defender_XDR_enabled": {
                    "runAfter": after("Reset_DefenderHtml"), "type": "If",
                    "expression": {"and": [{"equals": ["@parameters('EnableDefenderAdvancedHunting')", True]}]},
                    "actions": {
                        "HTTP_Defender_XDR_Device_Hunting": {
                            "runAfter": {}, "type": "Http",
                            "inputs": {
                                "method": "POST",
                                "uri": "https://graph.microsoft.com/v1.0/security/runHuntingQuery",
                                "headers": {"Content-Type": "application/json; charset=utf-8"},
                                "body": {
                                    "Query": DEFENDER_KQL,
                                    "Timespan": "P30D",
                                },
                                "authentication": MICROSOFT_GRAPH_MANAGED_IDENTITY_AUTH,
                            },
                            "runtimeConfiguration": {"secureData": {"properties": ["inputs", "outputs"]}},
                        },
                        "Compose_Defender_Rows": {
                            "runAfter": after("HTTP_Defender_XDR_Device_Hunting", states=("Succeeded", "Failed", "TimedOut")),
                            "type": "Compose",
                            "inputs": (
                                "@if(equals(outputs('HTTP_Defender_XDR_Device_Hunting')?['statusCode'], 200), "
                                "coalesce(body('HTTP_Defender_XDR_Device_Hunting')?['results'], json('[]')), json('[]'))"
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
                                    "@if(not(equals(outputs('HTTP_Defender_XDR_Device_Hunting')?['statusCode'], 200)), "
                                    "concat('unavailable (HTTP ', string(coalesce(outputs('HTTP_Defender_XDR_Device_Hunting')?['statusCode'], 'no response')), ')'), "
                                    "if(greater(length(outputs('Compose_Defender_Rows')), 0), 'found', 'not found'))"
                                ),
                            },
                        },
                    },
                    "else": {"actions": {}},
                },
                "Condition_Defender_result_found": {
                    "runAfter": after("Condition_Defender_XDR_enabled"), "type": "If",
                    "expression": {"and": [{"equals": ["@variables('DefenderStatus')", "found"]}]},
                    "actions": {
                        "Set_DefenderHtml_found": {
                            "runAfter": {}, "type": "SetVariable",
                            "inputs": {"name": "DefenderHtml", "value": DEFENDER_FOUND_BLOCK},
                        }
                    },
                    "else": {
                        "actions": {
                            "Set_DefenderHtml_unavailable": {
                                "runAfter": {}, "type": "SetVariable",
                                "inputs": {"name": "DefenderHtml", "value": DEFENDER_UNAVAILABLE_BLOCK},
                            }
                        }
                    },
                },
                "Run_KQL_workspace_context": {
                    "runAfter": after("Condition_Defender_result_found"), "type": "ApiConnection",
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
                "Filter_High_Workspace_Alerts": {
                    "runAfter": after("Compose_Workspace_Rows"), "type": "Query",
                    "inputs": {"from": "@outputs('Compose_Workspace_Rows')", "where": "@equals(item()?['Source'], 'Sentinel high alert')"},
                },
                "Filter_Critical_Client_Context": {
                    "runAfter": after("Filter_High_Workspace_Alerts"), "type": "Query",
                    "inputs": {"from": "@outputs('Compose_Workspace_Rows')", "where": "@equals(item()?['Source'], 'Client device context - critical')"},
                },
                "Select_Workspace_Rows": {
                    "runAfter": after("Filter_Critical_Client_Context"), "type": "Select",
                    "inputs": {
                        "from": "@outputs('Compose_Workspace_Rows')",
                        "select": (
                            f'<tr><td style="{TD}"><b>@{{item()?[\'Source\']}}</b></td>'
                            f'<td style="{TD}">@{{item()?[\'Detail\']}}</td>'
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
                    "inputs": HEADER + DEVICE_BLOCK,
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
        "title": "Enrich device entities and post a Sentinel incident comment",
        "description": "For each Host entity on a Microsoft Sentinel incident, correlates the host to Microsoft Defender XDR DeviceInfo and summarizes device inventory, EDR health, exposure, alerts, Vulnerability Management findings, configuration gaps, logons, identity authentication, network activity, processes and security-control events. It also queries Sentinel workspace telemetry and an optional client DeviceContext watchlist, calculates a HIGH/MEDIUM/LOW/UNKNOWN triage verdict, and posts one formatted incident comment.",
        "prerequisites": "A Microsoft Sentinel-enabled Log Analytics workspace. For direct Defender XDR enrichment, relevant Defender licensing/onboarding and Microsoft Graph application permission ThreatHunting.Read.All on the playbook managed identity are required.",
        "postDeployment": [
            "Grant the user-assigned managed identity Microsoft Sentinel Responder on the resource group holding the workspace.",
            "Grant the same identity Log Analytics Reader on the workspace.",
            "Grant the managed identity Microsoft Graph application permission ThreatHunting.Read.All using an app-role assignment and allow time for token propagation.",
            "Authorise the Microsoft Sentinel and Azure Monitor Logs API connections.",
            "Attach the playbook to a Sentinel incident automation rule, or run it on demand from an incident.",
        ],
        "lastUpdateTime": "2026-09-01",
        "entities": ["Host"],
        "tags": ["Enrichment", "Device", "Defender XDR", "Vulnerability Management"],
        "support": {"tier": "community"},
    },
    "parameters": {
        "PlaybookName": {
            "type": "string", "defaultValue": "Enrich-Device-IncidentComment",
            "metadata": {"description": "Name of the Logic App playbook."},
        },
        "UserAssignedManagedIdentityResourceId": {
            "type": "string",
            "minLength": 1,
            "metadata": {
                "description": "Required. Enter the full resource ID of the existing client-owned user-assigned managed identity used by the Logic App and all managed-identity connections."
            },
        },
        "WorkspaceName": {"type": "string", "metadata": {"description": "Log Analytics / Sentinel workspace name."}},
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
            "metadata": {"description": "Query Defender XDR Advanced Hunting directly through Microsoft Graph. Requires ThreatHunting.Read.All application permission."},
        },
        "DefenderLookbackDays": {
            "type": "int", "defaultValue": 14, "minValue": 1, "maxValue": 30,
            "metadata": {"description": "Defender Advanced Hunting activity lookback. Raw Defender hunting data is limited to 30 days."},
        },
        "DeviceContextWatchlistAlias": {
            "type": "string", "defaultValue": "DeviceContext",
            "metadata": {"description": "Optional client device watchlist alias. Set blank to disable."},
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
                "userAssignedIdentities": {
                    "[parameters('UserAssignedManagedIdentityResourceId')]": {}
                },
            },
            "tags": {
                "hidden-SentinelTemplateName": "Enrich-Device-IncidentComment",
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
                    "DeviceContextWatchlistAlias": {"value": "[parameters('DeviceContextWatchlistAlias')]"},
                    "WorkspaceSubscriptionId": {"value": "[parameters('WorkspaceSubscriptionId')]"},
                    "WorkspaceResourceGroup": {"value": "[parameters('WorkspaceResourceGroup')]"},
                    "WorkspaceName": {"value": "[parameters('WorkspaceName')]"},
                },
            },
        },
    ],
    "outputs": {
        "PlaybookResourceId": {"type": "string", "value": "[resourceId('Microsoft.Logic/workflows', parameters('PlaybookName'))]"},
        "ManagedIdentityType": {"type": "string", "value": "UserAssigned"},
        "ManagedIdentityResourceId": {
            "type": "string",
            "value": "[parameters('UserAssignedManagedIdentityResourceId')]",
        },
        "ManagedIdentityPrincipalId": {
            "type": "string",
            "value": "[reference(parameters('UserAssignedManagedIdentityResourceId'), '2018-11-30').principalId]",
        },
    },
}


output = pathlib.Path(__file__).parent / "azuredeploy-device.json"
output.write_text(json.dumps(template, indent=2), encoding="utf-8")
print(f"wrote {output} ({output.stat().st_size} bytes)")

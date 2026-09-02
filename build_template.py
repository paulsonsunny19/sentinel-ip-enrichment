#!/usr/bin/env python3
"""Generates azuredeploy.json for the Enrich-IP-IncidentComment Sentinel playbook."""
import json, pathlib


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
AZURE_MANAGEMENT_MANAGED_IDENTITY_AUTH = managed_identity_authentication(
    "https://management.azure.com"
)
MICROSOFT_GRAPH_MANAGED_IDENTITY_AUTH = managed_identity_authentication(
    "https://graph.microsoft.com"
)

IP = "@{items('For_each_IP_entity')?['Address']}"
KQL_IP = "@{replace(items('For_each_IP_entity')?['Address'], decodeUriComponent('%27'), '')}"
LOOK = "@{parameters('LookbackDays')}d"

KQL = f"""let ip = '{KQL_IP}';
let look = {LOOK};
let TI = union isfuzzy=true
(ThreatIntelligenceIndicator
 | where TimeGenerated > ago(30d)
 | where NetworkIP == ip or NetworkSourceIP == ip or NetworkDestinationIP == ip
 | where Active == true
 | summarize arg_max(TimeGenerated, *) by IndicatorId
 | project Source = 'Threat Intel', Detail = strcat('TI match - ', coalesce(Description, 'indicator'), ' | type: ', coalesce(ThreatType, 'n/a'), ' | confidence: ', tostring(ConfidenceScore), ' | feed: ', coalesce(SourceSystem, 'n/a')), Last = TimeGenerated),
(ThreatIntelIndicators
 | where TimeGenerated > ago(30d)
 | where ObservableValue == ip
 | summarize arg_max(TimeGenerated, *) by Id
 | project Source = 'Threat Intel', Detail = strcat('TI match - ', tostring(Data.description), ' | confidence: ', tostring(Confidence)), Last = TimeGenerated);
let Sightings = union isfuzzy=true
(SigninLogs | where TimeGenerated > ago(look) | where IPAddress == ip
 | summarize C = count(), U = dcount(UserPrincipalName), F = countif(ResultType != '0'), Users = make_set(UserPrincipalName, 50), Last = max(TimeGenerated)
 | where C > 0 | project Source = 'SigninLogs', Detail = strcat(C, ' sign-ins, ', U, ' user(s), ', F, ' failed | ', tostring(Users)), Last),
(AADNonInteractiveUserSignInLogs | where TimeGenerated > ago(look) | where IPAddress == ip
 | summarize C = count(), U = dcount(UserPrincipalName), Users = make_set(UserPrincipalName, 50), Last = max(TimeGenerated)
 | where C > 0 | project Source = 'NonInteractiveSignIn', Detail = strcat(C, ' sign-ins, ', U, ' user(s) | ', tostring(Users)), Last),
(AzureActivity | where TimeGenerated > ago(look) | where CallerIpAddress == ip
 | summarize C = count(), Callers = make_set(Caller, 5), Last = max(TimeGenerated)
 | where C > 0 | project Source = 'AzureActivity', Detail = strcat(C, ' operations | callers: ', tostring(Callers)), Last),
(OfficeActivity | where TimeGenerated > ago(look) | where ClientIP has ip
 | summarize C = count(), U = make_set(UserId, 5), Last = max(TimeGenerated)
 | where C > 0 | project Source = 'OfficeActivity', Detail = strcat(C, ' events | users: ', tostring(U)), Last),
(SecurityEvent | where TimeGenerated > ago(look) | where IpAddress == ip
 | summarize C = count(), Hosts = make_set(Computer, 5), Last = max(TimeGenerated)
 | where C > 0 | project Source = 'SecurityEvent', Detail = strcat(C, ' events | hosts: ', tostring(Hosts)), Last),
(CommonSecurityLog | where TimeGenerated > ago(look) | where SourceIP == ip or DestinationIP == ip
 | summarize C = count(), Dev = dcount(DeviceName), Act = make_set(DeviceAction, 5), Ports = make_set(DestinationPort, 8), Last = max(TimeGenerated)
 | where C > 0 | project Source = 'CommonSecurityLog', Detail = strcat(C, ' events across ', Dev, ' device(s) | actions: ', tostring(Act), ' | dst ports: ', tostring(Ports)), Last),
(DeviceNetworkEvents | where TimeGenerated > ago(look) | where RemoteIP == ip
 | summarize C = count(), Dev = make_set(DeviceName, 5), Proc = make_set(InitiatingProcessFileName, 5), Last = max(TimeGenerated)
 | where C > 0 | project Source = 'DeviceNetworkEvents', Detail = strcat(C, ' connections | devices: ', tostring(Dev), ' | processes: ', tostring(Proc)), Last),
(VMConnection | where TimeGenerated > ago(look) | where RemoteIp == ip
 | summarize C = count(), Dev = make_set(Computer, 5), Last = max(TimeGenerated)
 | where C > 0 | project Source = 'VMConnection', Detail = strcat(C, ' connections | hosts: ', tostring(Dev)), Last),
(W3CIISLog | where TimeGenerated > ago(look) | where cIP == ip
 | summarize C = count(), Sites = make_set(sSiteName, 5), Last = max(TimeGenerated)
 | where C > 0 | project Source = 'W3CIISLog', Detail = strcat(C, ' requests | sites: ', tostring(Sites)), Last),
(AWSCloudTrail | where TimeGenerated > ago(look) | where SourceIpAddress == ip
 | summarize C = count(), Users = make_set(UserIdentityArn, 5), Last = max(TimeGenerated)
 | where C > 0 | project Source = 'AWSCloudTrail', Detail = strcat(C, ' API calls | identities: ', tostring(Users)), Last);
let Alerts = union isfuzzy=true
(SecurityAlert | where TimeGenerated > ago(30d) | where Entities has ip
 | summarize C = count(), Names = make_set(AlertName, 5), Sev = make_set(AlertSeverity, 4), Last = max(TimeGenerated)
 | where C > 0 | project Source = 'Prior alerts', Detail = strcat(C, ' alert(s) in 30d | ', tostring(Names), ' | severity: ', tostring(Sev)), Last);
union isfuzzy=true TI, Sightings, Alerts
| where isnotempty(Source)
| order by Last desc
| take 60"""

EXTENDED_KQL = f"""let ip = '{KQL_IP}';
let watchAlias = '@{{replace(parameters('IPContextWatchlistAlias'), decodeUriComponent('%27'), '')}}';
let look = {LOOK};
let ClientContext = union isfuzzy=true
(Watchlist
 | where isnotempty(watchAlias)
 | where WatchlistAlias == watchAlias and SearchKey == ip
 | summarize arg_max(TimeGenerated, *) by SearchKey
 | extend W = todynamic(WatchlistItem)
 | extend Classification = coalesce(tostring(W.Classification), tostring(W.Category), 'unclassified')
 | project Source = iff(tolower(Classification) in ('knownbad', 'malicious', 'block'), 'Client IP context - high', 'Client IP context'),
           Detail = strcat('classification: ', Classification,
                           ' | owner: ', coalesce(tostring(W.Owner), 'n/a'),
                           ' | ', coalesce(tostring(W.Description), tostring(W.Notes), 'no description'),
                           ' | override: ', coalesce(tostring(W.RiskOverride), 'none'),
                           ' | valid until: ', coalesce(tostring(W.ValidUntil), 'not set')),
           Last = coalesce(LastUpdatedTimeUTC, TimeGenerated));
let Ueba = union isfuzzy=true
(BehaviorAnalytics
 | where TimeGenerated > ago(look)
 | where SourceIPAddress == ip or DestinationIPAddress == ip
 | top 5 by InvestigationPriority desc
 | project Source = iff(InvestigationPriority >= 8, 'UEBA high anomaly', 'UEBA'),
           Detail = strcat('priority ', InvestigationPriority, '/10 | ', ActivityType, ' / ', ActionType,
                           ' | user: ', coalesce(UserPrincipalName, UserName, 'n/a'),
                           ' | source: ', EventSource),
           Last = TimeGenerated);
let Network = union isfuzzy=true
(_Im_NetworkSession(starttime=ago(look), endtime=now(), ipaddr_has_any_prefix=pack_array(ip))
 | where SrcIpAddr == ip or DstIpAddr == ip
 | summarize C = sum(EventCount), Devices = make_set(coalesce(SrcHostname, DstHostname, Dvc), 5),
             Ports = make_set(DstPortNumber, 8), Actions = make_set(DvcAction, 5), Last = max(TimeGenerated)
 | where C > 0
 | project Source = 'ASIM network',
           Detail = strcat(C, ' session(s) | devices: ', tostring(Devices),
                           ' | destination ports: ', tostring(Ports), ' | actions: ', tostring(Actions)), Last);
let Dns = union isfuzzy=true
(_Im_Dns(starttime=ago(look), endtime=now(), response_has_ipv4=ip)
 | summarize C = count(), Domains = make_set(DnsQuery, 10),
             Clients = make_set(coalesce(SrcHostname, SrcIpAddr), 5), Last = max(TimeGenerated)
 | where C > 0
 | project Source = 'ASIM DNS',
           Detail = strcat(C, ' response(s) | domains: ', tostring(Domains),
                           ' | clients: ', tostring(Clients)), Last);
union isfuzzy=true ClientContext, Ueba, Network, Dns
| where isnotempty(Source)
| order by Last desc
| take 40"""

DEFENDER_KQL = f"""let ip = '{KQL_IP}';
let look = @{{parameters('DefenderLookbackDays')}}d;
union isfuzzy=true
(DeviceNetworkEvents
 | where Timestamp > ago(look)
 | where RemoteIP == ip or LocalIP == ip
 | summarize C = count(), LocalMatches = countif(LocalIP == ip), RemoteMatches = countif(RemoteIP == ip),
             Devices = make_set(DeviceName, 20), DeviceIds = make_set(DeviceId, 20),
             Processes = make_set(InitiatingProcessFileName, 12),
             Users = make_set(coalesce(InitiatingProcessAccountUpn, InitiatingProcessAccountName), 12),
             Ports = make_set(RemotePort, 10), Actions = make_set(ActionType, 6), Last = max(Timestamp)
 | project Source = 'Defender XDR - device network presence',
           Detail = strcat('Observed in DeviceNetworkEvents: ', iff(C > 0, 'YES', 'NO'),
                           ' | ', C, ' event(s), ', LocalMatches, ' local-IP match(es), ',
                           RemoteMatches, ' remote-IP match(es) | devices: ', tostring(Devices),
                           ' | device IDs: ', tostring(DeviceIds),
                           ' | processes: ', tostring(Processes), ' | users: ', tostring(Users),
                           ' | remote ports: ', tostring(Ports), ' | actions: ', tostring(Actions)), Last),
(DeviceLogonEvents
 | where Timestamp > ago(look)
 | where RemoteIP == ip
 | summarize C = count(), Failures = countif(isnotempty(FailureReason) or ActionType has 'Fail'),
             Devices = make_set(DeviceName, 5), Accounts = make_set(strcat(AccountDomain, '/', AccountName), 8),
             LogonTypes = make_set(LogonType, 6), Actions = make_set(ActionType, 6), Last = max(Timestamp)
 | where C > 0
 | project Source = 'Defender XDR - device logons',
           Detail = strcat(C, ' logon event(s), ', Failures, ' failed | devices: ', tostring(Devices),
                           ' | accounts: ', tostring(Accounts), ' | types: ', tostring(LogonTypes),
                           ' | actions: ', tostring(Actions)), Last),
(CloudAppEvents
 | where Timestamp > ago(look)
 | where IPAddress == ip
 | summarize C = count(), AdminOperations = countif(IsAdminOperation == true),
             ProxyEvents = countif(IsAnonymousProxy == true), Accounts = make_set(coalesce(AccountId, AccountDisplayName), 8),
             Applications = make_set(Application, 8), Activities = make_set(ActivityType, 8),
             Actions = make_set(ActionType, 8), Last = max(Timestamp)
 | where C > 0
 | project Source = 'Defender XDR - cloud apps',
           Detail = strcat(C, ' activity event(s), ', AdminOperations, ' admin operation(s), ', ProxyEvents,
                           ' anonymous-proxy event(s) | accounts: ', tostring(Accounts),
                           ' | applications: ', tostring(Applications), ' | activities: ', tostring(Activities),
                           ' | actions: ', tostring(Actions)), Last),
(IdentityLogonEvents
 | where Timestamp > ago(look)
 | where IPAddress == ip or DestinationIPAddress == ip
 | summarize C = count(), Failures = countif(isnotempty(FailureReason) or ActionType has 'Fail'),
             Accounts = make_set(coalesce(AccountUpn, AccountName), 8), Devices = make_set(DeviceName, 6),
             Destinations = make_set(DestinationDeviceName, 6), Applications = make_set(Application, 6),
             Protocols = make_set(Protocol, 6), Actions = make_set(ActionType, 8), Last = max(Timestamp)
 | where C > 0
 | project Source = 'Defender XDR - identity logons',
           Detail = strcat(C, ' authentication event(s), ', Failures, ' failed | accounts: ', tostring(Accounts),
                           ' | devices: ', tostring(Devices), ' | destinations: ', tostring(Destinations),
                           ' | applications: ', tostring(Applications), ' | protocols: ', tostring(Protocols),
                           ' | actions: ', tostring(Actions)), Last),
(UrlClickEvents
 | where Timestamp > ago(look)
 | where IPAddress == ip
 | summarize C = count(), ClickThrough = countif(IsClickedThrough == true), Users = make_set(AccountUpn, 8),
             Workloads = make_set(Workload, 5), Actions = make_set(ActionType, 6),
             Threats = make_set(ThreatTypes, 6), Urls = make_set(Url, 8), Last = max(Timestamp)
 | where C > 0
 | project Source = 'Defender XDR - URL clicks',
           Detail = strcat(C, ' click event(s), ', ClickThrough, ' clicked through | users: ', tostring(Users),
                           ' | workloads: ', tostring(Workloads), ' | actions: ', tostring(Actions),
                           ' | threats: ', tostring(Threats), ' | URLs: ', tostring(Urls)), Last),
(EmailEvents
 | where Timestamp > ago(look)
 | where SenderIPv4 == ip or SenderIPv6 == ip
 | summarize C = count(), Recipients = dcount(RecipientEmailAddress), Senders = make_set(SenderFromAddress, 8),
             Subjects = make_set(Subject, 6), Directions = make_set(EmailDirection, 4),
             Delivery = make_set(DeliveryAction, 5), Threats = make_set(ThreatTypes, 6), Last = max(Timestamp)
 | where C > 0
 | project Source = 'Defender XDR - email',
           Detail = strcat(C, ' message event(s) to ', Recipients, ' recipient(s) | senders: ', tostring(Senders),
                           ' | subjects: ', tostring(Subjects), ' | directions: ', tostring(Directions),
                           ' | delivery: ', tostring(Delivery), ' | threats: ', tostring(Threats)), Last),
(AlertEvidence
 | where Timestamp > ago(look)
 | where RemoteIP == ip or LocalIP == ip
 | summarize C = dcount(AlertId), Titles = make_set(Title, 8), Severities = make_set(Severity, 5),
             Sources = make_set(ServiceSource, 6), Roles = make_set(EvidenceRole, 5), Last = max(Timestamp)
 | where C > 0
 | project Source = 'Defender XDR - alert evidence',
           Detail = strcat(C, ' alert(s) | titles: ', tostring(Titles), ' | severity: ', tostring(Severities),
                           ' | services: ', tostring(Sources), ' | evidence roles: ', tostring(Roles)), Last)
| where isnotempty(Source)
| order by Last desc
| take 60"""

SIGNIN_KQL = f"""let ip = '{KQL_IP}';
let look = {LOOK};
let hist = 90d;
let priorCount = toscalar(SigninLogs | where TimeGenerated between (ago(hist) .. ago(look)) | where IPAddress == ip | summarize count());
SigninLogs
| where TimeGenerated > ago(look)
| where IPAddress == ip
| summarize arg_max(TimeGenerated, *)
| extend D = parse_json(tostring(DeviceDetail)), L = parse_json(tostring(LocationDetails)), N = tostring(NetworkLocationDetails)
| project
    SignInUser = tostring(UserPrincipalName),
    SignInTime = format_datetime(TimeGenerated, 'yyyy-MM-dd HH:mm:ss'),
    SignInApp = tostring(AppDisplayName),
    SignInResult = strcat(tostring(ResultType), iff(isnotempty(ResultDescription), strcat(' - ', ResultDescription), '')),
    CountryCode = iff(isempty(tostring(L.countryOrRegion)), 'Unknown', tostring(L.countryOrRegion)),
    CityState = strcat(iff(isempty(tostring(L.city)), 'Unknown', tostring(L.city)), ', ', tostring(L.state)),
    TrustedLocation = case(N has 'trustedNamedLocation', 'Trusted named location',
                           N has 'namedLocation', 'Named location (not trusted)',
                           'Unknown'),
    KnownIP = iff(priorCount > 0, strcat('Yes - ', priorCount, ' prior sign-ins in the previous 90d'), 'No - first observed in this window'),
    IPAddressStatus = case(priorCount > 0 and N has 'trustedNamedLocation', 'Known and trusted IP address',
                           priorCount > 0, 'Known IP address',
                           'Unknown IP address'),
    DeviceTrust = iff(isempty(tostring(D.trustType)), 'Unregistered / unknown', tostring(D.trustType)),
    DeviceName = iff(isempty(tostring(D.displayName)), 'n/a', tostring(D.displayName)),
    DeviceId = iff(isempty(tostring(D.deviceId)), 'n/a', tostring(D.deviceId)),
    DeviceCompliant = tostring(D.isCompliant),
    DeviceManaged = tostring(D.isManaged),
    OperatingSystem = iff(isempty(tostring(D.operatingSystem)), 'n/a', tostring(D.operatingSystem)),
    Browser = iff(isempty(tostring(D.browser)), 'n/a', tostring(D.browser)),
    AgentString = tostring(column_ifexists('UserAgent', '')),
    RiskLevel = tostring(RiskLevelDuringSignIn),
    RiskState = tostring(RiskState),
    RiskDetail = tostring(RiskDetail),
    RiskEvents = tostring(column_ifexists('RiskEventTypes_V2', dynamic([]))),
    ConditionalAccess = tostring(ConditionalAccessStatus),
    AuthRequirement = tostring(AuthenticationRequirement)
| take 1"""

SIGNIN_USERS_KQL = f"""let ip = '{KQL_IP}';
let look = {LOOK};
let SignIns = union isfuzzy=true
(SigninLogs
 | where TimeGenerated > ago(look) and IPAddress == ip
 | extend SignInClass = 'Interactive',
          DisplayName = coalesce(tostring(column_ifexists('UserDisplayName', '')), tostring(Identity), tostring(UserPrincipalName))
 | project TimeGenerated, UserPrincipalName=tostring(UserPrincipalName), DisplayName,
           AppDisplayName=tostring(AppDisplayName), ResultType=tostring(ResultType), SignInClass),
(AADNonInteractiveUserSignInLogs
 | where TimeGenerated > ago(look) and IPAddress == ip
 | extend SignInClass = 'Non-interactive',
          DisplayName = coalesce(tostring(column_ifexists('UserDisplayName', '')), tostring(Identity), tostring(UserPrincipalName))
 | project TimeGenerated, UserPrincipalName=tostring(UserPrincipalName), DisplayName,
           AppDisplayName=tostring(AppDisplayName), ResultType=tostring(ResultType), SignInClass);
SignIns
| where isnotempty(UserPrincipalName)
| summarize InteractiveSignIns=countif(SignInClass == 'Interactive'),
            NonInteractiveSignIns=countif(SignInClass == 'Non-interactive'),
            FailedSignIns=countif(ResultType != '0'),
            DisplayNames=make_set(DisplayName, 5), Applications=make_set(AppDisplayName, 12),
            FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by UserPrincipalName
| extend DisplayName=iff(array_length(DisplayNames) > 0, tostring(DisplayNames[0]), UserPrincipalName)
| project DisplayName, UserPrincipalName,
          TotalSignIns=InteractiveSignIns + NonInteractiveSignIns,
          InteractiveSignIns, NonInteractiveSignIns, FailedSignIns,
          Applications=tostring(Applications),
          FirstSeen=format_datetime(FirstSeen, 'yyyy-MM-dd HH:mm:ss'),
          LastSeen=format_datetime(LastSeen, 'yyyy-MM-dd HH:mm:ss')
| order by LastSeen desc
| take 100"""

# ---- shared inline styles (Sentinel's comment pane keeps inline styles) --------------
TH = "text-align:left;padding:4px 10px;background:#f3f2f1;border:1px solid #e1dfdd;font-weight:600;white-space:nowrap"
TD = "padding:4px 10px;border:1px solid #e1dfdd;vertical-align:top"
TBL = "border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:12px;width:100%"
H4 = "margin:12px 0 4px 0;font-family:Segoe UI,Arial,sans-serif;font-size:13px"

def g(field, default="n/a"):
    """Null-safe read from the geo response (coalesce BEFORE string())."""
    return "@{string(coalesce(outputs('Compose_Geo')?['%s'], '%s'))}" % (field, default)


def r(field, default="n/a"):
    """Null-safe read from the RDAP response."""
    return "@{string(coalesce(outputs('Compose_RDAP')?['%s'], '%s'))}" % (field, default)


def s(field, default="n/a"):
    """Null-safe read from the most recent sign-in record."""
    return "@{string(coalesce(outputs('Compose_Signin')?['%s'], '%s'))}" % (field, default)


def ab(field, default="'n/a'"):
    return "string(coalesce(body('HTTP_AbuseIPDB')?['data']?['%s'], %s))" % (field, default)


def vt(*path, default="'n/a'"):
    p = "".join("?['%s']" % k for k in path)
    return "string(coalesce(body('HTTP_VirusTotal')?['data']?['attributes']%s, %s))" % (p, default)

# ---- derived signals (replace ip-api's proxy/hosting/mobile booleans) ----------------
ORG_TYPE = "toLower(string(coalesce(outputs('Compose_Geo')?['organizationType'], '')))"
ROUTING = "toLower(string(coalesce(outputs('Compose_Geo')?['ipRoutingType'], '')))"

IS_HOSTING_EXPR = ("or(contains(%s, 'hosting'), contains(%s, 'data center'), contains(%s, 'datacenter'), "
                   "contains(%s, 'hosting'))" % (ORG_TYPE, ORG_TYPE, ORG_TYPE, ROUTING))
IS_TOR_EXPR = "contains(outputs('Compose_TorList'), items('For_each_IP_entity')?['Address'])"

HOSTING_CELL = ("@{if(%s, '<b style=\"color:#a4262c\">Yes</b>', 'No')}" % IS_HOSTING_EXPR)
TOR_CELL = ("@{if(%s, '<b style=\"color:#a4262c\">Yes &mdash; known Tor exit node</b>', 'No')}" % IS_TOR_EXPR)
MOBILE_CELL = ("@{if(or(contains(%s, 'mobile'), contains(%s, 'wireless'), contains(%s, 'cellular')), 'Yes', 'No')}"
               % (ROUTING, ROUTING, ORG_TYPE))

# ---- the HTML block appended per IP --------------------------------------------------
IP_BLOCK = f"""<hr style="border:0;border-top:1px solid #e1dfdd;margin:16px 0">
<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;font-weight:600;margin-bottom:6px">
IP enrichment &mdash; <code>{IP}</code>
<span style="@{{outputs('Compose_VerdictStyle')}}">@{{outputs('Compose_Verdict')}}</span>
</div>
<div style="font-family:Segoe UI,Arial,sans-serif;font-size:11px;color:#605e5c;margin-bottom:10px">@{{outputs('Compose_VerdictReason')}}</div>

<div style="{H4}"><b>Geolocation</b> <span style="font-weight:400;color:#605e5c">(Microsoft Sentinel enrichment API &mdash; confidence 0-100 where shown)</span></div>
<table style="{TBL}">
<tr><th style="{TH}">Organization</th><td style="{TD}">{g('organization')}</td><th style="{TH}">Organization type</th><td style="{TD}">{g('organizationType','-')}</td></tr>
<tr><th style="{TH}">City</th><td style="{TD}">{g('city')} <span style="color:#605e5c">(cf {g('cityCf','-')})</span></td><th style="{TH}">Country</th><td style="{TD}">{g('country')} <span style="color:#605e5c">(cf {g('countryCf','-')})</span></td></tr>
<tr><th style="{TH}">State</th><td style="{TD}">{g('state')} <span style="color:#605e5c">({g('stateCode','-')}, cf {g('stateCf','-')})</span></td><th style="{TH}">Continent</th><td style="{TD}">{g('continent')}</td></tr>
<tr><th style="{TH}">Region</th><td style="{TD}">{g('region','-')}</td><th style="{TH}">Coordinates</th><td style="{TD}"><a href="https://www.bing.com/maps?cp={g('latitude','0')}~{g('longitude','0')}&amp;lvl=9">{g('latitude')}, {g('longitude')}</a></td></tr>
</table>

<div style="{H4}"><b>Network / ASN</b></div>
<table style="{TBL}">
<tr><th style="{TH}">ASN</th><td style="{TD}">{g('asn')}</td><th style="{TH}">Carrier</th><td style="{TD}">{g('carrier')}</td></tr>
<tr><th style="{TH}">Routing type</th><td style="{TD}">{g('ipRoutingType','-')}</td><th style="{TH}">RIR network</th><td style="{TD}">{r('name')} ({r('handle')})</td></tr>
<tr><th style="{TH}">Range</th><td style="{TD}">{r('startAddress')} &ndash; {r('endAddress')}</td><th style="{TH}">Allocation</th><td style="{TD}">{r('type')}</td></tr>
<tr><th style="{TH}">Tor exit node</th><td style="{TD}">{TOR_CELL}</td><th style="{TH}">Hosting / datacentre</th><td style="{TD}">{HOSTING_CELL}</td></tr>
<tr><th style="{TH}">Mobile / wireless</th><td style="{TD}">{MOBILE_CELL}</td><th style="{TH}">Geo lookup</th><td style="{TD}">@{{if(empty(outputs('Compose_Geo')), '<span style="color:#a4262c">failed &mdash; no geodata returned</span>', 'ok')}}</td></tr>
</table>

@{{variables('SigninHtml')}}

<div style="{H4}"><b>Users signed in from this IP &mdash; last @{{parameters('LookbackDays')}} days</b> <span style="font-weight:400;color:#605e5c">(interactive + non-interactive; up to 100 distinct users)</span></div>
<table style="{TBL}">
<tr><th style="{TH}">User</th><th style="{TH}">Sign-ins</th><th style="{TH}">Failed</th><th style="{TH}">Applications</th><th style="{TH}">First / last seen (UTC)</th></tr>
@{{if(empty(outputs('Compose_SigninUsers')), concat('<tr><td style="{TD}" colspan="5">No user sign-ins from this IP in the selected lookback, or the required Entra sign-in tables are not collected.</td></tr>'), join(body('Select_SigninUsers'), ''))}}
</table>

@{{if(empty(concat(variables('AbuseHtml'), variables('VTHtml'), variables('GreyNoiseHtml'), variables('ShodanHtml'))), '', concat('<div style="{H4}"><b>Reputation</b></div><table style="{TBL}">', variables('AbuseHtml'), variables('VTHtml'), variables('GreyNoiseHtml'), variables('ShodanHtml'), '</table>'))}}

@{{variables('DefenderHtml')}}

<div style="{H4}"><b>Workspace insights &mdash; last @{{parameters('LookbackDays')}} days</b></div>
<table style="{TBL}">
<tr><th style="{TH}">Source</th><th style="{TH}">Detail</th><th style="{TH}">Last seen (UTC)</th></tr>
@{{if(empty(outputs('Compose_Rows')), concat('<tr><td style="{TD}" colspan="3">No results &mdash; this IP was not observed in any queried table.</td></tr>'), join(body('Select_Insight_Rows'), ''))}}
</table>
"""

# Full workflow expressions; do not nest @{...} interpolation inside @if(...).
ABUSE_VALUE = (
    "@if(equals(outputs('HTTP_AbuseIPDB')?['statusCode'], 200), concat("
    f"'<tr><th style=\"{TH}\">AbuseIPDB</th><td style=\"{TD}\">Confidence of abuse: <b>', "
    + ab("abuseConfidenceScore", "0") + ", '%</b>',"
    "' &nbsp;|&nbsp; ', " + ab("totalReports", "0") + ", ' report(s) from ', " + ab("numDistinctUsers", "0") + ", ' reporter(s)',"
    "' &nbsp;|&nbsp; usage: ', " + ab("usageType") + ","
    "' &nbsp;|&nbsp; domain: ', " + ab("domain") + ","
    "' &nbsp;|&nbsp; Tor: ', " + ab("isTor", "false") + ","
    "' &nbsp;|&nbsp; last report: ', " + ab("lastReportedAt", "'never'") + ", '</td></tr>'), "
    f"'<tr><th style=\"{TH}\">AbuseIPDB</th><td style=\"{TD}\">lookup failed or rate limited</td></tr>')"
)

VT_VALUE = (
    "@if(equals(outputs('HTTP_VirusTotal')?['statusCode'], 200), concat("
    f"'<tr><th style=\"{TH}\">VirusTotal</th><td style=\"{TD}\"><b>', "
    + vt("last_analysis_stats", "malicious", default="0") + ", '</b> malicious / ',"
    + vt("last_analysis_stats", "suspicious", default="0") + ", ' suspicious / ',"
    + vt("last_analysis_stats", "harmless", default="0") + ", ' harmless',"
    "' &nbsp;|&nbsp; community reputation: ', " + vt("reputation", default="0") + ","
    "' &nbsp;|&nbsp; network: ', " + vt("network") + ","
    "' &nbsp;|&nbsp; owner: ', " + vt("as_owner") + ","
    "' &nbsp;|&nbsp; <a href=\"https://www.virustotal.com/gui/ip-address/', "
    "items('For_each_IP_entity')?['Address'], '\">open in VirusTotal</a></td></tr>'), "
    f"'<tr><th style=\"{TH}\">VirusTotal</th><td style=\"{TD}\">lookup failed or rate limited</td></tr>')"
)

GREYNOISE_VALUE = (
    "@if(equals(outputs('HTTP_GreyNoise')?['statusCode'], 200), concat("
    f"'<tr><th style=\"{TH}\">GreyNoise Community</th><td style=\"{TD}\">classification: <b>', "
    "string(coalesce(body('HTTP_GreyNoise')?['classification'], 'unknown')), '</b>', "
    "' &nbsp;|&nbsp; internet scanner noise: ', string(coalesce(body('HTTP_GreyNoise')?['noise'], false)), "
    "' &nbsp;|&nbsp; RIOT service: ', string(coalesce(body('HTTP_GreyNoise')?['riot'], false)), "
    "' &nbsp;|&nbsp; actor/service: ', string(coalesce(body('HTTP_GreyNoise')?['name'], 'n/a')), "
    "' &nbsp;|&nbsp; last seen: ', string(coalesce(body('HTTP_GreyNoise')?['last_seen'], 'n/a')), "
    "' &nbsp;|&nbsp; <a href=\"', string(coalesce(body('HTTP_GreyNoise')?['link'], 'https://viz.greynoise.io/')), "
    "'\">open in GreyNoise</a></td></tr>'), "
    "if(equals(outputs('HTTP_GreyNoise')?['statusCode'], 404), "
    f"'<tr><th style=\"{TH}\">GreyNoise Community</th><td style=\"{TD}\">not observed in the Community dataset</td></tr>', "
    f"'<tr><th style=\"{TH}\">GreyNoise Community</th><td style=\"{TD}\">lookup unavailable or rate limited</td></tr>'))"
)

SHODAN_VALUE = (
    "@if(equals(outputs('HTTP_Shodan_InternetDB')?['statusCode'], 200), concat("
    f"'<tr><th style=\"{TH}\">Shodan InternetDB</th><td style=\"{TD}\">ports: ', "
    "string(coalesce(body('HTTP_Shodan_InternetDB')?['ports'], json('[]'))), "
    "' &nbsp;|&nbsp; tags: ', string(coalesce(body('HTTP_Shodan_InternetDB')?['tags'], json('[]'))), "
    "' &nbsp;|&nbsp; hostnames: ', string(coalesce(body('HTTP_Shodan_InternetDB')?['hostnames'], json('[]'))), "
    "' &nbsp;|&nbsp; vulnerabilities: ', string(coalesce(body('HTTP_Shodan_InternetDB')?['vulns'], json('[]'))), "
    "' &nbsp;|&nbsp; CPEs: ', string(coalesce(body('HTTP_Shodan_InternetDB')?['cpes'], json('[]'))), "
    "' &nbsp;|&nbsp; <a href=\"https://www.shodan.io/host/', items('For_each_IP_entity')?['Address'], "
    "'\">open in Shodan</a></td></tr>'), "
    "if(equals(outputs('HTTP_Shodan_InternetDB')?['statusCode'], 404), "
    f"'<tr><th style=\"{TH}\">Shodan InternetDB</th><td style=\"{TD}\">no InternetDB record</td></tr>', "
    f"'<tr><th style=\"{TH}\">Shodan InternetDB</th><td style=\"{TD}\">lookup unavailable</td></tr>'))"
)

DEFENDER_HTML_VALUE = (
    "@if(equals(outputs('HTTP_Defender_XDR_Hunting')?['statusCode'], 200), concat("
    f"'<div style=\"{H4}\"><b>Defender XDR Advanced Hunting</b> ', "
    "'<span style=\"font-weight:400;color:#605e5c\">(direct Microsoft Graph query; last ', "
    "string(parameters('DefenderLookbackDays')), ' days)</span></div>', "
    f"'<table style=\"{TBL}\"><tr><th style=\"{TH}\">Source</th><th style=\"{TH}\">Detail</th>', "
    f"'<th style=\"{TH}\">Last seen (UTC)</th></tr>', "
    "if(empty(outputs('Compose_Defender_Rows')), "
    f"'<tr><td style=\"{TD}\" colspan=\"3\">No matching Defender XDR Advanced Hunting records.</td></tr>', "
    "join(body('Select_Defender_Rows'), '')), '</table>'), "
    "concat("
    f"'<div style=\"{H4}\"><b>Defender XDR Advanced Hunting</b></div><table style=\"{TBL}\">', "
    f"'<tr><td style=\"{TD}\">Query unavailable (HTTP ', "
    "string(coalesce(outputs('HTTP_Defender_XDR_Hunting')?['statusCode'], 'no response')), "
    "'). Confirm the managed identity has Microsoft Graph application permission <b>ThreatHunting.Read.All</b>, ', "
    "'the relevant Defender products are licensed/onboarded, and the tenant has not reached its hunting quota.', "
    "'</td></tr></table>'))"
)

# ---- sign-in context block (rendered only when a sign-in from this IP exists) --------
SIGNIN_BLOCK = (
    f'<div style="{H4}"><b>Sign-in context</b> '
    f'<span style="font-weight:400;color:#605e5c">(most recent sign-in from this IP)</span></div>'
    f'<table style="{TBL}">'
    f'<tr><th style="{TH}">User</th><td style="{TD}">{s("SignInUser")}</td>'
    f'<th style="{TH}">Sign-in time (UTC)</th><td style="{TD}">{s("SignInTime")}</td></tr>'
    f'<tr><th style="{TH}">Application</th><td style="{TD}">{s("SignInApp")}</td>'
    f'<th style="{TH}">Result</th><td style="{TD}">{s("SignInResult")}</td></tr>'
    f'<tr><th style="{TH}">IP address status</th><td style="{TD}"><b>{s("IPAddressStatus")}</b></td>'
    f'<th style="{TH}">IP trusted location</th><td style="{TD}">{s("TrustedLocation")}</td></tr>'
    f'<tr><th style="{TH}">Known IP</th><td style="{TD}">{s("KnownIP")}</td>'
    f'<th style="{TH}">Country code (sign-in)</th><td style="{TD}">{s("CountryCode")}</td></tr>'
    f'<tr><th style="{TH}">Is proxy / anonymiser</th><td style="{TD}">{TOR_CELL}</td>'
    f'<th style="{TH}">Is hosting / datacentre</th><td style="{TD}">{HOSTING_CELL}</td></tr>'
    f'<tr><th style="{TH}">Device trust</th><td style="{TD}">{s("DeviceTrust")}</td>'
    f'<th style="{TH}">Device name</th><td style="{TD}">{s("DeviceName")}</td></tr>'
    f'<tr><th style="{TH}">Compliant / managed</th><td style="{TD}">{s("DeviceCompliant","unknown")} / {s("DeviceManaged","unknown")}</td>'
    f'<th style="{TH}">Device ID</th><td style="{TD}">{s("DeviceId")}</td></tr>'
    f'<tr><th style="{TH}">Operating system</th><td style="{TD}">{s("OperatingSystem")}</td>'
    f'<th style="{TH}">Browser</th><td style="{TD}">{s("Browser")}</td></tr>'
    f'<tr><th style="{TH}">User agent</th><td style="{TD}" colspan="3"><code style="font-size:11px">{s("AgentString","not recorded")}</code></td></tr>'
    f'<tr><th style="{TH}">Sign-in risk</th><td style="{TD}">{s("RiskLevel","none")} (state: {s("RiskState","none")}, detail: {s("RiskDetail","none")})</td>'
    f'<th style="{TH}">Risk events</th><td style="{TD}">{s("RiskEvents","[]")}</td></tr>'
    f'<tr><th style="{TH}">Conditional Access</th><td style="{TD}">{s("ConditionalAccess")}</td>'
    f'<th style="{TH}">Auth requirement</th><td style="{TD}">{s("AuthRequirement")}</td></tr>'
    "</table>"
)

HEADER = ('<div style="font-family:Segoe UI,Arial,sans-serif;font-size:12px;color:#605e5c">'
          "Automated IP enrichment &mdash; playbook <b>@{workflow()?['name']}</b> "
          "&middot; run @{formatDateTime(utcNow(), 'yyyy-MM-dd HH:mm')} UTC</div>")

VERDICT = ("@if(or(greater(length(body('Filter_TI')), 0), greater(variables('VTMalicious'), 0), "
           "greaterOrEquals(variables('AbuseScore'), 50), " + IS_TOR_EXPR + ", "
           "equals(toLower(string(coalesce(outputs('Compose_Signin')?['RiskLevel'], ''))), 'high')), 'HIGH', "
           "if(or(" + IS_HOSTING_EXPR + ", "
           "greaterOrEquals(variables('AbuseScore'), 25), "
           "equals(variables('GreyNoiseClassification'), 'malicious'), "
           "equals(toLower(string(coalesce(outputs('Compose_Signin')?['RiskLevel'], ''))), 'medium'), "
           "startsWith(string(coalesce(outputs('Compose_Signin')?['IPAddressStatus'], '')), 'Unknown')), "
           "'MEDIUM', 'LOW'))")

CHIP = "display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;color:#ffffff;margin-left:6px;background:"
VERDICT_STYLE = ("@if(equals(outputs('Compose_Verdict'), 'HIGH'), '%s#a4262c', "
                 "if(equals(outputs('Compose_Verdict'), 'MEDIUM'), '%s#986f0b', '%s#107c10'))" % (CHIP, CHIP, CHIP))

VERDICT_REASON = ("@concat('Signals: ', string(length(body('Filter_TI'))), ' TI match(es) &middot; AbuseIPDB ', "
                  "string(variables('AbuseScore')), '% &middot; VT malicious ', string(variables('VTMalicious')), "
                  "' &middot; GreyNoise ', variables('GreyNoiseClassification'), "
                  "' &middot; Tor exit: ', if(" + IS_TOR_EXPR + ", 'yes', 'no'), "
                  "' &middot; ', string(length(outputs('Compose_Rows'))), ' workspace insight row(s)')")

SENTINEL_CONN = "@parameters('$connections')['azuresentinel']['connectionId']"
LA_CONN = "@parameters('$connections')['azuremonitorlogs']['connectionId']"


def after(*names, states=("Succeeded",)):
    return {n: list(states) for n in names}


definition = {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "$connections": {"defaultValue": {}, "type": "Object"},
        "LookbackDays": {"type": "Int", "defaultValue": 14},
        "TorExitListUrl": {"type": "String", "defaultValue": "https://check.torproject.org/torbulkexitlist"},
        "AbuseIPDBApiKey": {"type": "SecureString", "defaultValue": ""},
        "VirusTotalApiKey": {"type": "SecureString", "defaultValue": ""},
        "GreyNoiseApiKey": {"type": "SecureString", "defaultValue": ""},
        "EnableShodanInternetDB": {"type": "Bool", "defaultValue": False},
        "EnableDefenderAdvancedHunting": {"type": "Bool", "defaultValue": False},
        "DefenderLookbackDays": {"type": "Int", "defaultValue": 14},
        "IPContextWatchlistAlias": {"type": "String", "defaultValue": "IPContext"},
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
        # ---- variables -------------------------------------------------------------
        "Init_HtmlBody": {
            "runAfter": {}, "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "HtmlBody", "type": "string", "value": HEADER}]},
        },
        "Init_AbuseHtml": {
            "runAfter": after("Init_HtmlBody"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "AbuseHtml", "type": "string", "value": ""}]},
        },
        "Init_VTHtml": {
            "runAfter": after("Init_AbuseHtml"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "VTHtml", "type": "string", "value": ""}]},
        },
        "Init_GreyNoiseHtml": {
            "runAfter": after("Init_VTHtml"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "GreyNoiseHtml", "type": "string", "value": ""}]},
        },
        "Init_GreyNoiseClassification": {
            "runAfter": after("Init_GreyNoiseHtml"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "GreyNoiseClassification", "type": "string", "value": "unknown"}]},
        },
        "Init_ShodanHtml": {
            "runAfter": after("Init_GreyNoiseClassification"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "ShodanHtml", "type": "string", "value": ""}]},
        },
        "Init_DefenderHtml": {
            "runAfter": after("Init_ShodanHtml"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "DefenderHtml", "type": "string", "value": ""}]},
        },
        "Init_AbuseScore": {
            "runAfter": after("Init_DefenderHtml"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "AbuseScore", "type": "integer", "value": 0}]},
        },
        "Init_VTMalicious": {
            "runAfter": after("Init_AbuseScore"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "VTMalicious", "type": "integer", "value": 0}]},
        },
        "Init_SigninHtml": {
            "runAfter": after("Init_VTMalicious"), "type": "InitializeVariable",
            "inputs": {"variables": [{"name": "SigninHtml", "type": "string", "value": ""}]},
        },
        # ---- Tor exit list: fetched once per run, not once per IP -------------------
        "HTTP_Tor_Exit_List": {
            "runAfter": after("Init_SigninHtml"), "type": "Http",
            "inputs": {"method": "GET", "uri": "@parameters('TorExitListUrl')"},
        },
        "Compose_TorList": {
            "runAfter": after("HTTP_Tor_Exit_List", states=("Succeeded", "Failed", "TimedOut")),
            "type": "Compose",
            "inputs": ("@if(equals(outputs('HTTP_Tor_Exit_List')?['statusCode'], 200), "
                       "split(replace(string(body('HTTP_Tor_Exit_List')), decodeUriComponent('%0D'), ''), "
                       "decodeUriComponent('%0A')), json('[]'))"),
        },
        # ---- entities --------------------------------------------------------------
        "Entities_-_Get_IPs": {
            "runAfter": after("Compose_TorList"), "type": "ApiConnection",
            "inputs": {
                "host": {"connection": {"name": SENTINEL_CONN}},
                "method": "post",
                "body": "@triggerBody()?['object']?['properties']?['relatedEntities']",
                "path": "/entities/ip",
            },
        },
        # ---- per-IP loop -----------------------------------------------------------
        "For_each_IP_entity": {
            "foreach": "@body('Entities_-_Get_IPs')?['IPs']",
            "runAfter": after("Entities_-_Get_IPs"),
            "type": "Foreach",
            "runtimeConfiguration": {"concurrency": {"repetitions": 1}},
            "actions": {
                "Reset_AbuseHtml": {
                    "runAfter": {}, "type": "SetVariable",
                    "inputs": {"name": "AbuseHtml", "value": ""},
                },
                "Reset_VTHtml": {
                    "runAfter": after("Reset_AbuseHtml"), "type": "SetVariable",
                    "inputs": {"name": "VTHtml", "value": ""},
                },
                "Reset_GreyNoiseHtml": {
                    "runAfter": after("Reset_VTHtml"), "type": "SetVariable",
                    "inputs": {"name": "GreyNoiseHtml", "value": ""},
                },
                "Reset_GreyNoiseClassification": {
                    "runAfter": after("Reset_GreyNoiseHtml"), "type": "SetVariable",
                    "inputs": {"name": "GreyNoiseClassification", "value": "unknown"},
                },
                "Reset_ShodanHtml": {
                    "runAfter": after("Reset_GreyNoiseClassification"), "type": "SetVariable",
                    "inputs": {"name": "ShodanHtml", "value": ""},
                },
                "Reset_DefenderHtml": {
                    "runAfter": after("Reset_ShodanHtml"), "type": "SetVariable",
                    "inputs": {"name": "DefenderHtml", "value": ""},
                },
                "Reset_AbuseScore": {
                    "runAfter": after("Reset_DefenderHtml"), "type": "SetVariable",
                    "inputs": {"name": "AbuseScore", "value": 0},
                },
                "Reset_VTMalicious": {
                    "runAfter": after("Reset_AbuseScore"), "type": "SetVariable",
                    "inputs": {"name": "VTMalicious", "value": 0},
                },
                "Reset_SigninHtml": {
                    "runAfter": after("Reset_VTMalicious"), "type": "SetVariable",
                    "inputs": {"name": "SigninHtml", "value": ""},
                },
                # geolocation + ASN via Sentinel's own enrichment API (managed identity, no key)
                "HTTP_Sentinel_Geodata": {
                    "runAfter": after("Reset_SigninHtml"), "type": "Http",
                    "inputs": {
                        "method": "GET",
                        "uri": ("https://management.azure.com/subscriptions/"
                                "@{parameters('WorkspaceSubscriptionId')}/resourceGroups/"
                                "@{parameters('WorkspaceResourceGroup')}/providers/"
                                "Microsoft.SecurityInsights/enrichment/ip/geodata/"),
                        "queries": {
                            "ipAddress": "@{items('For_each_IP_entity')?['Address']}",
                            "api-version": "2023-02-01-preview",
                        },
                        "authentication": AZURE_MANAGEMENT_MANAGED_IDENTITY_AUTH,
                    },
                },
                "Compose_Geo": {
                    "runAfter": after("HTTP_Sentinel_Geodata", states=("Succeeded", "Failed", "TimedOut")),
                    "type": "Compose",
                    "inputs": ("@if(equals(outputs('HTTP_Sentinel_Geodata')?['statusCode'], 200), "
                               "coalesce(body('HTTP_Sentinel_Geodata'), json('{}')), json('{}'))"),
                },
                # RIR / RDAP
                "HTTP_RDAP": {
                    "runAfter": after("Compose_Geo"), "type": "Http",
                    "inputs": {
                        "method": "GET",
                        "uri": "https://rdap.org/ip/@{items('For_each_IP_entity')?['Address']}",
                        "headers": {"Accept": "application/rdap+json"},
                    },
                },
                "HTTP_RDAP_Regional": {
                    "runAfter": after("HTTP_RDAP", states=("Succeeded", "Failed", "TimedOut")),
                    "type": "Http",
                    "inputs": {
                        "method": "GET",
                        "uri": ("@coalesce(outputs('HTTP_RDAP')?['headers']?['Location'], "
                                "outputs('HTTP_RDAP')?['headers']?['location'], "
                                "concat('https://rdap.org/ip/', items('For_each_IP_entity')?['Address']))"),
                        "headers": {"Accept": "application/rdap+json"},
                    },
                },
                "Compose_RDAP": {
                    "runAfter": after("HTTP_RDAP_Regional", states=("Succeeded", "Failed", "TimedOut")),
                    "type": "Compose",
                    "inputs": ("@if(equals(outputs('HTTP_RDAP_Regional')?['statusCode'], 200), "
                               "coalesce(body('HTTP_RDAP_Regional'), json('{}')), "
                               "if(equals(outputs('HTTP_RDAP')?['statusCode'], 200), "
                               "coalesce(body('HTTP_RDAP'), json('{}')), json('{}')))"),
                },
                # AbuseIPDB (optional)
                "Condition_AbuseIPDB_key_present": {
                    "runAfter": after("Compose_RDAP"), "type": "If",
                    "expression": {"and": [{"not": {"equals": ["@parameters('AbuseIPDBApiKey')", ""]}}]},
                    "actions": {
                        "HTTP_AbuseIPDB": {
                            "runAfter": {}, "type": "Http",
                            "inputs": {
                                "method": "GET",
                                "uri": "https://api.abuseipdb.com/api/v2/check",
                                "queries": {
                                    "ipAddress": "@{items('For_each_IP_entity')?['Address']}",
                                    "maxAgeInDays": "90",
                                },
                                "headers": {"Key": "@parameters('AbuseIPDBApiKey')", "Accept": "application/json"},
                            },
                            "runtimeConfiguration": {"secureData": {"properties": ["inputs"]}},
                        },
                        "Set_AbuseScore": {
                            "runAfter": after("HTTP_AbuseIPDB", states=("Succeeded", "Failed", "TimedOut")),
                            "type": "SetVariable",
                            "inputs": {
                                "name": "AbuseScore",
                                "value": ("@if(equals(outputs('HTTP_AbuseIPDB')?['statusCode'], 200), "
                                          "int(coalesce(body('HTTP_AbuseIPDB')?['data']?['abuseConfidenceScore'], 0)), 0)"),
                            },
                        },
                        "Set_AbuseHtml": {
                            "runAfter": after("Set_AbuseScore"), "type": "SetVariable",
                            "inputs": {"name": "AbuseHtml", "value": ABUSE_VALUE},
                        },
                    },
                    "else": {"actions": {}},
                },
                # VirusTotal (optional)
                "Condition_VirusTotal_key_present": {
                    "runAfter": after("Condition_AbuseIPDB_key_present"), "type": "If",
                    "expression": {"and": [{"not": {"equals": ["@parameters('VirusTotalApiKey')", ""]}}]},
                    "actions": {
                        "HTTP_VirusTotal": {
                            "runAfter": {}, "type": "Http",
                            "inputs": {
                                "method": "GET",
                                "uri": "https://www.virustotal.com/api/v3/ip_addresses/@{items('For_each_IP_entity')?['Address']}",
                                "headers": {"x-apikey": "@parameters('VirusTotalApiKey')"},
                            },
                            "runtimeConfiguration": {"secureData": {"properties": ["inputs"]}},
                        },
                        "Set_VTMalicious": {
                            "runAfter": after("HTTP_VirusTotal", states=("Succeeded", "Failed", "TimedOut")),
                            "type": "SetVariable",
                            "inputs": {
                                "name": "VTMalicious",
                                "value": ("@if(equals(outputs('HTTP_VirusTotal')?['statusCode'], 200), "
                                          "int(coalesce(body('HTTP_VirusTotal')?['data']?['attributes']?['last_analysis_stats']?['malicious'], 0)), 0)"),
                            },
                        },
                        "Set_VTHtml": {
                            "runAfter": after("Set_VTMalicious"), "type": "SetVariable",
                            "inputs": {"name": "VTHtml", "value": VT_VALUE},
                        },
                    },
                    "else": {"actions": {}},
                },
                # GreyNoise Community (optional; leave the key blank to disable)
                "Condition_GreyNoise_key_present": {
                    "runAfter": after("Condition_VirusTotal_key_present"), "type": "If",
                    "expression": {"and": [{"not": {"equals": ["@parameters('GreyNoiseApiKey')", ""]}}]},
                    "actions": {
                        "HTTP_GreyNoise": {
                            "runAfter": {}, "type": "Http",
                            "inputs": {
                                "method": "GET",
                                "uri": "https://api.greynoise.io/v3/community/@{items('For_each_IP_entity')?['Address']}",
                                "headers": {"key": "@parameters('GreyNoiseApiKey')", "Accept": "application/json"},
                            },
                            "runtimeConfiguration": {"secureData": {"properties": ["inputs"]}},
                        },
                        "Set_GreyNoiseClassification": {
                            "runAfter": after("HTTP_GreyNoise", states=("Succeeded", "Failed", "TimedOut")),
                            "type": "SetVariable",
                            "inputs": {
                                "name": "GreyNoiseClassification",
                                "value": ("@if(equals(outputs('HTTP_GreyNoise')?['statusCode'], 200), "
                                          "toLower(string(coalesce(body('HTTP_GreyNoise')?['classification'], 'unknown'))), "
                                          "'unknown')"),
                            },
                        },
                        "Set_GreyNoiseHtml": {
                            "runAfter": after("Set_GreyNoiseClassification"), "type": "SetVariable",
                            "inputs": {"name": "GreyNoiseHtml", "value": GREYNOISE_VALUE},
                        },
                    },
                    "else": {"actions": {}},
                },
                # Shodan InternetDB is non-commercial unless covered by Shodan Enterprise.
                "Condition_Shodan_licensed": {
                    "runAfter": after("Condition_GreyNoise_key_present"), "type": "If",
                    "expression": {"and": [{"equals": ["@parameters('EnableShodanInternetDB')", True]}]},
                    "actions": {
                        "HTTP_Shodan_InternetDB": {
                            "runAfter": {}, "type": "Http",
                            "inputs": {
                                "method": "GET",
                                "uri": "https://internetdb.shodan.io/@{items('For_each_IP_entity')?['Address']}",
                                "headers": {"Accept": "application/json"},
                            },
                        },
                        "Set_ShodanHtml": {
                            "runAfter": after("HTTP_Shodan_InternetDB", states=("Succeeded", "Failed", "TimedOut")),
                            "type": "SetVariable",
                            "inputs": {"name": "ShodanHtml", "value": SHODAN_VALUE},
                        },
                    },
                    "else": {"actions": {}},
                },
                # Defender XDR Advanced Hunting through Microsoft Graph (optional).
                "Condition_Defender_XDR_enabled": {
                    "runAfter": after("Condition_Shodan_licensed"), "type": "If",
                    "expression": {"and": [{"equals": ["@parameters('EnableDefenderAdvancedHunting')", True]}]},
                    "actions": {
                        "HTTP_Defender_XDR_Hunting": {
                            "runAfter": {}, "type": "Http",
                            "inputs": {
                                "method": "POST",
                                "uri": "https://graph.microsoft.com/v1.0/security/runHuntingQuery",
                                "headers": {"Content-Type": "application/json; charset=utf-8"},
                                "body": {
                                    "Query": DEFENDER_KQL,
                                    "Timespan": "@{concat('P', string(parameters('DefenderLookbackDays')), 'D')}",
                                },
                                "authentication": MICROSOFT_GRAPH_MANAGED_IDENTITY_AUTH,
                            },
                            "runtimeConfiguration": {"secureData": {"properties": ["inputs", "outputs"]}},
                        },
                        "Compose_Defender_Rows": {
                            "runAfter": after("HTTP_Defender_XDR_Hunting", states=("Succeeded", "Failed", "TimedOut")),
                            "type": "Compose",
                            "inputs": ("@if(equals(outputs('HTTP_Defender_XDR_Hunting')?['statusCode'], 200), "
                                       "coalesce(body('HTTP_Defender_XDR_Hunting')?['results'], json('[]')), json('[]'))"),
                        },
                        "Select_Defender_Rows": {
                            "runAfter": after("Compose_Defender_Rows"), "type": "Select",
                            "inputs": {
                                "from": "@outputs('Compose_Defender_Rows')",
                                "select": (f'<tr><td style="{TD}"><b>@{{item()?[\'Source\']}}</b></td>'
                                           f'<td style="{TD}">@{{item()?[\'Detail\']}}</td>'
                                           f'<td style="{TD}">@{{item()?[\'Last\']}}</td></tr>'),
                            },
                        },
                        "Set_DefenderHtml": {
                            "runAfter": after("Select_Defender_Rows"), "type": "SetVariable",
                            "inputs": {"name": "DefenderHtml", "value": DEFENDER_HTML_VALUE},
                        },
                    },
                    "else": {"actions": {}},
                },
                # most recent Entra sign-in from this IP (device / OS / browser / risk)
                "Run_KQL_signin_context": {
                    "runAfter": after("Condition_Defender_XDR_enabled"), "type": "ApiConnection",
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
                "Compose_Signin": {
                    "runAfter": after("Run_KQL_signin_context", states=("Succeeded", "Failed", "TimedOut")),
                    "type": "Compose",
                    "inputs": ("@if(and(equals(actions('Run_KQL_signin_context')?['status'], 'Succeeded'), "
                               "greater(length(coalesce(body('Run_KQL_signin_context')?['value'], json('[]'))), 0)), "
                               "first(body('Run_KQL_signin_context')?['value']), json('{}'))"),
                },
                "Condition_signin_found": {
                    "runAfter": after("Compose_Signin"), "type": "If",
                    "expression": {"and": [{"not": {"equals": ["@empty(outputs('Compose_Signin'))", True]}}]},
                    "actions": {
                        "Set_SigninHtml": {
                            "runAfter": {}, "type": "SetVariable",
                            "inputs": {"name": "SigninHtml", "value": SIGNIN_BLOCK},
                        }
                    },
                    "else": {
                        "actions": {
                            "Set_SigninHtml_none": {
                                "runAfter": {}, "type": "SetVariable",
                                "inputs": {
                                    "name": "SigninHtml",
                                    "value": (f'<div style="{H4}"><b>Sign-in context</b></div>'
                                              f'<table style="{TBL}"><tr><td style="{TD}">'
                                              "No Entra ID sign-in from this IP in the last "
                                              "@{parameters('LookbackDays')} days (or SigninLogs is not "
                                              "collected in this workspace).</td></tr></table>"),
                                },
                            }
                        }
                    },
                },
                "Run_KQL_signin_users": {
                    "runAfter": after("Condition_signin_found"), "type": "ApiConnection",
                    "inputs": {
                        "host": {"connection": {"name": LA_CONN}},
                        "method": "post",
                        "body": SIGNIN_USERS_KQL,
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
                "Compose_SigninUsers": {
                    "runAfter": after("Run_KQL_signin_users", states=("Succeeded", "Failed", "TimedOut")),
                    "type": "Compose",
                    "inputs": ("@if(equals(actions('Run_KQL_signin_users')?['status'], 'Succeeded'), "
                               "coalesce(body('Run_KQL_signin_users')?['value'], json('[]')), json('[]'))"),
                },
                "Select_SigninUsers": {
                    "runAfter": after("Compose_SigninUsers"), "type": "Select",
                    "inputs": {
                        "from": "@outputs('Compose_SigninUsers')",
                        "select": (f'<tr><td style="{TD}"><b>@{{item()?[\'DisplayName\']}}</b><br>'
                                   f'<code style="font-size:11px">@{{item()?[\'UserPrincipalName\']}}</code></td>'
                                   f'<td style="{TD}"><b>@{{item()?[\'TotalSignIns\']}}</b> total<br>'
                                   f'@{{item()?[\'InteractiveSignIns\']}} interactive / '
                                   f'@{{item()?[\'NonInteractiveSignIns\']}} non-interactive</td>'
                                   f'<td style="{TD}">@{{item()?[\'FailedSignIns\']}}</td>'
                                   f'<td style="{TD}">@{{item()?[\'Applications\']}}</td>'
                                   f'<td style="{TD}">@{{item()?[\'FirstSeen\']}}<br>@{{item()?[\'LastSeen\']}}</td></tr>'),
                    },
                },
                # workspace insights
                "Run_KQL_insights": {
                    "runAfter": after("Select_SigninUsers"), "type": "ApiConnection",
                    "inputs": {
                        "host": {"connection": {"name": LA_CONN}},
                        "method": "post",
                        "body": KQL,
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
                "Run_KQL_extended_context": {
                    "runAfter": after("Run_KQL_insights", states=("Succeeded", "Failed", "TimedOut")),
                    "type": "ApiConnection",
                    "inputs": {
                        "host": {"connection": {"name": LA_CONN}},
                        "method": "post",
                        "body": EXTENDED_KQL,
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
                "Compose_Rows": {
                    "runAfter": after("Run_KQL_extended_context", states=("Succeeded", "Failed", "TimedOut")),
                    "type": "Compose",
                    "inputs": ("@union("
                               "if(equals(actions('Run_KQL_insights')?['status'], 'Succeeded'), "
                               "coalesce(body('Run_KQL_insights')?['value'], json('[]')), json('[]')), "
                               "if(equals(actions('Run_KQL_extended_context')?['status'], 'Succeeded'), "
                               "coalesce(body('Run_KQL_extended_context')?['value'], json('[]')), json('[]')))"),
                },
                "Filter_TI": {
                    "runAfter": after("Compose_Rows"), "type": "Query",
                    "inputs": {
                        "from": "@outputs('Compose_Rows')",
                        "where": "@equals(item()?['Source'], 'Threat Intel')",
                    },
                },
                "Select_Insight_Rows": {
                    "runAfter": after("Filter_TI"), "type": "Select",
                    "inputs": {
                        "from": "@outputs('Compose_Rows')",
                        "select": (f'<tr><td style="{TD}"><b>@{{item()?[\'Source\']}}</b></td>'
                                   f'<td style="{TD}">@{{item()?[\'Detail\']}}</td>'
                                   f'<td style="{TD}">@{{item()?[\'Last\']}}</td></tr>'),
                    },
                },
                "Compose_Verdict": {
                    "runAfter": after("Select_Insight_Rows"), "type": "Compose", "inputs": VERDICT,
                },
                "Compose_VerdictStyle": {
                    "runAfter": after("Compose_Verdict"), "type": "Compose", "inputs": VERDICT_STYLE,
                },
                "Compose_VerdictReason": {
                    "runAfter": after("Compose_VerdictStyle"), "type": "Compose", "inputs": VERDICT_REASON,
                },
                # Post one comment per entity, right here inside the loop, instead of
                # accumulating every entity's block into one shared HtmlBody and posting
                # it once after the loop. Sentinel's /Incidents/Comment API rejects any
                # single comment over 30,000 characters; a shared, ever-growing comment
                # made that limit trivial to hit on an incident with several IP entities
                # (and would then fail the ENTIRE comment, losing every entity's
                # enrichment, not just the overflow). Per-entity comments are bounded by
                # one entity's own data, which is the fix; the truncation step below is
                # just a backstop for the rare single entity whose own block is still
                # unusually large (e.g. a very long RDAP/AbuseIPDB/GreyNoise dump).
                "Compose_Entity_Comment": {
                    "runAfter": after("Compose_VerdictReason"), "type": "Compose",
                    "inputs": HEADER + IP_BLOCK,
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
        "title": "Enrich IP entities and post a Sentinel incident comment",
        "description": "License-aware IP enrichment for Microsoft Sentinel. For every IP entity it collects Microsoft geodata, RDAP registration, Tor membership, optional AbuseIPDB, GreyNoise Community and licensed Shodan/VirusTotal context, Entra sign-in context, client watchlist matches, UEBA anomalies, ASIM network and DNS observations, threat intelligence, sightings and prior alerts. An optional Microsoft Graph module queries Defender XDR Advanced Hunting data that is not ingested into the Sentinel workspace. Results are posted as one formatted incident comment.",
        "prerequisites": "A Microsoft Sentinel-enabled Log Analytics workspace. Optional: AbuseIPDB and GreyNoise Community keys, an IPContext watchlist, appropriately licensed VirusTotal or Shodan access, and Defender XDR licensing plus Microsoft Graph ThreatHunting.Read.All application permission for direct Advanced Hunting.",
        "postDeployment": [
            "Grant the user-assigned managed identity 'Microsoft Sentinel Responder' on the resource group holding the workspace (this also covers the geodata enrichment read).",
            "Grant the same identity 'Log Analytics Reader' on the workspace.",
            "If Defender Advanced Hunting is enabled, grant the managed identity Microsoft Graph application permission 'ThreatHunting.Read.All' using an app-role assignment and allow time for token propagation.",
            "Authorise both API connections (they are pre-set to managed identity).",
            "Attach the playbook to an automation rule, or run it on demand from an incident."
        ],
        "lastUpdateTime": "2026-09-01",
        "entities": ["Ip"],
        "tags": ["Enrichment", "Threat Intelligence", "Geolocation"],
        "support": {"tier": "community"},
    },
    "parameters": {
        "PlaybookName": {"type": "string", "defaultValue": "Enrich-IP-IncidentComment",
                         "metadata": {"description": "Name of the Logic App playbook."}},
        "UserAssignedManagedIdentityResourceId": {
            "type": "string",
            "minLength": 1,
            "metadata": {
                "description": "Required. Enter the full resource ID of the existing client-owned user-assigned managed identity used by the Logic App and all managed-identity connections."
            },
        },
        "WorkspaceName": {"type": "string",
                          "metadata": {"description": "Log Analytics / Sentinel workspace name."}},
        "WorkspaceResourceGroup": {"type": "string", "defaultValue": "[resourceGroup().name]",
                                   "metadata": {"description": "Resource group of the workspace."}},
        "WorkspaceSubscriptionId": {"type": "string", "defaultValue": "[subscription().subscriptionId]",
                                    "metadata": {"description": "Subscription of the workspace."}},
        "LookbackDays": {"type": "int", "defaultValue": 14, "minValue": 1, "maxValue": 90,
                         "metadata": {"description": "How far back to search workspace tables for sightings."}},
        "TorExitListUrl": {"type": "string", "defaultValue": "https://check.torproject.org/torbulkexitlist",
                           "metadata": {"description": "Public Tor exit-node list, fetched once per run. Point at an internal mirror if outbound access is restricted, or blank-check it by leaving the run to fail open (the check simply reports 'No')."}},
        "AbuseIPDBApiKey": {"type": "securestring", "defaultValue": "",
                            "metadata": {"description": "Free AbuseIPDB key (1,000 checks/day). Leave blank to skip the AbuseIPDB row."}},
        "VirusTotalApiKey": {"type": "securestring", "defaultValue": "",
                             "metadata": {"description": "OPTIONAL and OFF by default. VirusTotal's free public API forbids use in business workflows, so supply a Premium key or leave this blank."}},
        "GreyNoiseApiKey": {"type": "securestring", "defaultValue": "",
                            "metadata": {"description": "Optional GreyNoise Community API key. Leave blank to disable and avoid unauthenticated rate limits."}},
        "EnableShodanInternetDB": {"type": "bool", "defaultValue": False,
                                   "metadata": {"description": "Enable only when the client has Shodan Enterprise permission for commercial InternetDB use. Disabled by default."}},
        "EnableDefenderAdvancedHunting": {"type": "bool", "defaultValue": False,
                                          "metadata": {"description": "Query Defender XDR Advanced Hunting directly through Microsoft Graph. Requires the managed identity to have the ThreatHunting.Read.All application permission and relevant Defender licensing."}},
        "DefenderLookbackDays": {"type": "int", "defaultValue": 14, "minValue": 1, "maxValue": 30,
                                 "metadata": {"description": "Defender XDR Advanced Hunting lookback. Raw Defender hunting data is limited to a maximum of 30 days."}},
        "IPContextWatchlistAlias": {"type": "string", "defaultValue": "IPContext",
                                    "metadata": {"description": "Optional Sentinel watchlist alias. Use SearchKey for the IP and recommended columns Classification, Owner, Description, RiskOverride and ValidUntil. Set blank to disable."}},
    },
    "variables": {
        "SentinelConnectionName": "[concat('MicrosoftSentinel-', parameters('PlaybookName'))]",
        "MonitorLogsConnectionName": "[concat('AzureMonitorLogs-', parameters('PlaybookName'))]",
    },
    "resources": [
        {
            "type": "Microsoft.Web/connections", "apiVersion": "2016-06-01",
            "name": "[variables('SentinelConnectionName')]",
            "location": "[resourceGroup().location]", "kind": "V1",
            "properties": {
                "displayName": "[variables('SentinelConnectionName')]",
                "customParameterValues": {},
                "parameterValueType": "Alternative",
                "api": {"id": "[concat('/subscriptions/', subscription().subscriptionId, '/providers/Microsoft.Web/locations/', resourceGroup().location, '/managedApis/azuresentinel')]"},
            },
        },
        {
            "type": "Microsoft.Web/connections", "apiVersion": "2016-06-01",
            "name": "[variables('MonitorLogsConnectionName')]",
            "location": "[resourceGroup().location]", "kind": "V1",
            "properties": {
                "displayName": "[variables('MonitorLogsConnectionName')]",
                "customParameterValues": {},
                "parameterValueSet": {"name": "managedIdentityAuth", "values": {}},
                "api": {"id": "[concat('/subscriptions/', subscription().subscriptionId, '/providers/Microsoft.Web/locations/', resourceGroup().location, '/managedApis/azuremonitorlogs')]"},
            },
        },
        {
            "type": "Microsoft.Logic/workflows", "apiVersion": "2017-07-01",
            "name": "[parameters('PlaybookName')]",
            "location": "[resourceGroup().location]",
            "identity": {
                "type": "UserAssigned",
                "userAssignedIdentities": {
                    "[parameters('UserAssignedManagedIdentityResourceId')]": {}
                },
            },
            "tags": {"hidden-SentinelTemplateName": "Enrich-IP-IncidentComment",
                     "hidden-SentinelTemplateVersion": "1.0"},
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
                    "TorExitListUrl": {"value": "[parameters('TorExitListUrl')]"},
                    "AbuseIPDBApiKey": {"value": "[parameters('AbuseIPDBApiKey')]"},
                    "VirusTotalApiKey": {"value": "[parameters('VirusTotalApiKey')]"},
                    "GreyNoiseApiKey": {"value": "[parameters('GreyNoiseApiKey')]"},
                    "EnableShodanInternetDB": {"value": "[parameters('EnableShodanInternetDB')]"},
                    "EnableDefenderAdvancedHunting": {"value": "[parameters('EnableDefenderAdvancedHunting')]"},
                    "DefenderLookbackDays": {"value": "[parameters('DefenderLookbackDays')]"},
                    "IPContextWatchlistAlias": {"value": "[parameters('IPContextWatchlistAlias')]"},
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

out = pathlib.Path(__file__).parent / "azuredeploy.json"
out.write_text(json.dumps(template, indent=2), encoding="utf-8")
print(f"wrote {out} ({out.stat().st_size} bytes)")

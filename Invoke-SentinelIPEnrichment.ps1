<#
.SYNOPSIS
    STAT-style IP enrichment for Microsoft Sentinel incidents.

.DESCRIPTION
    Reads the IP entities from a Sentinel incident (or takes IPs directly), enriches each with
      - geolocation and ASN            (Sentinel's own enrichment API - no key, no external egress)
      - RIR registration               (RDAP, free, no key)
      - Tor exit node membership       (public Tor bulk exit list, free, no key)
      - reputation                     (AbuseIPDB free tier; VirusTotal only with a Premium key)
      - Entra sign-in context          (device trust, OS, browser, user agent, risk, known/trusted IP)
      - workspace insights             (TI matches, sightings across tables, prior alerts)
    then writes one formatted HTML comment back to the incident.

    Same output as the Logic App playbook in azuredeploy.json - use this to test the format,
    to backfill closed incidents, or as an Azure Automation runbook.

.EXAMPLE
    # Preview only - writes preview.html, posts nothing
    .\Invoke-SentinelIPEnrichment.ps1 -SubscriptionId <sub> -ResourceGroupName <rg> `
        -WorkspaceName bfree-sentinel-law -IpAddress 103.187.6.124 -PreviewOnly

.EXAMPLE
    # Enrich a live incident
    .\Invoke-SentinelIPEnrichment.ps1 -SubscriptionId <sub> -ResourceGroupName <rg> `
        -WorkspaceName bfree-sentinel-law -IncidentName <incident guid> -AbuseIPDBApiKey $env:ABUSEIPDB

.NOTES
    Requires: Az.Accounts, Az.OperationalInsights.  Connect-AzAccount first.
    RBAC:     Microsoft Sentinel Responder (to comment) + Log Analytics Reader (to query).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroupName,
    [Parameter(Mandatory)][string]$WorkspaceName,

    # Either give an incident (IPs are read from its entities) ...
    [string]$IncidentName,
    # ... or give IPs directly (with -PreviewOnly, or with -IncidentName to force a set).
    [string[]]$IpAddress,

    [int]$LookbackDays = 14,
    [string]$TorExitListUrl = 'https://check.torproject.org/torbulkexitlist',
    [string]$AbuseIPDBApiKey,      # free tier: 1,000 checks/day
    [string]$VirusTotalApiKey,     # Premium only - the free public API forbids business workflows

    [switch]$PreviewOnly,
    [string]$PreviewPath = './preview.html'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ------------------------------------------------------------------ styles ----------
$S = @{
    tbl = 'border-collapse:collapse;font-family:Segoe UI,Arial,sans-serif;font-size:12px;width:100%'
    th  = 'text-align:left;padding:4px 10px;background:#f3f2f1;border:1px solid #e1dfdd;font-weight:600;white-space:nowrap'
    td  = 'padding:4px 10px;border:1px solid #e1dfdd;vertical-align:top'
    h4  = 'margin:12px 0 4px 0;font-family:Segoe UI,Arial,sans-serif;font-size:13px'
}
function Enc([object]$v, [string]$fallback = 'n/a') {
    if ($null -eq $v -or "$v" -eq '') { return $fallback }
    return [System.Net.WebUtility]::HtmlEncode("$v")
}
function YesNo([object]$v) {
    if ($v -eq $true) { return '<b style="color:#a4262c">Yes</b>' } else { return 'No' }
}

# ------------------------------------------------------------------ context ----------
Set-AzContext -Subscription $SubscriptionId | Out-Null
$ws = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName
$workspaceId = $ws.CustomerId

function Invoke-Kql([string]$Query) {
    try {
        $r = Invoke-AzOperationalInsightsQuery -WorkspaceId $workspaceId -Query $Query -ErrorAction Stop
        return @($r.Results)
    } catch {
        Write-Warning "KQL failed: $($_.Exception.Message)"
        return @()
    }
}

# ------------------------------------------------------------------ entities ---------
$incidentArmId = $null
if ($IncidentName) {
    $incidentArmId = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/" +
                     "Microsoft.OperationalInsights/workspaces/$WorkspaceName/providers/" +
                     "Microsoft.SecurityInsights/incidents/$IncidentName"
    if (-not $IpAddress) {
        $resp = Invoke-AzRestMethod -Method POST -Path "$incidentArmId/entities?api-version=2023-02-01"
        if ($resp.StatusCode -ge 300) { throw "Could not read incident entities: $($resp.Content)" }
        $IpAddress = @(($resp.Content | ConvertFrom-Json).entities |
                       Where-Object { $_.kind -eq 'Ip' } |
                       ForEach-Object { $_.properties.address } | Select-Object -Unique)
    }
}
if (-not $IpAddress) { throw 'No IP entities found. Pass -IpAddress or an incident that has IP entities.' }
Write-Host "Enriching $($IpAddress.Count) IP(s): $($IpAddress -join ', ')" -ForegroundColor Cyan

# ------------------------------------------------------------------ KQL --------------
function Get-InsightsQuery([string]$ip) { @"
let ip = '$ip';
let look = ${LookbackDays}d;
let TI = union isfuzzy=true
(ThreatIntelligenceIndicator | where TimeGenerated > ago(30d)
 | where NetworkIP == ip or NetworkSourceIP == ip or NetworkDestinationIP == ip
 | where Active == true | summarize arg_max(TimeGenerated, *) by IndicatorId
 | project Source = 'Threat Intel', Detail = strcat('TI match - ', coalesce(Description, 'indicator'), ' | type: ', coalesce(ThreatType, 'n/a'), ' | confidence: ', tostring(ConfidenceScore), ' | feed: ', coalesce(SourceSystem, 'n/a')), Last = TimeGenerated),
(ThreatIntelIndicators | where TimeGenerated > ago(30d) | where ObservableValue == ip
 | summarize arg_max(TimeGenerated, *) by Id
 | project Source = 'Threat Intel', Detail = strcat('TI match - ', tostring(Data.description), ' | confidence: ', tostring(Confidence)), Last = TimeGenerated);
let Sightings = union isfuzzy=true
(SigninLogs | where TimeGenerated > ago(look) | where IPAddress == ip
 | summarize C = count(), U = dcount(UserPrincipalName), F = countif(ResultType != '0'), Users = make_set(UserPrincipalName, 8), Last = max(TimeGenerated)
 | where C > 0 | project Source = 'SigninLogs', Detail = strcat(C, ' sign-ins, ', U, ' user(s), ', F, ' failed | ', tostring(Users)), Last),
(AADNonInteractiveUserSignInLogs | where TimeGenerated > ago(look) | where IPAddress == ip
 | summarize C = count(), U = dcount(UserPrincipalName), Last = max(TimeGenerated)
 | where C > 0 | project Source = 'NonInteractiveSignIn', Detail = strcat(C, ' sign-ins, ', U, ' user(s)'), Last),
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
| take 60
"@ }

function Get-SigninQuery([string]$ip) { @"
let ip = '$ip';
let look = ${LookbackDays}d;
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
    TrustedLocation = case(N has 'trustedNamedLocation', 'Trusted named location', N has 'namedLocation', 'Named location (not trusted)', 'Unknown'),
    KnownIP = iff(priorCount > 0, strcat('Yes - ', priorCount, ' prior sign-ins in the previous 90d'), 'No - first observed in this window'),
    IPAddressStatus = case(priorCount > 0 and N has 'trustedNamedLocation', 'Known and trusted IP address', priorCount > 0, 'Known IP address', 'Unknown IP address'),
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
| take 1
"@ }

# ------------------------------------------------------------------ lookups ----------
function Get-Geo([string]$ip) {
    # Sentinel's own enrichment API - no key, no external egress, free with Sentinel.
    $path = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/" +
            "Microsoft.SecurityInsights/enrichment/ip/geodata/?ipAddress=$ip&api-version=2023-02-01-preview"
    try {
        $r = Invoke-AzRestMethod -Method GET -Path $path
        if ($r.StatusCode -ge 300) { Write-Warning "Geodata lookup failed for $ip ($($r.StatusCode))"; return $null }
        return ($r.Content | ConvertFrom-Json)
    } catch { Write-Warning "Geodata lookup failed for $ip"; $null }
}

$script:TorExits = @{}
function Initialize-TorList {
    try {
        $txt = Invoke-RestMethod -Uri $TorExitListUrl -TimeoutSec 30
        foreach ($line in ($txt -split "`n")) {
            $ipx = $line.Trim(); if ($ipx) { $script:TorExits[$ipx] = $true }
        }
        Write-Host "Loaded $($script:TorExits.Count) Tor exit nodes." -ForegroundColor DarkGray
    } catch { Write-Warning 'Tor exit list unavailable - the Tor check will report No.' }
}
function Test-TorExit([string]$ip) { return $script:TorExits.ContainsKey($ip) }
function Test-Hosting($geo) {
    $o = "$($geo.organizationType)".ToLower(); $r = "$($geo.ipRoutingType)".ToLower()
    return ($o -match 'hosting|data ?cent(er|re)' -or $r -match 'hosting')
}
function Test-Mobile($geo) {
    $o = "$($geo.organizationType)".ToLower(); $r = "$($geo.ipRoutingType)".ToLower()
    return ($r -match 'mobile|wireless' -or $o -match 'cellular')
}
function Get-Rdap([string]$ip) {
    try { Invoke-RestMethod -Uri "https://rdap.org/ip/$ip" -Headers @{Accept='application/rdap+json'} -TimeoutSec 20 }
    catch { Write-Warning "RDAP lookup failed for $ip"; $null }
}
function Get-Abuse([string]$ip) {
    if (-not $AbuseIPDBApiKey) { return $null }
    try { (Invoke-RestMethod -Uri "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip&maxAgeInDays=90" `
             -Headers @{Key=$AbuseIPDBApiKey; Accept='application/json'} -TimeoutSec 25).data }
    catch { Write-Warning "AbuseIPDB lookup failed for $ip"; $null }
}
function Get-VT([string]$ip) {
    if (-not $VirusTotalApiKey) { return $null }
    try { (Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/ip_addresses/$ip" `
             -Headers @{'x-apikey'=$VirusTotalApiKey} -TimeoutSec 25).data.attributes }
    catch { Write-Warning "VirusTotal lookup failed for $ip"; $null }
}

# ------------------------------------------------------------------ render -----------
function New-IpBlock([string]$ip) {
    $geo   = Get-Geo   $ip
    $rdap  = Get-Rdap  $ip
    $abuse = Get-Abuse $ip
    $vt    = Get-VT    $ip
    $rows  = Invoke-Kql (Get-InsightsQuery $ip)
    $si    = (Invoke-Kql (Get-SigninQuery $ip)) | Select-Object -First 1

    $tiCount    = @($rows | Where-Object { $_.Source -eq 'Threat Intel' }).Count
    $abuseScore = if ($abuse) { [int]$abuse.abuseConfidenceScore } else { 0 }
    $vtMal      = if ($vt) { [int]$vt.last_analysis_stats.malicious } else { 0 }
    $riskLevel  = if ($si) { "$($si.RiskLevel)".ToLower() } else { '' }
    $ipStatus   = if ($si) { "$($si.IPAddressStatus)" } else { '' }
    $isTor      = Test-TorExit $ip
    $isHosting  = if ($geo) { Test-Hosting $geo } else { $false }
    $isMobile   = if ($geo) { Test-Mobile  $geo } else { $false }

    if ($tiCount -gt 0 -or $vtMal -gt 0 -or $abuseScore -ge 50 -or $isTor -or $riskLevel -eq 'high') {
        $verdict = 'HIGH'; $colour = '#a4262c'
    } elseif ($isHosting -or $abuseScore -ge 25 -or
              $riskLevel -eq 'medium' -or $ipStatus -like 'Unknown*') {
        $verdict = 'MEDIUM'; $colour = '#986f0b'
    } else { $verdict = 'LOW'; $colour = '#107c10' }
    $torCell = if ($isTor) { '<b style="color:#a4262c">Yes &mdash; known Tor exit node</b>' } else { 'No' }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append("<hr style=`"border:0;border-top:1px solid #e1dfdd;margin:16px 0`">")
    [void]$sb.Append("<div style=`"font-family:Segoe UI,Arial,sans-serif;font-size:14px;font-weight:600;margin-bottom:6px`">")
    [void]$sb.Append("IP enrichment &mdash; <code>$(Enc $ip)</code>")
    [void]$sb.Append("<span style=`"display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;color:#fff;margin-left:6px;background:$colour`">$verdict</span></div>")
    [void]$sb.Append("<div style=`"font-family:Segoe UI,Arial,sans-serif;font-size:11px;color:#605e5c;margin-bottom:10px`">")
    [void]$sb.Append("Signals: $tiCount TI match(es) &middot; AbuseIPDB $abuseScore% &middot; VT malicious $vtMal &middot; Tor exit: $(if ($isTor) {'yes'} else {'no'}) &middot; $(@($rows).Count) workspace insight row(s)</div>")

    # geolocation - Sentinel enrichment API
    [void]$sb.Append("<div style=`"$($S.h4)`"><b>Geolocation</b> <span style=`"font-weight:400;color:#605e5c`">(Microsoft Sentinel enrichment API &mdash; confidence 0-100 where shown)</span></div><table style=`"$($S.tbl)`">")
    [void]$sb.Append("<tr><th style=`"$($S.th)`">Organization</th><td style=`"$($S.td)`">$(Enc $geo.organization)</td><th style=`"$($S.th)`">Organization type</th><td style=`"$($S.td)`">$(Enc $geo.organizationType '-')</td></tr>")
    [void]$sb.Append("<tr><th style=`"$($S.th)`">City</th><td style=`"$($S.td)`">$(Enc $geo.city) <span style=`"color:#605e5c`">(cf $(Enc $geo.cityCf '-'))</span></td><th style=`"$($S.th)`">Country</th><td style=`"$($S.td)`">$(Enc $geo.country) <span style=`"color:#605e5c`">(cf $(Enc $geo.countryCf '-'))</span></td></tr>")
    [void]$sb.Append("<tr><th style=`"$($S.th)`">State</th><td style=`"$($S.td)`">$(Enc $geo.state) <span style=`"color:#605e5c`">($(Enc $geo.stateCode '-'), cf $(Enc $geo.stateCf '-'))</span></td><th style=`"$($S.th)`">Continent</th><td style=`"$($S.td)`">$(Enc $geo.continent)</td></tr>")
    [void]$sb.Append("<tr><th style=`"$($S.th)`">Region</th><td style=`"$($S.td)`">$(Enc $geo.region '-')</td><th style=`"$($S.th)`">Coordinates</th><td style=`"$($S.td)`"><a href=`"https://www.bing.com/maps?cp=$($geo.latitude)~$($geo.longitude)&amp;lvl=9`">$(Enc $geo.latitude), $(Enc $geo.longitude)</a></td></tr></table>")

    # network
    [void]$sb.Append("<div style=`"$($S.h4)`"><b>Network / ASN</b></div><table style=`"$($S.tbl)`">")
    [void]$sb.Append("<tr><th style=`"$($S.th)`">ASN</th><td style=`"$($S.td)`">$(Enc $geo.asn)</td><th style=`"$($S.th)`">Carrier</th><td style=`"$($S.td)`">$(Enc $geo.carrier)</td></tr>")
    [void]$sb.Append("<tr><th style=`"$($S.th)`">Routing type</th><td style=`"$($S.td)`">$(Enc $geo.ipRoutingType '-')</td><th style=`"$($S.th)`">RIR network</th><td style=`"$($S.td)`">$(Enc $rdap.name) ($(Enc $rdap.handle))</td></tr>")
    [void]$sb.Append("<tr><th style=`"$($S.th)`">Range</th><td style=`"$($S.td)`">$(Enc $rdap.startAddress) &ndash; $(Enc $rdap.endAddress)</td><th style=`"$($S.th)`">Allocation</th><td style=`"$($S.td)`">$(Enc $rdap.type)</td></tr>")
    [void]$sb.Append("<tr><th style=`"$($S.th)`">Tor exit node</th><td style=`"$($S.td)`">$torCell</td><th style=`"$($S.th)`">Hosting / datacentre</th><td style=`"$($S.td)`">$(YesNo $isHosting)</td></tr>")
    [void]$sb.Append("<tr><th style=`"$($S.th)`">Mobile / wireless</th><td style=`"$($S.td)`">$(YesNo $isMobile)</td><th style=`"$($S.th)`">Geo lookup</th><td style=`"$($S.td)`">$(if ($geo) {'ok'} else {'<span style=\"color:#a4262c\">failed</span>'})</td></tr></table>")

    # sign-in context
    [void]$sb.Append("<div style=`"$($S.h4)`"><b>Sign-in context</b> <span style=`"font-weight:400;color:#605e5c`">(most recent sign-in from this IP)</span></div>")
    if ($si) {
        [void]$sb.Append("<table style=`"$($S.tbl)`">")
        [void]$sb.Append("<tr><th style=`"$($S.th)`">User</th><td style=`"$($S.td)`">$(Enc $si.SignInUser)</td><th style=`"$($S.th)`">Sign-in time (UTC)</th><td style=`"$($S.td)`">$(Enc $si.SignInTime)</td></tr>")
        [void]$sb.Append("<tr><th style=`"$($S.th)`">Application</th><td style=`"$($S.td)`">$(Enc $si.SignInApp)</td><th style=`"$($S.th)`">Result</th><td style=`"$($S.td)`">$(Enc $si.SignInResult)</td></tr>")
        [void]$sb.Append("<tr><th style=`"$($S.th)`">IP address status</th><td style=`"$($S.td)`"><b>$(Enc $si.IPAddressStatus)</b></td><th style=`"$($S.th)`">IP trusted location</th><td style=`"$($S.td)`">$(Enc $si.TrustedLocation)</td></tr>")
        [void]$sb.Append("<tr><th style=`"$($S.th)`">Known IP</th><td style=`"$($S.td)`">$(Enc $si.KnownIP)</td><th style=`"$($S.th)`">Country code (sign-in)</th><td style=`"$($S.td)`">$(Enc $si.CountryCode)</td></tr>")
        [void]$sb.Append("<tr><th style=`"$($S.th)`">Is proxy / anonymiser</th><td style=`"$($S.td)`">$torCell</td><th style=`"$($S.th)`">Is hosting / datacentre</th><td style=`"$($S.td)`">$(YesNo $isHosting)</td></tr>")
        [void]$sb.Append("<tr><th style=`"$($S.th)`">Device trust</th><td style=`"$($S.td)`">$(Enc $si.DeviceTrust)</td><th style=`"$($S.th)`">Device name</th><td style=`"$($S.td)`">$(Enc $si.DeviceName)</td></tr>")
        [void]$sb.Append("<tr><th style=`"$($S.th)`">Compliant / managed</th><td style=`"$($S.td)`">$(Enc $si.DeviceCompliant 'unknown') / $(Enc $si.DeviceManaged 'unknown')</td><th style=`"$($S.th)`">Device ID</th><td style=`"$($S.td)`">$(Enc $si.DeviceId)</td></tr>")
        [void]$sb.Append("<tr><th style=`"$($S.th)`">Operating system</th><td style=`"$($S.td)`">$(Enc $si.OperatingSystem)</td><th style=`"$($S.th)`">Browser</th><td style=`"$($S.td)`">$(Enc $si.Browser)</td></tr>")
        [void]$sb.Append("<tr><th style=`"$($S.th)`">User agent</th><td style=`"$($S.td)`" colspan=`"3`"><code style=`"font-size:11px`">$(Enc $si.AgentString 'not recorded')</code></td></tr>")
        [void]$sb.Append("<tr><th style=`"$($S.th)`">Sign-in risk</th><td style=`"$($S.td)`">$(Enc $si.RiskLevel 'none') (state: $(Enc $si.RiskState 'none'), detail: $(Enc $si.RiskDetail 'none'))</td><th style=`"$($S.th)`">Risk events</th><td style=`"$($S.td)`">$(Enc $si.RiskEvents '[]')</td></tr>")
        [void]$sb.Append("<tr><th style=`"$($S.th)`">Conditional Access</th><td style=`"$($S.td)`">$(Enc $si.ConditionalAccess)</td><th style=`"$($S.th)`">Auth requirement</th><td style=`"$($S.td)`">$(Enc $si.AuthRequirement)</td></tr></table>")
    } else {
        [void]$sb.Append("<table style=`"$($S.tbl)`"><tr><td style=`"$($S.td)`">No Entra ID sign-in from this IP in the last $LookbackDays days (or SigninLogs is not collected).</td></tr></table>")
    }

    # reputation
    if ($abuse -or $vt) {
        [void]$sb.Append("<div style=`"$($S.h4)`"><b>Reputation</b></div><table style=`"$($S.tbl)`">")
        if ($abuse) {
            [void]$sb.Append("<tr><th style=`"$($S.th)`">AbuseIPDB</th><td style=`"$($S.td)`">Confidence of abuse: <b>$abuseScore%</b> &nbsp;|&nbsp; $(Enc $abuse.totalReports '0') report(s) from $(Enc $abuse.numDistinctUsers '0') reporter(s) &nbsp;|&nbsp; usage: $(Enc $abuse.usageType) &nbsp;|&nbsp; domain: $(Enc $abuse.domain) &nbsp;|&nbsp; Tor: $(Enc $abuse.isTor 'false') &nbsp;|&nbsp; last report: $(Enc $abuse.lastReportedAt 'never')</td></tr>")
        }
        if ($vt) {
            [void]$sb.Append("<tr><th style=`"$($S.th)`">VirusTotal</th><td style=`"$($S.td)`"><b>$vtMal</b> malicious / $(Enc $vt.last_analysis_stats.suspicious '0') suspicious / $(Enc $vt.last_analysis_stats.harmless '0') harmless &nbsp;|&nbsp; community reputation: $(Enc $vt.reputation '0') &nbsp;|&nbsp; network: $(Enc $vt.network) &nbsp;|&nbsp; owner: $(Enc $vt.as_owner) &nbsp;|&nbsp; <a href=`"https://www.virustotal.com/gui/ip-address/$ip`">open in VirusTotal</a></td></tr>")
        }
        [void]$sb.Append("</table>")
    }

    # workspace insights
    [void]$sb.Append("<div style=`"$($S.h4)`"><b>Workspace insights &mdash; last $LookbackDays days</b></div><table style=`"$($S.tbl)`">")
    [void]$sb.Append("<tr><th style=`"$($S.th)`">Source</th><th style=`"$($S.th)`">Detail</th><th style=`"$($S.th)`">Last seen (UTC)</th></tr>")
    if (@($rows).Count -eq 0) {
        [void]$sb.Append("<tr><td style=`"$($S.td)`" colspan=`"3`">No results &mdash; this IP was not observed in any queried table.</td></tr>")
    } else {
        foreach ($r in $rows) {
            [void]$sb.Append("<tr><td style=`"$($S.td)`"><b>$(Enc $r.Source)</b></td><td style=`"$($S.td)`">$(Enc $r.Detail)</td><td style=`"$($S.td)`">$(Enc $r.Last)</td></tr>")
        }
    }
    [void]$sb.Append("</table>")
    return $sb.ToString()
}

$html = "<div style=`"font-family:Segoe UI,Arial,sans-serif;font-size:12px;color:#605e5c`">" +
        "Automated IP enrichment &middot; run $(Get-Date -AsUTC -Format 'yyyy-MM-dd HH:mm') UTC</div>"
Initialize-TorList
foreach ($ip in $IpAddress) { $html += (New-IpBlock $ip) }

# ------------------------------------------------------------------ output -----------
if ($PreviewOnly -or -not $incidentArmId) {
    "<html><body style=`"background:#fff;padding:20px`">$html</body></html>" |
        Set-Content -Path $PreviewPath -Encoding UTF8
    Write-Host "Preview written to $PreviewPath (nothing posted)." -ForegroundColor Yellow
    return
}

$commentId = [guid]::NewGuid().ToString()
$body = @{ properties = @{ message = $html } } | ConvertTo-Json -Depth 5 -Compress
$post = Invoke-AzRestMethod -Method PUT `
    -Path "$incidentArmId/comments/$commentId`?api-version=2023-02-01" -Payload $body
if ($post.StatusCode -ge 300) { throw "Failed to add comment: $($post.Content)" }
Write-Host "Comment added to incident $IncidentName." -ForegroundColor Green

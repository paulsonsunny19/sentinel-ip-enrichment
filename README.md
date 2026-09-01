# Sentinel IP Enrichment → Incident Comment

License-aware IP enrichment for Microsoft Sentinel. For every IP entity on an incident it writes a
single formatted comment. Business-safe sources are enabled by default; sources that need a paid or
client-specific entitlement are explicit opt-ins.

This repository also contains a separate **device enrichment playbook** for Sentinel Host entities.
It queries Defender XDR device inventory, EDR health, alerts, Vulnerability Management posture,
logons, network and process activity, plus Sentinel workspace context. See
[`README-DEVICE.md`](README-DEVICE.md) and deploy `azuredeploy-device.json`. The IP and device
playbooks are independent and can both be attached to the same incident automation rule.

## Sources and what they cost

| Source | Cost | Key | Limit | Licence note |
|---|---|---|---|---|
| **Sentinel geodata enrichment API** — geolocation, ASN, org type, routing type | included with Sentinel | none (managed identity) | 100 calls/user/hour | first-party; the lookup never leaves your tenant. Public preview. |
| **RDAP** (`rdap.org`) — RIR network, range, allocation type | free | none | none published | public registry data |
| **Tor bulk exit list** — anonymiser detection | free | none | fetched once per run | public list published by the Tor Project |
| **AbuseIPDB** — abuse confidence, reports, usage type | free tier | free key | 1,000 checks/day | free plan carries no commercial-use prohibition |
| **GreyNoise Community** — internet scanner/noise, RIOT, classification | free Community tier | Community key | 50 searches/week with a free key | optional; blank key skips the lookup |
| **Client IP context watchlist** — classification, owner, notes, override | included | none (managed identity) | your workspace | optional `IPContext` watchlist; your own data |
| **UEBA / ASIM network / ASIM DNS** — anomalous use and tenant telemetry | included when those features/data connectors are present | none (managed identity) | your workspace | your own data; missing tables/parsers fail open |
| **Workspace KQL** — TI, sightings, prior alerts, sign-in context | included | none (managed identity) | your workspace | your own data |
| **Defender XDR Advanced Hunting** — endpoint network/logons, identity, cloud apps, URL clicks, email and alert evidence | included with the relevant Defender products | Microsoft Graph managed identity | 30-day raw-data maximum; tenant hunting quotas apply | optional; requires `ThreatHunting.Read.All` application permission |
| VirusTotal | **off by default** | Premium key | 500/day, 4/min on the free key | the free public API forbids use "in business workflows that do not contribute new files" — a SOC enrichment playbook is exactly that, so leave this blank unless you hold a Premium key |
| Shodan InternetDB | **off by default** | none | public service | free InternetDB use is non-commercial; enable only when the client has Shodan Enterprise permission |

Deliberately *not* used: **ip-api.com** (free tier is non-commercial only).

## What lands in the comment

| Section | Contents |
|---|---|
| **Geolocation** | Organization + organization type, city, country, state (+ state code), continent, region, coordinates with map link — each with Microsoft's 0–100 confidence rating where provided |
| **Network / ASN** | ASN, carrier, IP routing type, RIR network name/handle/range/allocation type, Tor exit node, hosting/datacentre, mobile/wireless |
| **Sign-in context** | Most recent Entra sign-in plus a dedicated table of up to 100 distinct users seen from this IP across interactive and non-interactive sign-ins, including display name, UPN, counts, failures, applications and first/last seen. The most-recent detail also includes IP address status, trusted location, device trust/name/ID, compliance, OS/browser, risk and Conditional Access. |
| **Reputation** | AbuseIPDB, optional GreyNoise Community, optional licensed VirusTotal and Shodan InternetDB |
| **Defender XDR Advanced Hunting** | Direct Microsoft Graph results from DeviceNetworkEvents, DeviceLogonEvents, CloudAppEvents, IdentityLogonEvents, UrlClickEvents, EmailEvents and AlertEvidence—even when those events are not ingested into Log Analytics. DeviceNetworkEvents always returns an explicit `YES`/`NO`, with local/remote match counts, device names/IDs, processes, users, ports and actions. |
| **Workspace insights** | Client `IPContext` watchlist, UEBA, ASIM network/DNS, threat-intel matches, sightings across SigninLogs, non-interactive sign-ins, AzureActivity, OfficeActivity, SecurityEvent, CommonSecurityLog, DeviceNetworkEvents, VMConnection, W3CIISLog, AWSCloudTrail, and prior alerts referencing the IP |

Each IP gets a **HIGH / MEDIUM / LOW** chip:

- **HIGH** — a TI match, Tor exit node, AbuseIPDB ≥ 50, VT malicious > 0, or sign-in risk `high`
- **MEDIUM** — GreyNoise `malicious`, hosting/datacentre, AbuseIPDB ≥ 25, sign-in risk `medium`, or an unknown IP address
- **LOW** — none of the above

## Files

```
azuredeploy.json                  ARM template — the Logic App playbook (deploy this)
build_template.py                 generator for azuredeploy.json (edit here, re-run; don't hand-edit the JSON)
Invoke-SentinelIPEnrichment.ps1   standalone test/backfill script (does not call Defender XDR)
kql/IP-Insights.kql               the workspace-insights query, standalone, for tuning in the Logs blade
kql/IP-Signin-Users.kql           distinct interactive + non-interactive users observed from an IP
kql/Defender-XDR-IP-Insights.kql  the direct Defender query, for testing in Advanced Hunting
preview.html                      what the comment looks like, with sample data
make_preview.py                   regenerates preview.html

azuredeploy-device.json                    separate Host/device enrichment ARM template
build_device_template.py                   generator for the device template
kql/Defender-XDR-Device-Enrichment.kql     standalone device Advanced Hunting validation query
README-DEVICE.md                           device sources, verdict logic, permissions and deployment
```

## Deploy (about 10 minutes)

**1. Deploy the template**

```bash
az deployment group create \
  --resource-group <rg-holding-your-workspace> \
  --template-file azuredeploy.json \
  --parameters WorkspaceName=bfree-sentinel-law LookbackDays=14
```

Everything works with no keys at all. Add `AbuseIPDBApiKey=<key>` and/or
`GreyNoiseApiKey=<key>` if you want those reputation rows. Do not enable Shodan or supply a
VirusTotal key until the client's licences cover this business workflow.

**2. Grant the managed identity two roles.** The deployment outputs `ManagedIdentityPrincipalId`.

```bash
PID=$(az deployment group show -g <rg> -n azuredeploy \
      --query properties.outputs.managedIdentityPrincipalId.value -o tsv)

# post comments, and read the geodata enrichment API (Responder covers both)
az role assignment create --assignee-object-id $PID --assignee-principal-type ServicePrincipal \
  --role "Microsoft Sentinel Responder" \
  --scope /subscriptions/<sub>/resourceGroups/<rg>

# run the KQL
az role assignment create --assignee-object-id $PID --assignee-principal-type ServicePrincipal \
  --role "Log Analytics Reader" \
  --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/bfree-sentinel-law
```

**3. Optional: grant direct Defender XDR hunting permission.** Only do this when deploying with
`EnableDefenderAdvancedHunting=true`. This is a Microsoft Graph application permission—not Azure
RBAC—and requires an Entra administrator. The deployment output is the managed identity's service
principal object ID.

```powershell
$playbookPrincipalId = az deployment group show -g <rg> -n azuredeploy `
    --query properties.outputs.managedIdentityPrincipalId.value -o tsv

Connect-MgGraph -Scopes "Application.Read.All","AppRoleAssignment.ReadWrite.All"

$graphServicePrincipal = Get-MgServicePrincipal `
    -Filter "appId eq '00000003-0000-0000-c000-000000000000'" `
    -Property "id,appRoles"

$huntingRole = $graphServicePrincipal.AppRoles | Where-Object {
    $_.Value -eq "ThreatHunting.Read.All" -and
    $_.AllowedMemberTypes -contains "Application"
}

New-MgServicePrincipalAppRoleAssignment `
    -ServicePrincipalId $playbookPrincipalId `
    -PrincipalId $playbookPrincipalId `
    -ResourceId $graphServicePrincipal.Id `
    -AppRoleId $huntingRole.Id
```

Managed-identity tokens are cached, so allow time for the new role to propagate before testing.

**4. Authorise the two API connections.** Both are pre-configured for managed identity but each needs
one click: *Logic App → API connections → MicrosoftSentinel-… / AzureMonitorLogs-… → Edit API
connection → Authorize → Save*.

**5. Wire it up.** Either *Sentinel → Automation → Create automation rule* → trigger *When incident is
created* → action *Run playbook*; or open any incident → *Run playbook* to test on demand.

Sentinel needs `Microsoft Sentinel Automation Contributor` on the playbook's resource group before an
automation rule can call it; the portal offers to grant this on the automation-rule blade.

## Test before deploying

```powershell
Connect-AzAccount
./Invoke-SentinelIPEnrichment.ps1 -SubscriptionId <sub> -ResourceGroupName <rg> `
    -WorkspaceName bfree-sentinel-law -IpAddress 103.187.6.124,69.160.113.77 -PreviewOnly
# → preview.html, posts nothing
```

Drop `-PreviewOnly` and add `-IncidentName <incident guid>` to comment on a real incident.

## Parameters

| Parameter | Default | Notes |
|---|---|---|
| `PlaybookName` | `Enrich-IP-IncidentComment` | |
| `WorkspaceName` | *(required)* | Sentinel workspace |
| `WorkspaceResourceGroup` / `WorkspaceSubscriptionId` | current | set if the workspace lives elsewhere |
| `LookbackDays` | `14` | how far back sightings and sign-in context look |
| `TorExitListUrl` | Tor Project bulk exit list | point at an internal mirror if outbound access is restricted |
| `AbuseIPDBApiKey` | *(empty)* | free key, 1,000 checks/day; blank skips the row |
| `VirusTotalApiKey` | *(empty)* | leave blank — see the licence note above |
| `GreyNoiseApiKey` | *(empty)* | Community key; blank skips the row |
| `EnableShodanInternetDB` | `false` | enable only with Shodan Enterprise permission for commercial use |
| `EnableDefenderAdvancedHunting` | `false` | direct Microsoft Graph query; requires `ThreatHunting.Read.All` application permission |
| `DefenderLookbackDays` | `14` | Defender raw-data lookback, from 1 to 30 days |
| `IPContextWatchlistAlias` | `IPContext` | set blank to disable; `SearchKey` must contain the IP |

## Optional client IP watchlist

Create a Sentinel watchlist with alias `IPContext` (or change the parameter). Set `SearchKey` to the
IP address and use these recommended CSV columns: `Classification`, `Owner`, `Description`,
`RiskOverride`, and `ValidUntil`. The playbook treats `knownbad`, `malicious`, and `block`
classifications as a highlighted workspace row; it does not automatically override the incident
severity or the external reputation verdict.

## Things worth knowing

- **Nothing is fatal.** Every lookup, workspace query and Defender query runs with failure tolerated — a rate-limited
  API, a blocked egress path, or a table you don't collect degrades that one section to "lookup
  failed" / "No results" rather than failing the run. `union isfuzzy=true` is what makes missing
  tables safe.
- **The geodata API is capped at 100 calls per user per hour**, counted against the playbook's managed
  identity. That's roughly 100 IP entities an hour across all incidents. If you're busier than that,
  cache results in a watchlist or accept that the geo section degrades during bursts.
- **Proxy/VPN detection is narrower than a paid feed.** Free sources give you Tor exit nodes reliably
  and hosting/datacentre by inference from `organizationType` and `ipRoutingType`. Commercial VPN
  exit nodes that aren't in a datacentre range won't be flagged. If that matters, the honest upgrade
  is a paid feed — no free source covers it well.
- **"IP address status" and "Known IP" are derived**, not fields Entra hands you. The query counts
  sign-ins from the same IP between 90 days ago and the start of the lookback window: any prior
  sign-in ⇒ *Known IP address*, plus a trusted named location ⇒ *Known and trusted*. Change the
  `hist = 90d` line to move that baseline.
- **The sign-in user table combines `SigninLogs` and `AADNonInteractiveUserSignInLogs`.** It returns
  display name, UPN, interactive/non-interactive counts, failures, applications and first/last seen
  for up to 100 distinct users per IP. The cap prevents a shared proxy or NAT address from exceeding
  Sentinel's practical incident-comment size; use `kql/IP-Signin-Users.kql` and remove its final
  `take 100` when an uncapped analyst export is required.
- **No extra Azure RBAC is required for the workspace-native enrichments.** `Log Analytics Reader` covers
  the Watchlist, BehaviorAnalytics and normalized ASIM queries. UEBA and the relevant data
  connectors/parsers still need to be enabled for those rows to return data. Direct Defender
  Advanced Hunting is different: it requires the Entra application-role assignment
  `ThreatHunting.Read.All` on the managed identity.
- **Defender results are a separate section and do not currently change HIGH/MEDIUM/LOW.** This
  avoids automatically changing a client incident verdict before its Defender data has been tested.
  The query is capped at 60 summarized rows per IP and `DefenderLookbackDays` cannot exceed 30.
  Its DeviceNetworkEvents row is always present: `YES` means the IP matched a Defender endpoint's
  local or remote address; `NO` means no matching endpoint network events were found in the selected
  Defender lookback, not that the IP is universally safe.
- **Defender hunting telemetry is protected in Logic App run history.** The direct Microsoft Graph
  action uses secure inputs and outputs; the selected summary is intentionally posted to the
  Sentinel incident comment for analysts who can access that incident.
- **API-key inputs are secured in run history.** AbuseIPDB, VirusTotal, and GreyNoise HTTP actions
  use secure inputs so their headers aren't displayed to operators viewing a run.
- **Private/internal IPs** return no geodata. If most of your entities are RFC1918, filter them at the
  top of the loop.
- **Edit `build_template.py`, not `azuredeploy.json`.** The JSON is generated; the HTML and KQL are
  far easier to read in the Python source. Re-run `python3 build_template.py` after changes.

## Obvious extensions

- Tag the incident (`Add labels to incident`) when the verdict is HIGH
- Raise incident severity on a TI match or Tor exit node
- Add a second `Entities - Get Accounts` loop with matching account enrichment
- Load additional free blocklists (Spamhaus DROP, blocklist.de) into a watchlist and join in the KQL

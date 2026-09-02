# Sentinel IP Enrichment → Incident Comment

License-aware IP enrichment for Microsoft Sentinel. For every IP entity on an incident it writes a
single formatted comment. Business-safe sources are enabled by default; sources that need a paid or
client-specific entitlement are explicit opt-ins.

This repository also contains a separate **device enrichment playbook** for Sentinel Host entities.
It queries Defender XDR device inventory, EDR health, alerts, Vulnerability Management posture,
logons, network and process activity, plus Sentinel workspace context. See
[`README-DEVICE.md`](README-DEVICE.md) and deploy `azuredeploy-device.json`. The IP and device
playbooks are independent and can both be attached to the same incident automation rule.

A third, separate **URL enrichment playbook** enriches Sentinel URL entities with the maximum
practical set of sources: Microsoft Defender Threat Intelligence (MDTI), Defender XDR URL activity,
VirusTotal, Google Safe Browsing, urlscan.io, PhishTank, and Sentinel threat intelligence/workspace
sightings. See [`README-URL.md`](README-URL.md) and deploy `azuredeploy-url.json`.

A fourth, separate **file hash enrichment playbook** enriches Sentinel FileHash entities
(SHA256/SHA1/MD5) with Defender's native `FileProfile()` file intelligence, Defender XDR file/process
activity, and Sentinel threat intelligence and workspace sightings. See
[`README-FILEHASH.md`](README-FILEHASH.md) and deploy `azuredeploy-filehash.json`.

A fifth, separate **reported email enrichment playbook** enriches Sentinel Mail message entities
(e.g. user-reported phishing) with the full Defender XDR email record — delivery, threat
classification, authentication results, attachments, contained URLs, Safe Links click-through,
post-delivery remediation — plus MDTI sender-domain reputation and Sentinel threat
intelligence/workspace sightings. See [`README-EMAIL.md`](README-EMAIL.md) and deploy
`azuredeploy-email.json`.

A sixth, separate **account (user) enrichment playbook** enriches Sentinel Account entities with
the Entra ID profile (name, job title, office/city/state/country, manager, directory roles),
registered devices, MFA/SSPR registration posture, Entra ID Protection identity risk (including
recent risk detections), out-of-office status, and Sentinel-workspace sign-in activity (including
failed-MFA and MFA-fraud-reported counts) — deliberately without IP-address reputation lookups,
which stay in the dedicated IP playbook. See [`README-ACCOUNT.md`](README-ACCOUNT.md) and deploy
`azuredeploy-account.json`.

All six playbooks — IP, device, URL, file hash, email, and account — are independent and can all be
attached to the same incident automation rule.

## Deploy all six in one go

`azuredeploy-all.json` deploys all six playbooks as one ARM deployment (each as a nested
deployment, still with its own dedicated connections) — one `az deployment group create` call
instead of six. Every parameter each playbook has (beyond the shared identity/workspace ones) is
exposed here too, not just the URL playbook's API keys:

```bash
az deployment group create \
  --name sentinel-enrichment-all \
  --resource-group "$SENTINEL_RG" \
  --template-file azuredeploy-all.json \
  --parameters WorkspaceName="$WORKSPACE" \
               UserAssignedManagedIdentityResourceId="$UAMI_ID" \
               AbuseIPDBApiKey="$ABUSEIPDB_KEY" \
               VirusTotalApiKey="$VT_KEY" \
               GreyNoiseApiKey="$GREYNOISE_KEY" \
               GoogleSafeBrowsingApiKey="$GSB_KEY"
```
*(only the parameters you want to override need to be listed — every other parameter keeps its own default)*

Three kinds of parameter handling:

- **Always shared** (identical everywhere): `UserAssignedManagedIdentityResourceId`, `WorkspaceName`,
  `WorkspaceResourceGroup`, `WorkspaceSubscriptionId`.
- **Deliberately merged** into one shared parameter, applied to every playbook that has it:
  `LookbackDays`, `DefenderLookbackDays`, `EnableMicrosoftThreatIntelligence` (URL + Email),
  `VirusTotalApiKey` (IP + URL — same VirusTotal account, different endpoints), and
  `EnableDefenderAdvancedHunting` (IP, Device, URL, FileHash, Email). **Note**: this template
  defaults `EnableDefenderAdvancedHunting` to `true` for all five — the IP playbook defaults it to
  `false` when deployed standalone (`azuredeploy.json`), since it's the one that needs the extra
  Graph permission/quota most narrowly. Pass `EnableDefenderAdvancedHunting=false` at deploy time if
  you don't want that change.
- **Everything else keeps its own name** — `AbuseIPDBApiKey`, `GreyNoiseApiKey`,
  `EnableShodanInternetDB` (IP); `DeviceContextWatchlistAlias` (Device); `EnablePhishTank`,
  `EnableUrlscanSearch`, `GoogleSafeBrowsingApiKey`, `PhishTankAppKey`, `UrlscanApiKey`,
  `URLContextWatchlistAlias` (URL); `FileHashContextWatchlistAlias` (FileHash);
  `EmailContextWatchlistAlias` (Email); `EnableIdentityProtection`, `EnableMailboxSettings`,
  `EnableMfaMethods`, `EnableRegisteredDevices`, `EnableSigninHistory`, `EnableUserProfile`,
  `UserContextWatchlistAlias` (Account) — 36 master parameters in total. `PlaybookName` is the one
  exception that can't be shared (each Logic App needs a distinct resource name), so it's exposed
  per playbook instead: `IPPlaybookName`, `DevicePlaybookName`, `UrlPlaybookName`,
  `FileHashPlaybookName`, `EmailPlaybookName`, `AccountPlaybookName`, each still defaulting to that
  playbook's own original name.

To change a parameter after deployment, either redeploy `azuredeploy-all.json` with new values, or
redeploy that playbook's own `azuredeploy-*.json` directly — both target the same resource names,
so either updates in place rather than creating a duplicate. Generated by
`build_master_template.py`, which re-runs the six individual generators first so it never embeds
stale JSON, and asserts at build time that no parameter name collides across playbooks without
being explicitly merged or prefixed.

## Automation rules — one per entity type

Every playbook already self-gates: if you attach all six to a single "run always" automation rule,
each one still checks its own entity list and simply produces no comment when the incident has no
matching entity (e.g. the URL playbook does nothing on an incident with only an IP entity). So a
single catch-all rule is correct, and no automation rule change is required to make any of this
work.

Splitting into six entity-conditional rules is optional, but worth doing for two reasons: it avoids
firing (and paying for) a playbook run that can only ever no-op, and it makes the incident's run
history readable — only the playbooks that actually enriched something show up.

### Option A — deploy `azuredeploy-automation-rules.json`

Generated by `build_automation_rules_template.py`. Creates all six rules as ARM resources
(`Microsoft.OperationalInsights/workspaces/providers/automationRules`) directly in your Sentinel
workspace, each condition-matched against the property names Sentinel's automation rule engine
actually supports (verified against the `Microsoft.SecurityInsights` resource provider's schema,
not just the Portal's field labels):

```bash
az deployment group create \
  --name sentinel-enrichment-automation-rules \
  --resource-group "$SENTINEL_RG" \
  --template-file azuredeploy-automation-rules.json \
  --parameters WorkspaceName="$WORKSPACE"
```

Each rule has its own `Enable<X>Rule` parameter (default `true`) — set it to `false` for any
playbook you haven't deployed, so its rule is skipped rather than pointing at a Logic App that
doesn't exist. The `<X>PlaybookName` parameters (e.g. `IPPlaybookName`) default to each playbook's
own standalone default name and only need overriding if you deployed under a custom name.

### Option B — build them by hand in the Sentinel Portal

1. **Sentinel → Automation → Create → Automation rule.**
2. **Trigger**: `When incident is created`.
3. **Conditions → Add → Entity**: pick the entity category, then a property on it, operator
   `Contains`, and leave the value blank. An empty-value `Contains` matches any incident that has at
   least one entity of that type/property present — it's an existence check, not a text match.
   (Sentinel's automation rule conditions have no dedicated "exists" operator, so this is the
   standard way to do it.)
4. **Actions → Add action → Run playbook**, and pick the matching playbook below.
5. Save. Repeat for each of the six entity types (six separate automation rules).

| Incident has entity... | Condition (category → property) | Operator | Value | Run playbook |
|---|---|---|---|---|
| IP address | Entity → IP address → Address | Contains | *(blank)* | `Enrich-IP-IncidentComment` |
| Host | Entity → Host → Host name | Contains | *(blank)* | `Enrich-Device-IncidentComment` |
| URL / domain name | Entity → URL → Url | Contains | *(blank)* | `Enrich-URL-IncidentComment` |
| File hash | Entity → File hash → Value | Contains | *(blank)* | `Enrich-FileHash-IncidentComment` |
| Mail message | Entity → Mail message → Recipient | Contains | *(blank)* | `Enrich-Email-IncidentComment` |
| Account | Entity → Account → AAD user ID (or Name) | Contains | *(blank)* | `Enrich-Account-IncidentComment` |

*(Mail message entities have no "network message ID" condition property in the automation rule
engine, so Recipient is used as the existence check instead — every mail message entity has at
least one. File hash entities likewise only expose the hash Value as a condition property, not the
algorithm.)*

The playbook names above are the ARM template defaults (`PlaybookName` parameter, or the
per-playbook `*PlaybookName` parameters in `azuredeploy-all.json`) — if you deployed with a custom
name, pick that Logic App in the action instead. An incident with several entity types (e.g. an IP
and a file hash) simply matches several rules and runs several playbooks, each posting its own
comment.

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

azuredeploy-url.json                       separate URL enrichment ARM template
build_url_template.py                      generator for the URL template
kql/Defender-XDR-URL-Enrichment.kql        standalone Defender URL validation query
README-URL.md                              URL sources, verdict logic, permissions and deployment

azuredeploy-filehash.json                  separate file hash enrichment ARM template
build_filehash_template.py                 generator for the file hash template
kql/Defender-XDR-FileHash-Enrichment.kql   standalone Defender file hash validation query
README-FILEHASH.md                         file hash sources, verdict logic, permissions and deployment

azuredeploy-email.json                     separate reported-email enrichment ARM template
build_email_template.py                    generator for the email template
kql/Defender-XDR-Email-Enrichment.kql      standalone Defender email validation query
README-EMAIL.md                            email sources, verdict logic, permissions and deployment

azuredeploy-account.json                   separate Account (user) enrichment ARM template
build_account_template.py                  generator for the account template
kql/User-Signin-Insights.kql               standalone sign-in validation query
README-ACCOUNT.md                          account sources, verdict logic, permissions and deployment

azuredeploy-all.json                       deploys all six playbooks as one nested deployment
build_master_template.py                   generator for the combined template

azuredeploy-automation-rules.json          optional: six entity-conditional automation rules
build_automation_rules_template.py         generator for the automation rules template
```

## Deploy (about 10 minutes)

**1. Deploy the template**

The IP playbook is user-assigned-managed-identity-only. Create the identity first (or select an
existing client-owned identity), then pass its full resource ID. The template does not enable a
system-assigned identity.

```bash
UAMI_ID=$(az identity show \
  --resource-group <identity-resource-group> \
  --name <identity-name> \
  --query id -o tsv)

az deployment group create \
  --resource-group <rg-holding-your-workspace> \
  --template-file azuredeploy.json \
  --parameters WorkspaceName=bfree-sentinel-law \
               LookbackDays=14 \
               UserAssignedManagedIdentityResourceId="$UAMI_ID"
```

The user-assigned identity must already exist in the client's tenant and subscription. The
deployment principal needs permission to write the Logic App and `Managed Identity Operator` (or
the equivalent `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action`) over that identity.
The user-assigned identity is attached to the Logic App and explicitly used by the Microsoft
Sentinel connector, Azure Monitor Logs connector, Sentinel geodata HTTP call and Microsoft Graph
Defender Advanced Hunting call. External services such as AbuseIPDB, GreyNoise and VirusTotal do
not accept Azure managed identity tokens and still require their own optional API keys.

Everything works with no keys at all. Add `AbuseIPDBApiKey=<key>` and/or
`GreyNoiseApiKey=<key>` if you want those reputation rows. Do not enable Shodan or supply a
VirusTotal key until the client's licences cover this business workflow.

**2. Grant the user-assigned managed identity two roles.** The deployment outputs its service
principal object ID as `ManagedIdentityPrincipalId`.

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
| `UserAssignedManagedIdentityResourceId` | *(required)* | full resource ID of one existing client-owned UAMI; the template never enables a system-assigned identity |
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

- **One comment per IP entity, not one per incident.** Each entity's comment posts as soon as its
  own enrichment finishes, right inside the loop — an incident with several IPs gets several
  comments, not one giant one. This also keeps every comment under Sentinel's 30,000-character
  `/Incidents/Comment` limit; if one entity's own data is still unusually large, that single
  comment is truncated at 28,000 characters with a note, rather than the whole comment failing.
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

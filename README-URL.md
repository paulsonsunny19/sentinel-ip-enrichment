# Sentinel URL Enrichment → Incident Comment

This is a separate Microsoft Sentinel playbook for **URL entities**, built to pull in the maximum
practical set of enrichment for a URL: Microsoft's own threat intelligence and Defender telemetry,
plus every community/vendor URL reputation source that doesn't require a paid tier by default. It
uses one required, client-owned **user-assigned managed identity (UAMI)** for the Logic App,
Microsoft Sentinel and Azure Monitor Logs connections, Microsoft Defender Threat Intelligence, and
Defender XDR Advanced Hunting. It never enables a system-assigned identity.

The URL, IP, device, and file hash playbooks are independent, so all four can run from the same
incident automation rule.

## What it adds

| Source | URL enrichment placed in the incident comment | Default |
|---|---|---|
| **Microsoft Defender Threat Intelligence (MDTI)** | Host reputation/classification and score, attributed reputation rules and report links, first/last seen, WHOIS, passive DNS, trackers, cookies, and detected web components | on — needs `ThreatIntelligence.Read.All` |
| **Defender XDR Advanced Hunting** | Safe Links clicks and users, click-through actions and threat labels, email URL references, devices/processes/IPs connecting to the URL, and alert evidence | on — needs `ThreatHunting.Read.All` |
| **VirusTotal** | Community engine detection counts (malicious/suspicious/harmless/undetected), reputation score, categories | off — needs a **Premium** key |
| **Google Safe Browsing** | Google's own malware/social-engineering/unwanted-software/PHA threat-match verdicts | off — needs a free key |
| **urlscan.io** | Prior public scans of the host: count, how many were flagged malicious, most recent scan's resolved IP/ASN/country | on — free, no key required |
| **PhishTank** | Community-verified phishing database membership and verification status | on — free, no key required |
| **Sentinel workspace** | Current `ThreatIntelIndicators`, legacy TI fallback, prior alerts, Safe Links/email/device/firewall observations, and optional client watchlist context | on — included |
| **Triage** | A HIGH / MEDIUM / LOW / UNKNOWN verdict and a concise source-status summary across every source above | — |

VirusTotal and Google Safe Browsing are gated on an API key being supplied at deployment (blank
key = skipped, shown in the comment as "skipped, no API key"); urlscan.io and PhishTank are on by
default since both offer a genuinely free, keyless lookup tier, but each has its own boolean toggle
(`EnableUrlscanSearch`, `EnablePhishTank`) to turn it off. Every source fails open independently: if
one is unavailable, rate-limited, or disabled, the rest of the comment is still produced.

MDTI's Graph enrichment endpoints are host-based. The playbook extracts the hostname from each
URL for MDTI, while retaining the complete normalized URL for Defender hunting, VirusTotal, Safe
Browsing, and workspace searches. It defangs common `hxxp` and `[.]` forms before querying and
HTML-escapes the displayed URL before it is added to the incident.

## Files

| File | Purpose |
|---|---|
| `azuredeploy-url.json` | Deployable ARM template |
| `build_url_template.py` | Source generator for the ARM template |
| `kql/Defender-XDR-URL-Enrichment.kql` | Standalone query to validate the Defender data available for one URL |

## Prerequisites and permissions

The UAMI needs the following permissions. Graph permissions are **application permissions**, not
Azure RBAC roles. VirusTotal, Google Safe Browsing, urlscan.io, and PhishTank are called with plain
HTTP and don't use the managed identity — they're gated on their own API key parameters instead.

| Scope | Permission | Used for |
|---|---|---|
| Resource group containing Sentinel | `Microsoft Sentinel Responder` | Read incident entities and post the comment |
| Log Analytics workspace | `Log Analytics Reader` | Run workspace KQL |
| Microsoft Graph | `ThreatIntelligence.Read.All` | MDTI host reputation, WHOIS, passive DNS, trackers, cookies, and components |
| Microsoft Graph | `ThreatHunting.Read.All` | Defender XDR Advanced Hunting |
| UAMI itself (deployment principal, not the UAMI) | `Managed Identity Operator` | Attach the selected UAMI to the Logic App |

The relevant Defender products must be licensed and producing data for their Advanced Hunting
tables. MDTI and Defender capabilities can also roll out at different times between tenants; a
403/404 from an MDTI call normally means the permission has not propagated or the API is not yet
available in that tenant. Workspace enrichment continues independently.

### Grant Azure RBAC

```bash
SUBSCRIPTION_ID=<subscription-id>
SENTINEL_RG=<sentinel-resource-group>
WORKSPACE=<workspace-name>
IDENTITY_RG=<identity-resource-group>
IDENTITY_NAME=<identity-name>

UAMI_ID=$(az identity show \
  --resource-group "$IDENTITY_RG" \
  --name "$IDENTITY_NAME" \
  --query id -o tsv)

UAMI_PRINCIPAL_ID=$(az identity show \
  --resource-group "$IDENTITY_RG" \
  --name "$IDENTITY_NAME" \
  --query principalId -o tsv)

az role assignment create \
  --assignee-object-id "$UAMI_PRINCIPAL_ID" \
  --assignee-principal-type ServicePrincipal \
  --role "Microsoft Sentinel Responder" \
  --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$SENTINEL_RG"

az role assignment create \
  --assignee-object-id "$UAMI_PRINCIPAL_ID" \
  --assignee-principal-type ServicePrincipal \
  --role "Log Analytics Reader" \
  --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$SENTINEL_RG/providers/Microsoft.OperationalInsights/workspaces/$WORKSPACE"
```

### Grant both Microsoft Graph application permissions

Run this as an Entra administrator that can create app-role assignments. The Microsoft Graph
service principal has app ID `00000003-0000-0000-c000-000000000000`.

```bash
GRAPH_APP_ID=00000003-0000-0000-c000-000000000000
GRAPH_SP_ID=$(az ad sp show --id "$GRAPH_APP_ID" --query id -o tsv)

for GRAPH_ROLE in ThreatIntelligence.Read.All ThreatHunting.Read.All; do
  GRAPH_ROLE_ID=$(az ad sp show \
    --id "$GRAPH_APP_ID" \
    --query "appRoles[?value=='$GRAPH_ROLE' && contains(allowedMemberTypes, 'Application')].id | [0]" \
    -o tsv)

  az rest --method post \
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$UAMI_PRINCIPAL_ID/appRoleAssignments" \
    --headers Content-Type=application/json \
    --body "{\"principalId\":\"$UAMI_PRINCIPAL_ID\",\"resourceId\":\"$GRAPH_SP_ID\",\"appRoleId\":\"$GRAPH_ROLE_ID\"}"
done
```

Allow several minutes for new role assignments and Graph permissions to propagate before testing.

### Optional third-party API keys

| Source | Where to get a key | Cost |
|---|---|---|
| VirusTotal | https://www.virustotal.com/gui/my-apikey | Free key exists but its terms forbid business-workflow use; get a **Premium** key |
| Google Safe Browsing | Enable the "Safe Browsing API" on a Google Cloud project, then create an API key | Free, generous quota |
| urlscan.io | https://urlscan.io/user/profile/ (optional — search works unauthenticated) | Free |
| PhishTank | https://www.phishtank.com/api_register.php (optional — checks work unauthenticated at a lower rate) | Free |

## Deploy

```bash
az deployment group create \
  --name sentinel-url-enrichment \
  --resource-group "$SENTINEL_RG" \
  --template-file azuredeploy-url.json \
  --parameters WorkspaceName="$WORKSPACE" \
               UserAssignedManagedIdentityResourceId="$UAMI_ID" \
               VirusTotalApiKey="$VT_KEY" \
               GoogleSafeBrowsingApiKey="$GSB_KEY"
```

Leave `VirusTotalApiKey`/`GoogleSafeBrowsingApiKey` unset to deploy without those two sources.

After deployment, open the Logic App and confirm both API connections show the selected managed
identity. Then attach the playbook to a Microsoft Sentinel incident automation rule that runs when
incidents are created or updated.

## Parameters

| Parameter | Default | Notes |
|---|---:|---|
| `PlaybookName` | `ErgoSOC-AU-URL-Enrichment` | Logic App name |
| `UserAssignedManagedIdentityResourceId` | required | Full resource ID of the existing UAMI |
| `WorkspaceName` | required | Sentinel/Log Analytics workspace |
| `WorkspaceResourceGroup` | deployment RG | Override when the workspace is in another RG |
| `WorkspaceSubscriptionId` | current subscription | Override for a cross-subscription workspace |
| `LookbackDays` | 14 | Sentinel workspace lookback, 1–90 days |
| `EnableMicrosoftThreatIntelligence` | `true` | Requires `ThreatIntelligence.Read.All` |
| `EnableDefenderAdvancedHunting` | `true` | Requires `ThreatHunting.Read.All` |
| `DefenderLookbackDays` | 14 | Defender lookback, 1–30 days |
| `URLContextWatchlistAlias` | `URLContext` | Set blank to disable the optional watchlist |
| `VirusTotalApiKey` | blank (skipped) | Premium key; free-tier ToS forbids this use case |
| `GoogleSafeBrowsingApiKey` | blank (skipped) | Free Google Cloud API key |
| `EnableUrlscanSearch` | `true` | Free, keyless search of prior public scans |
| `UrlscanApiKey` | blank | Optional; raises the urlscan.io rate limit |
| `EnablePhishTank` | `true` | Free, keyless phishing-database check |
| `PhishTankAppKey` | blank | Optional; raises the PhishTank rate limit |

## Optional client watchlist

Create a Sentinel watchlist whose alias is `URLContext`. Put either the complete normalized URL or
the hostname in `SearchKey`. Optional columns are `Classification` (or `Risk`), `Owner`, `Campaign`,
`Description` (or `Notes`), and `LastUpdated`. Values such as `critical`, `high`, `malicious`,
`knownbad`, or `phishing` raise the playbook verdict to HIGH.

## Verdict logic

- **HIGH**: MDTI malicious or score ≥ 70, a threat-tagged Safe Links click, a high Defender alert, a
  high-confidence Sentinel TI match, critical client watchlist context, any VirusTotal malicious
  detection, any Google Safe Browsing threat match, any urlscan.io scan flagged malicious, or a
  PhishTank entry that is both in the database and verified valid.
- **MEDIUM**: MDTI suspicious or score ≥ 40, a click-through, any Defender URL observation/alert,
  any workspace observation, any VirusTotal suspicious detection, any prior urlscan.io scan (even
  unflagged), or a PhishTank database hit still pending verification.
- **LOW**: MDTI reports benign or neutral and no stronger signal exists.
- **UNKNOWN**: no source returned enough information to classify the URL.

## Operational notes

- Each URL's comment posts individually, right inside the loop — an incident with several URL
  entities gets several comments, not one shared one. That keeps every comment under Sentinel's
  30,000-character `/Incidents/Comment` limit; if one URL's own data is still unusually large, that
  single comment truncates at 28,000 characters with a note instead of failing outright.
- One URL can make up to seven MDTI Graph calls, one Defender hunting call, one VirusTotal call, one
  Safe Browsing call, one urlscan.io call, one PhishTank call, and one workspace query. The URL loop
  is deliberately sequential to control quota and shared-variable updates.
- Full URLs can contain tokens or personal data in their path/query string. The incident comment
  contains the URL, and this playbook also sends it to VirusTotal, Google Safe Browsing, urlscan.io,
  and PhishTank when those sources are enabled — factor that into any client policy for sensitive
  URLs, and disable the third-party sources for tenants where sending URLs off-platform isn't
  acceptable.
- Disable either Microsoft Graph source at deployment if the tenant has not granted its permission;
  the other sources continue to work.
- If Defender returns HTTP 400, copy the query from
  `kql/Defender-XDR-URL-Enrichment.kql` into Advanced Hunting. Its use of `column_ifexists()` and
  fuzzy unions is intentional so absent optional tables/columns fail open.
- urlscan.io's search API only surfaces **prior** public scans — the playbook never submits a new
  scan, so it never publishes an otherwise-private URL to urlscan.io's public results.

# Sentinel URL Enrichment → Incident Comment

This is a separate Microsoft Sentinel playbook for **URL entities**. It uses one required,
client-owned **user-assigned managed identity (UAMI)** for the Logic App, Microsoft Sentinel and
Azure Monitor Logs connections, Microsoft Defender Threat Intelligence, and Defender XDR
Advanced Hunting. It never enables a system-assigned identity.

The URL and IP/device playbooks are independent, so all three can run from the same incident
automation rule.

## What it adds

| Source | URL enrichment placed in the incident comment |
|---|---|
| **Microsoft Defender Threat Intelligence (MDTI)** | Host reputation/classification and score, attributed reputation rules and report links, first/last seen, WHOIS, passive DNS, trackers, cookies, and detected web components |
| **Defender XDR Advanced Hunting** | Safe Links clicks and users, click-through actions and threat labels, email URL references, devices/processes/IPs connecting to the URL, and alert evidence |
| **Sentinel workspace** | Current `ThreatIntelIndicators`, legacy TI fallback, prior alerts, Safe Links/email/device/firewall observations, and optional client watchlist context |
| **Triage** | A HIGH / MEDIUM / LOW / UNKNOWN verdict and a concise source-status summary |

MDTI's Graph enrichment endpoints are host-based. The playbook extracts the hostname from each
URL for MDTI, while retaining the complete normalized URL for Defender hunting and workspace
searches. It defangs common `hxxp` and `[.]` forms before querying and HTML-escapes the displayed
URL before it is added to the incident.

## Files

| File | Purpose |
|---|---|
| `azuredeploy-url.json` | Deployable ARM template |
| `build_url_template.py` | Source generator for the ARM template |
| `kql/Defender-XDR-URL-Enrichment.kql` | Standalone query to validate the Defender data available for one URL |

## Prerequisites and permissions

The UAMI needs the following permissions. Graph permissions are **application permissions**, not
Azure RBAC roles.

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

## Deploy

```bash
az deployment group create \
  --name sentinel-url-enrichment \
  --resource-group "$SENTINEL_RG" \
  --template-file azuredeploy-url.json \
  --parameters WorkspaceName="$WORKSPACE" \
               UserAssignedManagedIdentityResourceId="$UAMI_ID"
```

After deployment, open the Logic App and confirm both API connections show the selected managed
identity. Then attach the playbook to a Microsoft Sentinel incident automation rule that runs when
incidents are created or updated.

## Parameters

| Parameter | Default | Notes |
|---|---:|---|
| `PlaybookName` | `Enrich-URL-IncidentComment` | Logic App name |
| `UserAssignedManagedIdentityResourceId` | required | Full resource ID of the existing UAMI |
| `WorkspaceName` | required | Sentinel/Log Analytics workspace |
| `WorkspaceResourceGroup` | deployment RG | Override when the workspace is in another RG |
| `WorkspaceSubscriptionId` | current subscription | Override for a cross-subscription workspace |
| `LookbackDays` | 14 | Sentinel workspace lookback, 1–90 days |
| `EnableMicrosoftThreatIntelligence` | `true` | Requires `ThreatIntelligence.Read.All` |
| `EnableDefenderAdvancedHunting` | `true` | Requires `ThreatHunting.Read.All` |
| `DefenderLookbackDays` | 14 | Defender lookback, 1–30 days |
| `URLContextWatchlistAlias` | `URLContext` | Set blank to disable the optional watchlist |

## Optional client watchlist

Create a Sentinel watchlist whose alias is `URLContext`. Put either the complete normalized URL or
the hostname in `SearchKey`. Optional columns are `Classification` (or `Risk`), `Owner`, `Campaign`,
`Description` (or `Notes`), and `LastUpdated`. Values such as `critical`, `high`, `malicious`,
`knownbad`, or `phishing` raise the playbook verdict to HIGH.

## Verdict logic

- **HIGH**: MDTI malicious or score ≥ 70, a threat-tagged Safe Links click, a high Defender alert,
  a high-confidence Sentinel TI match, or critical client watchlist context.
- **MEDIUM**: MDTI suspicious or score ≥ 40, a click-through, any Defender URL observation/alert,
  or any workspace observation.
- **LOW**: MDTI reports benign or neutral and no stronger signal exists.
- **UNKNOWN**: no source returned enough information to classify the URL.

## Operational notes

- One URL can make seven MDTI Graph calls, one Defender hunting call, and one workspace query. The
  URL loop is deliberately sequential to control quota and shared-variable updates.
- Full URLs can contain tokens or personal data in their path/query string. The incident comment
  contains the URL, so establish a client policy for redaction if those values are sensitive.
- Disable either Microsoft Graph source at deployment if the tenant has not granted its permission;
  the other sources continue to work.
- If Defender returns HTTP 400, copy the query from
  `kql/Defender-XDR-URL-Enrichment.kql` into Advanced Hunting. Its use of `column_ifexists()` and
  fuzzy unions is intentional so absent optional tables/columns fail open.


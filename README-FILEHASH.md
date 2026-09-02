# Sentinel File Hash Enrichment → Incident Comment

This is a separate Microsoft Sentinel playbook for **FileHash entities** (SHA256, SHA1, or MD5).
It uses one required, client-owned **user-assigned managed identity (UAMI)** for the Logic App,
Microsoft Sentinel and Azure Monitor Logs connections, and Defender XDR Advanced Hunting. It never
enables a system-assigned identity.

The file hash, URL, IP, and device playbooks are independent, so all four can run from the
same incident automation rule.

## Why this doesn't call the MDTI Graph API

The IP/device and URL playbooks in this repo query Microsoft Defender Threat Intelligence
(MDTI) through `security/threatIntelligence/hosts/...` in Microsoft Graph. That surface is
host-based (IP addresses and domains) and has no hash-reputation equivalent. File-hash reputation
comes from Microsoft's own threat intelligence natively inside Defender XDR Advanced Hunting, via
the built-in **`FileProfile()`** enrichment function — the same native-integration idea the blog
post this repo started from describes, reached the way Defender actually exposes it for files:
`FileProfile(hash, 1)` returns a single row with global prevalence, first/last seen, file type and
size, code-signing status (signed, certificate valid, Microsoft-rooted), signer/issuer, and
publisher, all sourced from Microsoft's file intelligence backend rather than an HTTP round trip
you construct yourself.

## What it adds

| Source | File hash enrichment placed in the incident comment |
|---|---|
| **Defender native file intelligence (`FileProfile()`)** | Global prevalence, first/last seen, file type/size, signing status, certificate validity, Microsoft-root signer, signer/issuer, publisher |
| **Defender XDR Advanced Hunting** | Device file events, process executions (as the file itself or as a parent process), AV/EDR detections and threat names, email attachment references, and alert evidence |
| **Sentinel workspace** | Current `ThreatIntelIndicators`, legacy TI fallback, prior alerts, ingested device file/email attachment sightings, and optional client watchlist context |
| **Triage** | A HIGH / MEDIUM / LOW / UNKNOWN verdict and a concise source-status summary |

The playbook accepts whichever hash algorithm the FileHash entity carries (SHA256/SHA1/MD5) and
passes it through unchanged — `FileProfile()` and the activity queries match against all three hash
columns, so the algorithm doesn't need to be known ahead of time. It HTML-escapes the displayed hash
before it is added to the incident.

## Files

| File | Purpose |
|---|---|
| `azuredeploy-filehash.json` | Deployable ARM template |
| `build_filehash_template.py` | Source generator for the ARM template |
| `kql/Defender-XDR-FileHash-Enrichment.kql` | Standalone query to validate the Defender data available for one hash |

## Prerequisites and permissions

The UAMI needs the following permissions. The Graph permission is an **application permission**,
not an Azure RBAC role.

| Scope | Permission | Used for |
|---|---|---|
| Resource group containing Sentinel | `Microsoft Sentinel Responder` | Read incident entities and post the comment |
| Log Analytics workspace | `Log Analytics Reader` | Run workspace KQL |
| Microsoft Graph | `ThreatHunting.Read.All` | Defender XDR Advanced Hunting, including `FileProfile()` |
| UAMI itself (deployment principal, not the UAMI) | `Managed Identity Operator` | Attach the selected UAMI to the Logic App |

The relevant Defender products must be licensed and producing data for their Advanced Hunting
tables. `FileProfile()` only returns a row for hashes Microsoft has telemetry on; an empty result is
expected and reported as "no FileProfile record", not an error.

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

### Grant the Microsoft Graph application permission

Run this as an Entra administrator that can create app-role assignments. The Microsoft Graph
service principal has app ID `00000003-0000-0000-c000-000000000000`.

```bash
GRAPH_APP_ID=00000003-0000-0000-c000-000000000000
GRAPH_SP_ID=$(az ad sp show --id "$GRAPH_APP_ID" --query id -o tsv)

GRAPH_ROLE=ThreatHunting.Read.All
GRAPH_ROLE_ID=$(az ad sp show \
  --id "$GRAPH_APP_ID" \
  --query "appRoles[?value=='$GRAPH_ROLE' && contains(allowedMemberTypes, 'Application')].id | [0]" \
  -o tsv)

az rest --method post \
  --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$UAMI_PRINCIPAL_ID/appRoleAssignments" \
  --headers Content-Type=application/json \
  --body "{\"principalId\":\"$UAMI_PRINCIPAL_ID\",\"resourceId\":\"$GRAPH_SP_ID\",\"appRoleId\":\"$GRAPH_ROLE_ID\"}"
```

Allow several minutes for new role assignments and Graph permissions to propagate before testing.

## Deploy

```bash
az deployment group create \
  --name sentinel-filehash-enrichment \
  --resource-group "$SENTINEL_RG" \
  --template-file azuredeploy-filehash.json \
  --parameters WorkspaceName="$WORKSPACE" \
               UserAssignedManagedIdentityResourceId="$UAMI_ID"
```

After deployment, open the Logic App and confirm both API connections show the selected managed
identity. Then attach the playbook to a Microsoft Sentinel incident automation rule that runs when
incidents are created or updated.

## Parameters

| Parameter | Default | Notes |
|---|---:|---|
| `PlaybookName` | `Enrich-FileHash-IncidentComment` | Logic App name |
| `UserAssignedManagedIdentityResourceId` | required | Full resource ID of the existing UAMI |
| `WorkspaceName` | required | Sentinel/Log Analytics workspace |
| `WorkspaceResourceGroup` | deployment RG | Override when the workspace is in another RG |
| `WorkspaceSubscriptionId` | current subscription | Override for a cross-subscription workspace |
| `LookbackDays` | 14 | Sentinel workspace lookback, 1–90 days |
| `EnableDefenderAdvancedHunting` | `true` | Requires `ThreatHunting.Read.All`; also gates `FileProfile()` |
| `DefenderLookbackDays` | 14 | Defender activity lookback, 1–30 days (does not bound `FileProfile()` reputation/prevalence) |
| `FileHashContextWatchlistAlias` | `FileHashContext` | Set blank to disable the optional watchlist |

## Optional client watchlist

Create a Sentinel watchlist whose alias is `FileHashContext`. Put the hash (any of SHA256/SHA1/MD5,
lowercase) in `SearchKey`. Optional columns are `Classification` (or `Risk`), `Owner`, `Campaign`,
`Description` (or `Notes`), and `LastUpdated`. Values such as `critical`, `high`, `malicious`,
`knownbad`, or `malware` raise the playbook verdict to HIGH.

## Verdict logic

- **HIGH**: any AV/EDR detection, a high Defender alert, or critical client watchlist context.
- **MEDIUM**: any Defender file/process/email observation, any Defender alert, any workspace
  observation, or an unsigned file with a `FileProfile()` record and global prevalence under 10
  (rare and unsigned is a weak suspicious signal, not a verdict on its own).
- **LOW**: `FileProfile()` returned a record that is either Microsoft-root-signed or has global
  prevalence of 1000+ devices, and no stronger signal exists.
- **UNKNOWN**: no source returned enough information to classify the hash.

## Operational notes

- Each hash's comment posts individually, right inside the loop — an incident with several
  FileHash entities gets several comments, not one shared one. That keeps every comment under
  Sentinel's 30,000-character `/Incidents/Comment` limit; if one hash's own data is still unusually
  large, that single comment truncates at 28,000 characters with a note instead of failing outright.
- One hash makes one Defender hunting call (which itself runs `FileProfile()` plus five activity
  sub-queries) and one workspace query. The hash loop is deliberately sequential to control quota
  and shared-variable updates.
- `FileProfile()` prevalence and first/last-seen reflect Microsoft's global telemetry, not just this
  tenant — a common, widely-signed file (e.g. an OS component) will show high prevalence even if
  this tenant has never seen it before.
- Disable `EnableDefenderAdvancedHunting` at deployment if the tenant has not granted
  `ThreatHunting.Read.All`; workspace enrichment continues independently.
- If Defender returns HTTP 400, copy the query from
  `kql/Defender-XDR-FileHash-Enrichment.kql` into Advanced Hunting. Its use of `column_ifexists()`
  and fuzzy unions is intentional so absent optional tables/columns fail open.
- If the tenant's `Entities - Get File Hashes` action returns entities under different field names
  than `HashValue`/`Algorithm`, the hash resolves to an empty string and the algorithm falls back to
  a length-based guess (64 hex chars → SHA256, 40 → SHA1, 32 → MD5); check the action's raw output
  in the Logic App run history and adjust `Compose_Clean_Hash` in `build_filehash_template.py` if
  needed.

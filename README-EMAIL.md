# Sentinel Reported Email Enrichment → Incident Comment

This is a separate Microsoft Sentinel playbook for **Mail message entities** — most commonly a
user-reported phishing email, or an email pulled onto an incident by an automated investigation.
It uses one required, client-owned **user-assigned managed identity (UAMI)** for the Logic App,
Microsoft Sentinel and Azure Monitor Logs connections, Microsoft Defender Threat Intelligence, and
Defender XDR Advanced Hunting. It never enables a system-assigned identity.

The email, URL, IP, device, and file hash playbooks are independent, so all five can run from the
same incident automation rule.

## What it adds

| Source | Email enrichment placed in the incident comment |
|---|---|
| **Defender XDR Advanced Hunting — email record** | Full `EmailEvents` row: delivery action/location, direction, threat types/names, detection method, confidence level, bulk complaint level, email cluster ID, sender address/display name/IP, recipient, authentication details (SPF/DKIM/DMARC/composite auth), org- and user-level actions |
| **Defender XDR Advanced Hunting — related activity** | Every attachment (name, type, SHA256), every URL contained in the message, Safe Links click-through on those URLs (who clicked, whether they got through, threat type), post-delivery remediation events (ZAP, admin/user actions), and alert evidence |
| **Microsoft Defender Threat Intelligence (MDTI)** | Reputation/classification and score, first/last seen, registrar for the **sender's domain** |
| **Sentinel workspace** | Current `ThreatIntelIndicators`, legacy TI fallback matching the sender address/domain, prior alerts, ingested `EmailEvents`/`EmailUrlInfo` sightings, and optional client watchlist context |
| **Triage** | A HIGH / MEDIUM / LOW / UNKNOWN verdict and a concise source-status summary |

The playbook matches Defender's email tables primarily on `NetworkMessageId` (falling back to
`InternetMessageId` when the Sentinel entity doesn't carry one — this can happen depending on how
the email was reported/promoted onto the incident). MDTI's host-reputation endpoints are host-based,
so the sender's address is split on `@` to get a domain for that lookup; if no domain can be
extracted, the MDTI section is skipped rather than guessed at. The subject line is HTML-escaped
before it's added to the incident.

## Files

| File | Purpose |
|---|---|
| `azuredeploy-email.json` | Deployable ARM template |
| `build_email_template.py` | Source generator for the ARM template |
| `kql/Defender-XDR-Email-Enrichment.kql` | Standalone query to validate the Defender data available for one message |

## Prerequisites and permissions

The UAMI needs the following permissions. Graph permissions are **application permissions**, not
Azure RBAC roles.

| Scope | Permission | Used for |
|---|---|---|
| Resource group containing Sentinel | `Microsoft Sentinel Responder` | Read incident entities and post the comment |
| Log Analytics workspace | `Log Analytics Reader` | Run workspace KQL |
| Microsoft Graph | `ThreatIntelligence.Read.All` | MDTI sender-domain reputation |
| Microsoft Graph | `ThreatHunting.Read.All` | Defender XDR Advanced Hunting |
| UAMI itself (deployment principal, not the UAMI) | `Managed Identity Operator` | Attach the selected UAMI to the Logic App |

The relevant Defender products (Defender for Office 365) must be licensed and producing data for
their Advanced Hunting tables. A 403/404 from an MDTI call normally means the permission has not
propagated or the API is not yet available in that tenant; workspace enrichment continues
independently.

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
  --name sentinel-email-enrichment \
  --resource-group "$SENTINEL_RG" \
  --template-file azuredeploy-email.json \
  --parameters WorkspaceName="$WORKSPACE" \
               UserAssignedManagedIdentityResourceId="$UAMI_ID"
```

After deployment, open the Logic App and confirm both API connections show the selected managed
identity. Then attach the playbook to a Microsoft Sentinel incident automation rule that runs when
incidents are created or updated — this is the natural companion to a "user submission" / phishing
triage automation rule.

## Parameters

| Parameter | Default | Notes |
|---|---:|---|
| `PlaybookName` | `Enrich-Email-IncidentComment` | Logic App name |
| `UserAssignedManagedIdentityResourceId` | required | Full resource ID of the existing UAMI |
| `WorkspaceName` | required | Sentinel/Log Analytics workspace |
| `WorkspaceResourceGroup` | deployment RG | Override when the workspace is in another RG |
| `WorkspaceSubscriptionId` | current subscription | Override for a cross-subscription workspace |
| `LookbackDays` | 14 | Sentinel workspace lookback, 1–90 days |
| `EnableMicrosoftThreatIntelligence` | `true` | Requires `ThreatIntelligence.Read.All`; skipped automatically if no domain can be extracted from the sender |
| `EnableDefenderAdvancedHunting` | `true` | Requires `ThreatHunting.Read.All` |
| `DefenderLookbackDays` | 14 | Defender lookback, 1–30 days |
| `EmailContextWatchlistAlias` | `EmailContext` | Set blank to disable the optional watchlist |

## Optional client watchlist

Create a Sentinel watchlist whose alias is `EmailContext`. Put either the sender's full address or
just its domain in `SearchKey`. Optional columns are `Classification` (or `Risk`), `Owner`,
`Campaign`, `Description` (or `Notes`), and `LastUpdated`. Values such as `critical`, `high`,
`malicious`, `knownbad`, or `phishing` raise the playbook verdict to HIGH.

## Verdict logic

- **HIGH**: Defender classifies the message as phish/malware, MDTI reports the sender domain
  malicious, any recipient clicked through a contained URL, a high Defender alert, or a
  high-confidence Sentinel TI match against the sender.
- **MEDIUM**: delivered to the junk folder, any post-delivery remediation event (ZAP, admin/user
  action), any Safe Links click (even without clicking through), any Defender alert, a bulk
  complaint level of 6+, MDTI reports the sender domain suspicious, or any workspace observation.
- **LOW**: a Defender record was found, it was delivered to the inbox, and nothing else fired.
- **UNKNOWN**: no source returned enough information to classify the email.

## Operational notes

- One email makes up to two MDTI Graph calls, one Defender hunting call (which itself pulls the
  email record plus five related-activity sub-queries), and one workspace query. The email loop is
  deliberately sequential to control quota and shared-variable updates.
- Subjects and attachment/URL lists can contain personal data. The incident comment includes them,
  so establish a client policy for redaction if that's a concern for this tenant.
- If the Sentinel `Mail message` entity on an incident lacks a `NetworkMessageId` (some alert
  sources only populate `InternetMessageId`, sender, and subject), the Defender lookup falls back to
  matching on `InternetMessageId`; if neither is present, Defender enrichment returns "no record
  found" rather than guessing from subject/sender alone.
- If Defender returns HTTP 400, copy the query from `kql/Defender-XDR-Email-Enrichment.kql` into
  Advanced Hunting. Its use of `column_ifexists()` and fuzzy unions is intentional so absent optional
  tables/columns fail open.
- Disable either Microsoft Graph source at deployment if the tenant has not granted its permission;
  the other sources continue to work.

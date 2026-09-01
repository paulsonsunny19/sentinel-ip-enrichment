# Sentinel Account (User) Enrichment → Incident Comment

This is a separate Microsoft Sentinel playbook for **Account entities** — the user identity behind
an incident. It uses one required, client-owned **user-assigned managed identity (UAMI)** for the
Logic App, Microsoft Sentinel and Azure Monitor Logs connections, and Microsoft Graph. It never
enables a system-assigned identity.

This playbook deliberately does **not** perform IP-address reputation or network-prevalence
lookups on the IPs seen in sign-in logs — that's the dedicated IP playbook's job
(`README.md`/`azuredeploy.json`). Sign-in IPs are still listed here as plain context, just without
a reputation/prevalence lookup on each one.

The account, email, URL, IP, device, and file hash playbooks are independent, so all six can run
from the same incident automation rule.

## What it adds

| Source | Account enrichment placed in the incident comment |
|---|---|
| **User profile** (Graph) | Display name, UPN/mail, job title, department, office/city/state/country, phone, account enabled, created date, on-prem sync, **manager**, **AAD directory roles** |
| **Registered devices** (Graph) | Every device registered to the user: name, OS/version, trust type, compliant/managed, last sign-in |
| **MFA / SSPR registration** (Graph) | MFA registered/capable, SSPR registered/capable, passwordless capable, default MFA method, full list of registered methods, is-admin |
| **Entra ID Protection identity risk** (Graph) | Risk level, risk state, risk detail, last updated, **risk event count**, recent risk detections (type, level, state, IP, location, time) |
| **Out-of-office status** (Graph) | Automatic-replies status (disabled/scheduled/always-on) and the scheduled window |
| **Sign-in activity** (Sentinel workspace) | Total/failed/risky/high-risk sign-in counts, Conditional Access failures, **failed-MFA count**, **MFA-fraud-reported count**, countries/cities/IPs/apps/devices seen, most recent sign-in detail |
| **Sentinel workspace** | TI matches against the UPN, prior alerts, optional client watchlist context |
| **Triage** | A HIGH / MEDIUM / LOW / UNKNOWN verdict and a concise source-status summary |

## Files

| File | Purpose |
|---|---|
| `azuredeploy-account.json` | Deployable ARM template |
| `build_account_template.py` | Source generator for the ARM template |
| `kql/User-Signin-Insights.kql` | Standalone query to validate the sign-in data available for one user |

## Prerequisites and permissions

The UAMI needs the following permissions. Graph permissions are **application permissions**, not
Azure RBAC roles.

| Scope | Permission | Used for |
|---|---|---|
| Resource group containing Sentinel | `Microsoft Sentinel Responder` | Read incident entities and post the comment |
| Log Analytics workspace | `Log Analytics Reader` | Run workspace KQL (sign-in summary, TI, alerts) |
| Microsoft Graph | `User.Read.All` | User profile, manager |
| Microsoft Graph | `Directory.Read.All` | AAD directory role membership |
| Microsoft Graph | `Device.Read.All` | Registered devices |
| Microsoft Graph | `Reports.Read.All` | MFA/SSPR registration report |
| Microsoft Graph | `IdentityRiskyUser.Read.All` | Entra ID Protection risky-user state and risk detections |
| Microsoft Graph | `MailboxSettings.Read` | Out-of-office (automatic replies) status |
| UAMI itself (deployment principal, not the UAMI) | `Managed Identity Operator` | Attach the selected UAMI to the Logic App |

`SigninLogs`/`AADNonInteractiveUserSignInLogs` must be flowing into the workspace (the standard
Entra ID diagnostic settings data connector) for sign-in enrichment to return anything; identity
risk and MFA reporting require Entra ID P2 / Identity Protection to be licensed.

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

### Grant the Microsoft Graph application permissions

Run this as an Entra administrator that can create app-role assignments. The Microsoft Graph
service principal has app ID `00000003-0000-0000-c000-000000000000`.

```bash
GRAPH_APP_ID=00000003-0000-0000-c000-000000000000
GRAPH_SP_ID=$(az ad sp show --id "$GRAPH_APP_ID" --query id -o tsv)

for GRAPH_ROLE in User.Read.All Directory.Read.All Device.Read.All Reports.Read.All \
                  IdentityRiskyUser.Read.All MailboxSettings.Read; do
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
  --name sentinel-account-enrichment \
  --resource-group "$SENTINEL_RG" \
  --template-file azuredeploy-account.json \
  --parameters WorkspaceName="$WORKSPACE" \
               UserAssignedManagedIdentityResourceId="$UAMI_ID"
```

After deployment, open the Logic App and confirm both API connections show the selected managed
identity. Then attach the playbook to a Microsoft Sentinel incident automation rule that runs when
incidents are created or updated.

## Parameters

| Parameter | Default | Notes |
|---|---:|---|
| `PlaybookName` | `Enrich-Account-IncidentComment` | Logic App name |
| `UserAssignedManagedIdentityResourceId` | required | Full resource ID of the existing UAMI |
| `WorkspaceName` | required | Sentinel/Log Analytics workspace |
| `WorkspaceResourceGroup` | deployment RG | Override when the workspace is in another RG |
| `WorkspaceSubscriptionId` | current subscription | Override for a cross-subscription workspace |
| `LookbackDays` | 14 | Sign-in and workspace lookback, 1–90 days |
| `EnableUserProfile` | `true` | Profile, manager, AAD roles. Requires `User.Read.All` + `Directory.Read.All` |
| `EnableRegisteredDevices` | `true` | Requires `Device.Read.All` |
| `EnableMfaMethods` | `true` | Requires `Reports.Read.All` |
| `EnableIdentityProtection` | `true` | Requires `IdentityRiskyUser.Read.All` |
| `EnableMailboxSettings` | `true` | Requires `MailboxSettings.Read` |
| `EnableSigninHistory` | `true` | Workspace-only; no Graph permission needed |
| `UserContextWatchlistAlias` | `UserContext` | Set blank to disable the optional watchlist |

## How the account is resolved

The Sentinel `Entities - Get Accounts` action's `AadUserId` is used directly against Graph when
present. If the entity only carries a UPN (`AccountName@UPNSuffix` or a `userPrincipalName`
field), the playbook first resolves it to an Entra object ID with one extra Graph call — the
`identityProtection/riskyUsers/{id}` and `riskDetections` endpoints require the object ID, not a
UPN, unlike the `/users/{id|upn}` profile/device/mailbox endpoints which accept either.

## Optional client watchlist

Create a Sentinel watchlist whose alias is `UserContext`. Put the user's UPN in `SearchKey`.
Optional columns are `Classification` (or `Risk`), `Owner`, `Department`, `Description` (or
`Notes`), and `LastUpdated`. Values such as `critical`, `high`, `compromised`, `knownbad`, or `vip`
raise the playbook verdict to HIGH.

## Verdict logic

- **HIGH**: Entra risk level `high`, risk state `confirmedCompromised`, any high-risk sign-in, **any
  MFA fraud report** (a user telling Microsoft "this MFA prompt wasn't me" is a strong compromise
  signal on its own), a high-confidence Sentinel TI/alert match, critical watchlist context, or
  **sign-in activity landing inside the user's own scheduled out-of-office window** — a deliberate
  combined heuristic, since account activity while its owner has told their mail system they're away
  is a stronger tell than either signal alone.
- **MEDIUM**: Entra risk level `medium` or state `atRisk`, any risky sign-in, MFA not registered,
  the account disabled (yet still active on an incident), or any workspace observation.
- **LOW**: Entra risk state `none`/`confirmedSafe` and the profile lookup succeeded with nothing
  else flagged.
- **UNKNOWN**: no source returned enough information to classify the account.

## Operational notes

- One account can make up to nine Graph calls (profile, manager, roles, devices, MFA report, risky
  user, risk detections, mailbox settings, and an optional UPN→object-ID resolve) plus two workspace
  queries. The account loop is deliberately sequential to control quota and shared-variable updates.
- `isMfaRegistered: false` on a real, in-use account is itself a posture gap worth flagging even
  outside an incident — this playbook surfaces it as part of triage, not as a standalone
  recommendation to enforce MFA.
- If a Graph call 403s, check the specific permission it needs in the table above — each source is
  independently toggleable, so disabling one at deployment (or after finding it unpermissioned)
  leaves the rest of the comment working.
- If Log Analytics returns no sign-in rows, confirm `SigninLogs`/`AADNonInteractiveUserSignInLogs`
  are actually being collected (Entra ID diagnostic settings → workspace) — the query itself is
  schema-safe via `column_ifexists()`, so an empty result usually means the tables aren't ingested
  rather than a query error.

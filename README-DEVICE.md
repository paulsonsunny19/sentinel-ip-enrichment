# Sentinel Device Enrichment → Incident Comment

This companion playbook enriches every **Host** entity on a Microsoft Sentinel incident. It correlates
the Sentinel hostname/FQDN to Microsoft Defender XDR, queries data that can exist only in Advanced
Hunting, combines it with workspace context, calculates a triage verdict, and posts one formatted
incident comment.

It is deployed separately from the IP playbook, so neither workflow depends on the other.

## What is enriched

| Area | Data returned | Primary source |
|---|---|---|
| Device identity | Defender device ID/FQDN, OS/build/architecture, device type, vendor/model, last seen | `DeviceInfo` |
| EDR state | onboarding, sensor health, agent version, connectivity, machine group, site, mitigation/exclusion state | `DeviceInfo` |
| Exposure | exposure level, asset value, internet-facing state, public IP, cloud resource identity and tags | `DeviceInfo` |
| Network inventory | adapters, local addresses, MAC addresses, connected networks and DNS suffixes | `DeviceNetworkInfo` |
| Alerts | distinct alerts, high/medium counts, titles, sources and ATT&CK techniques | `AlertEvidence` |
| Vulnerabilities | unique CVEs, critical/high/medium counts, zero-days, missing-update tags and top affected software | `DeviceTvmSoftwareVulnerabilities` |
| Configuration posture | noncompliant assessments, high-impact gaps and top categories/configuration IDs | `DeviceTvmSecureConfigurationAssessment` |
| Authentication | endpoint logons, failures, local-admin accounts, remote IPs, identity logons and protocols | `DeviceLogonEvents`, `IdentityLogonEvents` |
| Activity | network destinations, processes, PowerShell/elevated process counts and security-control events | `DeviceNetworkEvents`, `DeviceProcessEvents`, `DeviceEvents` |
| Sentinel context | prior alerts, Windows/Linux events, heartbeat, Entra device sign-ins, Azure resource operations | Log Analytics workspace |
| Client context | owner, classification/criticality, environment, business function, patch group and notes | optional `DeviceContext` watchlist |

Defender Vulnerability Management tables are queried directly because those TVM tables are not
ingested into Sentinel by the Microsoft 365 Defender connector.

## Verdict logic

- **HIGH** — a high-severity Defender alert, a critical vulnerability, a high-exposure device that is
  internet-facing, or a high-severity Sentinel alert.
- **MEDIUM** — a medium Defender alert, high vulnerability, high-impact configuration gap,
  medium/high exposure, internet-facing device, unhealthy sensor, device not onboarded, or a client
  watchlist classification such as `critical`, `crown-jewel`, `high`, `knownbad`, or `compromised`.
- **LOW** — enrichment succeeded and none of the above signals were found.
- **UNKNOWN** — neither Defender nor the workspace returned usable data. This avoids presenting a
  missing-data condition as low risk.

The verdict is advisory. The playbook does not change incident severity, isolate the device, run a
scan, or perform any other remediation.

## Files

```text
azuredeploy-device.json                    deployable ARM template
build_device_template.py                   generator; edit this, then regenerate the JSON
kql/Defender-XDR-Device-Enrichment.kql     standalone Advanced Hunting validation query
```

## Deploy

The device playbook is user-assigned-managed-identity-only. Create the identity first (or select an
existing client-owned identity), then pass its full resource ID. The template does not enable a
system-assigned identity.

```bash
UAMI_ID=$(az identity show \
  --resource-group <identity-resource-group> \
  --name <identity-name> \
  --query id -o tsv)

az deployment group create \
  --name sentinel-device-enrichment \
  --resource-group <resource-group> \
  --template-file azuredeploy-device.json \
  --parameters WorkspaceName=<sentinel-workspace> \
               UserAssignedManagedIdentityResourceId="$UAMI_ID"
```

The UAMI must already exist in the client's tenant and subscription. The deployment principal needs
permission to write the Logic App and `Managed Identity Operator` over the selected identity. The
UAMI is attached to the Logic App and explicitly used by the Microsoft Sentinel connector, Azure
Monitor Logs connector and Microsoft Graph Defender Advanced Hunting call.

`EnableDefenderAdvancedHunting` defaults to `true`. The activity lookback defaults to 14 days and
can be set from 1 to 30 days. The Graph request uses a 30-day timespan so a recently inactive device
can still be resolved through `DeviceInfo`; activity summaries still honor `DefenderLookbackDays`.

## Required permissions

### 1. Azure RBAC for the Logic App managed identity

The deployment output `ManagedIdentityPrincipalId` is the UAMI service principal's object ID.

```bash
PLAYBOOK_ID=$(az deployment group show \
  --resource-group <resource-group> \
  --name sentinel-device-enrichment \
  --query properties.outputs.managedIdentityPrincipalId.value -o tsv)

az role assignment create \
  --assignee-object-id $PLAYBOOK_ID \
  --assignee-principal-type ServicePrincipal \
  --role "Microsoft Sentinel Responder" \
  --scope /subscriptions/<subscription>/resourceGroups/<sentinel-resource-group>

az role assignment create \
  --assignee-object-id $PLAYBOOK_ID \
  --assignee-principal-type ServicePrincipal \
  --role "Log Analytics Reader" \
  --scope /subscriptions/<subscription>/resourceGroups/<sentinel-resource-group>/providers/Microsoft.OperationalInsights/workspaces/<sentinel-workspace>
```

`Microsoft Sentinel Responder` permits the incident comment. `Log Analytics Reader` permits the
workspace query.

### 2. Microsoft Graph application permission for Defender hunting

Assign **`ThreatHunting.Read.All`** to the managed identity. This is a Microsoft Graph application
app-role assignment—not an Azure RBAC role—and requires an Entra administrator.

```powershell
$playbookPrincipalId = az deployment group show `
    --resource-group <resource-group> `
    --name sentinel-device-enrichment `
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

Managed-identity access tokens are cached. Allow time for the new Graph role to propagate before
testing.

### 3. Authorize the API connections

Open **Logic App → API connections** and authorize/save both generated connections:

- `MicrosoftSentinel-Enrich-Device-IncidentComment`
- `AzureMonitorLogs-Enrich-Device-IncidentComment`

The Sentinel connection uses the connector's managed-identity alternative parameters. The Azure
Monitor Logs connection uses `managedIdentityAuth`; it intentionally does not use
`parameterValueType: Alternative`, which Azure Monitor Logs does not support.

### 4. Allow Sentinel automation to run the playbook

When attaching the playbook to an automation rule, grant Microsoft Sentinel Automation Contributor
on the playbook resource group to the Sentinel service identity when the portal prompts for it.

## Parameters

| Parameter | Default | Notes |
|---|---|---|
| `PlaybookName` | `Enrich-Device-IncidentComment` | Logic App name |
| `UserAssignedManagedIdentityResourceId` | required | full resource ID of one existing client-owned UAMI; the template never enables a system-assigned identity |
| `WorkspaceName` | required | Sentinel workspace |
| `WorkspaceResourceGroup` / `WorkspaceSubscriptionId` | current deployment scope | change for a cross-scope workspace |
| `LookbackDays` | `14` | workspace lookback, 1–90 days |
| `EnableDefenderAdvancedHunting` | `true` | set false for a workspace-only deployment |
| `DefenderLookbackDays` | `14` | Defender activity lookback, 1–30 days |
| `DeviceContextWatchlistAlias` | `DeviceContext` | set blank to disable client context |

## Optional DeviceContext watchlist

Create a Sentinel watchlist with alias `DeviceContext`. Put the lowercase hostname or FQDN in
`SearchKey`. Recommended columns are:

- `Classification` or `Criticality`
- `Owner`
- `Environment`
- `BusinessFunction`
- `PatchGroup`
- `Description` or `Notes`

## Correlation and operating notes

- The playbook uses Sentinel's native **Entities - Get Hosts** action. It receives `HostName`,
  `DnsDomain`, `NetBiosName`, `OSFamily`, `OSVersion`, `OMSAgentID`, `IsDomainJoined`, and `AzureID`.
- Defender correlation prefers an exact Azure resource ID, then an exact FQDN, an exact device name,
  and finally a short-name match. If short names are duplicated across domains, the most recently
  seen match is selected; map FQDN or Azure resource ID Host entities in analytics rules for the best
  result.
- One compact Graph hunting query runs per Host entity, and the loop is sequential to control quota
  and avoid shared-variable races.
- A Graph permission, licensing, quota, or correlation failure does not fail the playbook. The
  Defender section explains the status and the Sentinel workspace query continues.
- Each Host entity's comment posts individually, right inside the loop — an incident with several
  devices gets several comments, not one shared one. That keeps every comment under Sentinel's
  30,000-character `/Incidents/Comment` limit; if one device's own data is still unusually large,
  that single comment truncates at 28,000 characters with a note instead of failing outright.
- Raw Graph inputs and outputs are protected in Logic App run history. The summarized result is
  intentionally posted to the incident comment and is visible to analysts who can access the
  incident.
- Vulnerability and configuration sections require Defender Vulnerability Management data. Without
  that entitlement/data, those counters remain zero while the remaining Defender sections continue.

## Validate before rollout

Run `kql/Defender-XDR-Device-Enrichment.kql` in Defender Advanced Hunting with a known onboarded
hostname. Then test the playbook manually against an incident containing a mapped Host entity before
enabling the automation rule for all incidents.

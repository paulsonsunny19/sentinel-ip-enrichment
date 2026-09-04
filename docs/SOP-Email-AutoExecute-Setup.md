# SOP: Setting up `ErgoSOC-AU-Email-BlockSenderAndQuarantine` auto-execute mode

This is a step-by-step standard operating procedure for turning the email response
playbook's optional `AutoExecuteBlock` mode on -- i.e. going from "the playbook composes
a block command for an analyst to run" to "the playbook actually writes the block to the
Tenant Allow/Block List itself." It documents every command used, every permission
required, and every real failure hit (and its fix) while doing this for the first time,
so the next person doing this doesn't have to rediscover any of it.

Read `README-RESPONSE.md` first for the overall design and the "why" behind the
architecture. This document is the "how," in the order you actually do it, including the
troubleshooting detours.

Placeholders used throughout (replace with your own values):

| Placeholder | What it is |
|---|---|
| `$SUBSCRIPTION_ID` | Your Azure subscription ID |
| `$SENTINEL_RG` | Resource group holding your Sentinel workspace and playbooks |
| `$TENANT_DOMAIN` | Your tenant's `*.onmicrosoft.com` domain |
| `$ADMIN_UPN` | A Global Admin / Exchange Admin account's UPN, used for the one-time EXO setup |
| `$SHARED_UAMI_NAME` | The user-assigned managed identity your Logic Apps already run as |
| `$EXO_IDENTITY_NAME` | A **dedicated** user-assigned managed identity for the Automation Account (recommended, see "Which identity should run the Logic App?" below) |

---

## Architecture recap

```
Sentinel incident (analyst clicks "Run playbook")
        |
        v
Logic App: ErgoSOC-AU-Email-BlockSenderAndQuarantine
   (runs as: its own UAMI)
        |
        | PUT .../automationAccounts/<account>/jobs/<guid>  (ARM, ManagedServiceIdentity auth)
        v
Azure Automation Account: ErgoSOC-AU-ResponseAutomation
   (runs as: a UAMI registered in Exchange Online)
        |
        | executes runbook Set-ErgoSOC-TenantBlockListItem.ps1
        v
Connect-ExchangeOnline -ManagedIdentity
        |
        v
New-TenantAllowBlockListItems  (writes the actual block)
```

Two identities are involved, and they need **different** things:

1. **The Logic App's own identity** -- needs to be able to (a) read/comment on the
   Sentinel incident, and (b) start a job on the Automation Account.
2. **The Automation Account's identity** -- needs to be able to authenticate to and
   write in Exchange Online. This can be the *same* identity as #1, or a dedicated one;
   see below.

### Which identity should run the Logic App?

The repo's default design (see `README-RESPONSE.md`) uses a **dedicated** identity for
the Automation Account, kept separate from the shared UAMI every other playbook runs as
-- the reasoning being that Exchange Online write access shouldn't spread to every
playbook's identity.

In practice, during this walkthrough we assigned the *same* dedicated identity
(`$EXO_IDENTITY_NAME`) as **both** the Automation Account's identity **and** the Logic
App's own `UserAssignedManagedIdentityResourceId`. That's a valid, deliberate choice too
-- it keeps this one playbook's entire footprint (Sentinel read/comment, ARM job
submission, and EXO write) on a single, purpose-built identity instead of spreading EXO
exposure onto the shared identity every other playbook uses. Either approach works; just
be consistent about which one you picked when granting permissions below, since the
permission list differs slightly (see the table).

---

## Full permissions checklist

| # | Grant | Where | Identity it goes on | Notes |
|---|---|---|---|---|
| 1 | `Microsoft Sentinel Responder` (Azure RBAC) | Resource group holding the Sentinel workspace | The Logic App's own identity | Baseline every playbook in this repo needs, to read/comment on incidents |
| 2 | `Automation Job Operator` (Azure RBAC) | The Automation Account resource | The Logic App's own identity | Lets it start (`PUT .../jobs/<guid>`) a runbook job |
| 3 | EXO service principal registration (`New-ServicePrincipal`) | Exchange Online (PowerShell) | The Automation Account's identity | Required before EXO will recognize the identity as an app at all |
| 4 | EXO role group with `Tenant AllowBlockList Manager` role | Exchange Online (PowerShell) | The Automation Account's identity | Least-privilege EXO RBAC -- just enough to write the block list, nothing else |
| 5 | **`Exchange.ManageAsApp`** application permission, admin-consented | Entra ID app role assignment against **Office 365 Exchange Online** (`00000002-0000-0ff1-ce00-000000000000`) -- a *third*, separate resource app, not Graph and not WindowsDefenderATP | The Automation Account's identity | **The step most likely to be missed.** Without this, `Connect-ExchangeOnline -ManagedIdentity` itself fails with `UnAuthorized`, even with #3 and #4 done correctly. See the dedicated section below. |

If you used the *same* identity for both roles (as this walkthrough ended up doing),
grants #1, #2, #3, #4, #5 **all** land on that one identity.

---

## Step-by-step procedure

All commands run in **Azure Cloud Shell (bash)** unless noted otherwise. Cloud Shell
sessions are ephemeral -- every reconnect loses environment variables (re-export them)
and the home directory's uploaded files (re-upload them). Watch for the "Your Cloud
Shell session will be ephemeral..." banner as your cue that you're in a fresh session.

### 0. One-time environment setup

```bash
export SENTINEL_RG="<your resource group>"
az account set --subscription "$SUBSCRIPTION_ID"   # if you have more than one subscription
```

### 1. Create (or identify) the identity for the Automation Account

If creating a new dedicated one:

```bash
az identity create \
  --name "$EXO_IDENTITY_NAME" \
  --resource-group "$SENTINEL_RG" \
  --location <your region>
```

Note the `principalId` (object ID) and `clientId` (application ID) from the output --
you'll need both repeatedly below.

> **Gotcha -- listing identities via `az identity list` may fail.** In this
> environment, `az identity list` hit a broken/stale hardcoded API version
> (`InvalidApiVersionParameter`). Workaround: use the generic resource command instead,
> which resolves API versions dynamically:
> ```bash
> az resource list --resource-group "$SENTINEL_RG" \
>   --resource-type "Microsoft.ManagedIdentity/userAssignedIdentities" \
>   --query "[].{name:name, id:id}" -o table
> ```

### 2. Deploy the Automation Account infrastructure

Generate/obtain `azuredeploy-automation-account-response.json` (built by
`build_automation_account_response.py`) and upload it to Cloud Shell.

> **Gotcha -- Cloud Shell's file upload can strip hyphens from filenames.** After
> uploading, always run `ls -la ~` and use the *actual* on-disk filename in
> `--template-file`, not the name you uploaded. `azuredeploy-automation-account-response.json`
> has landed as `azuredeployautomationaccountresponse.json` in practice. If you upload
> the same filename twice in one session, Cloud Shell instead appends `(1)`, `(2)`, etc.
> -- quote those filenames (`"name (1).json"`), since the space and parentheses break an
> unquoted shell command.

```bash
az deployment group create \
  --name sentinel-response-automation \
  --resource-group "$SENTINEL_RG" \
  --template-file <actual-filename-on-disk> \
  --parameters UserAssignedManagedIdentityResourceId="/subscriptions/$SUBSCRIPTION_ID/resourcegroups/$SENTINEL_RG/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$EXO_IDENTITY_NAME"
```

Capture the deployment outputs: `automationAccountResourceId`, `runbookName`,
`managedIdentityClientId`.

### 3. Publish the runbook content

The Automation Account template creates an **empty** runbook resource (ARM can't
reliably inline multi-line PowerShell). Upload `runbooks/Set-ErgoSOC-TenantBlockListItem.ps1`
and publish it as a separate step.

> **Gotcha -- the `automation` az CLI extension is broken.** `az automation runbook
> replace-content` / `az automation runbook publish` install a *preview* extension that
> hardcodes API version `2018-06-30`, which Azure Resource Manager has since retired for
> this provider (`InvalidApiVersionParameter`). Skip the extension entirely and call the
> REST API directly.
>
> **Gotcha -- the `runbooks` sub-resource has its own supported API-version list**,
> separate from the `automationAccounts` resource. `2023-07-01` (valid for the account
> itself) fails with `NoRegisteredProviderFound` for the `runbooks/draft/content` and
> `runbooks/publish` operations specifically. Use **`2019-06-01`** for those two calls.

```bash
TOKEN=$(az account get-access-token --resource https://management.azure.com/ --query accessToken -o tsv)
RUNBOOK_URL="https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$SENTINEL_RG/providers/Microsoft.Automation/automationAccounts/ErgoSOC-AU-ResponseAutomation/runbooks/Set-ErgoSOC-TenantBlockListItem"

# Push the script content into the runbook's draft
curl -sS -X PUT "$RUNBOOK_URL/draft/content?api-version=2019-06-01" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: text/powershell" \
  --data-binary @<actual-ps1-filename-on-disk>

# Publish the draft
curl -sS -X POST "$RUNBOOK_URL/publish?api-version=2019-06-01" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{}"
```

Both calls return an empty body on success (PUT returns `202 Accepted` with a
`location` header for polling; POST returns `202` too). Verify with:

```bash
curl -sS -X GET "$RUNBOOK_URL?api-version=2019-06-01" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

Look for `"state": "Published"` and check `"lastModifiedTime"` matches when you just ran
this.

> **`$TOKEN` expires quickly in this environment** -- if any call returns
> `ExpiredAuthenticationToken` or `AuthenticationFailedMissingToken`, just re-run the
> `TOKEN=$(az account get-access-token ...)` line and retry.

### 4. Pin the ExchangeOnlineManagement module version

The Automation Account template imports the module from the PowerShell Gallery's
"always latest" URL. That's a problem:

> **Gotcha -- newer ExchangeOnlineManagement versions crash on the PS 7.2 Automation
> sandbox.** Recent module releases (as imported at the time of this walkthrough, which
> resolved to `3.10.1`) ship dependencies compiled for .NET 8. Azure Automation's
> PowerShell 7.2 runtime is built on .NET 6 and can't load them, so every runbook job
> fails immediately with:
> ```
> Could not load file or assembly 'System.Runtime, Version=8.0.0.0, Culture=neutral,
> PublicKeyToken=b03f5f7f11d50a3a'. The system cannot find the file specified.
> ```
> Fix: pin the module to an older, compatible version (`3.2.0` worked in this
> walkthrough) instead of "latest."

```bash
MODULE_URL="https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$SENTINEL_RG/providers/Microsoft.Automation/automationAccounts/ErgoSOC-AU-ResponseAutomation/powershell72Modules/ExchangeOnlineManagement"

curl -sS -X PUT "$MODULE_URL?api-version=2023-11-01" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"properties":{"contentLink":{"uri":"https://www.powershellgallery.com/api/v2/package/ExchangeOnlineManagement/3.2.0"}}}'
```

Poll until done (this takes a few minutes):

```bash
curl -sS -X GET "$MODULE_URL?api-version=2023-11-01" -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

Wait for `"provisioningState": "Succeeded"` and confirm `"version": "3.2.0"` (not
whatever "latest" resolved to). If you need to check what versions actually exist on the
Gallery before picking one (in case `3.2.0` is ever retired):

```bash
curl -s "https://www.powershellgallery.com/api/v2/FindPackagesById()?id=%27ExchangeOnlineManagement%27&\$select=Version" \
  | grep -oP '(?<=<d:Version>)[^<]+' | sort -V
```

### 5. Register the identity in Exchange Online

Drop into PowerShell from Cloud Shell bash:

```bash
pwsh
```

```powershell
Install-Module -Name ExchangeOnlineManagement -Force -Scope CurrentUser
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline -UserPrincipalName $ADMIN_UPN
# If signing in as a guest account, omit -UserPrincipalName entirely and let the
# interactive sign-in prompt pick the account -- guest UPNs in #EXT# format are
# awkward to type by hand.

New-ServicePrincipal -AppId <identity's clientId> `
  -ObjectId <identity's principalId> `
  -DisplayName "<identity's display name>"
```

Then grant it least-privilege EXO RBAC via a dedicated role group:

```powershell
New-RoleGroup -Name "ErgoSOC-AU-TenantBlockList-RoleGroup" `
  -Roles "Tenant AllowBlockList Manager" `
  -Members "<identity's display name>" `
  -ManagedBy "Organization Management" `
  -Description "Least-privilege role group for the ErgoSOC-AU email-block automation identity"
```

> **Gotcha -- `New-RoleGroup` ownership error for guest accounts.** By default,
> `New-RoleGroup` tries to make the *creating* account the group's owner. A guest
> account's recipient type in Exchange Online isn't one EXO accepts as a group owner,
> producing:
> ```
> The group "..." can't be managed by recipient "<guid>". The owner of the group
> should have the following recipient type details: UserMailbox, ... RoleGroup, ...
> ```
> Fix: explicitly pass `-ManagedBy "Organization Management"` (a built-in role group,
> whose type *is* accepted).

```powershell
Disconnect-ExchangeOnline -Confirm:$false
exit
```

### 6. Grant `Exchange.ManageAsApp` -- the step most likely to be missed

This is a **separate, third permission grant**, distinct from steps 3 and 4 above (which
are Exchange Online's own RBAC system). Without this, `Connect-ExchangeOnline
-ManagedIdentity` fails to authenticate **at all** -- not a permissions-inside-EXO
problem, an authentication problem. The failure signature is a bare, unhelpful
`UnAuthorized (UnAuthorized)` exception with no further detail, thrown before the
runbook's own error handling ever runs (see "Troubleshooting a live `UnAuthorized`
failure" below for how to confirm this from a job's output streams).

```bash
EXO_APP_ID=00000002-0000-0ff1-ce00-000000000000
EXO_SP_ID=$(az ad sp show --id "$EXO_APP_ID" --query id -o tsv)

EXO_ROLE_ID=$(az ad sp show --id "$EXO_APP_ID" \
  --query "appRoles[?value=='Exchange.ManageAsApp' && contains(allowedMemberTypes, 'Application')].id | [0]" \
  -o tsv)

IDENTITY_PRINCIPAL_ID=<identity's principalId>

az rest --method post \
  --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$IDENTITY_PRINCIPAL_ID/appRoleAssignments" \
  --headers Content-Type=application/json \
  --body "{\"principalId\":\"$IDENTITY_PRINCIPAL_ID\",\"resourceId\":\"$EXO_SP_ID\",\"appRoleId\":\"$EXO_ROLE_ID\"}"
```

Verify it's actually there (both the Portal and the API can lag each other briefly, so
check both if in doubt):

```bash
az rest --method get \
  --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$IDENTITY_PRINCIPAL_ID/appRoleAssignments" \
  -o table
```

or in the Portal: **Entra ID -> Enterprise applications -> `<identity display name>` ->
Permissions** -- look for `Office 365 Exchange Online` / `Exchange.ManageAsApp` /
`Manage Exchange As Application`, granted via Admin consent.

> **Gotcha -- propagation delay.** Even once granted and confirmed via both the API and
> the Portal, `Connect-ExchangeOnline -ManagedIdentity` can keep failing with
> `UnAuthorized` for **15-30 minutes** afterward while Exchange Online's own auth layer
> catches up. This is the single most time-consuming step in this whole procedure --
> budget for the wait, and don't conclude the grant "didn't work" from a failure in the
> first few minutes after granting it.

### 7. Grant the Logic App's own identity its RBAC

```bash
IDENTITY_ID="/subscriptions/$SUBSCRIPTION_ID/resourcegroups/$SENTINEL_RG/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$EXO_IDENTITY_NAME"
IDENTITY_PRINCIPAL_ID=<identity's principalId>

# Baseline: every response/enrichment playbook in this repo needs this to read/comment on incidents
az role assignment create \
  --assignee-object-id "$IDENTITY_PRINCIPAL_ID" \
  --assignee-principal-type ServicePrincipal \
  --role "Microsoft Sentinel Responder" \
  --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$SENTINEL_RG"

# Needed to start the runbook job
az role assignment create \
  --assignee-object-id "$IDENTITY_PRINCIPAL_ID" \
  --assignee-principal-type ServicePrincipal \
  --role "Automation Job Operator" \
  --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$SENTINEL_RG/providers/Microsoft.Automation/automationAccounts/ErgoSOC-AU-ResponseAutomation"
```

(If you used the same identity for both roles, as this walkthrough did, this is the same
identity as step 6 -- all five permissions land on one principal.)

### 8. Deploy the Logic App -- dry run first

Deploy with `AutoExecuteBlock` left at its default (`false`). This is a genuinely safe
dry run: the playbook composes the block command and posts it to the incident comment,
but never calls the Automation job.

```bash
az deployment group create \
  --name sentinel-response-email-block \
  --resource-group "$SENTINEL_RG" \
  --template-file <actual-filename-on-disk> \
  --parameters \
    UserAssignedManagedIdentityResourceId="$IDENTITY_ID"
```

Test: Sentinel Portal -> an incident with a Mail message entity -> **Actions -> Run
playbook** -> `ErgoSOC-AU-Email-BlockSenderAndQuarantine`. Confirm the incident comment
shows the sender/domain it identified, the block command, and both job-result fields
reading `not attempted (AutoExecuteBlock is off...)`.

### 9. Deploy the Logic App -- turn on live blocking

Once the dry run identifies the right sender, redeploy the same Logic App (same
deployment name, same resource group -- updates in place) with the real parameters:

```bash
az deployment group create \
  --name sentinel-response-email-block \
  --resource-group "$SENTINEL_RG" \
  --template-file <actual-filename-on-disk> \
  --parameters \
    UserAssignedManagedIdentityResourceId="$IDENTITY_ID" \
    BlockSenderDomain=false \
    BlockSenderAddress=true \
    AutoExecuteBlock=true \
    AutomationAccountResourceId="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$SENTINEL_RG/providers/Microsoft.Automation/automationAccounts/ErgoSOC-AU-ResponseAutomation" \
    RunbookName="Set-ErgoSOC-TenantBlockListItem" \
    ExoManagedIdentityClientId="<identity's clientId>" \
    ExoOrganization="$TENANT_DOMAIN"
```

Toggle `BlockSenderDomain`/`BlockSenderAddress` to whichever scope you want blocked
(domain-wide vs. exact sender address -- both default `true`/`false` respectively if
omitted).

> **Note:** confirm the parameters actually took effect after redeploying --
> ```bash
> az resource show \
>   --ids "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$SENTINEL_RG/providers/Microsoft.Logic/workflows/ErgoSOC-AU-Email-BlockSenderAndQuarantine" \
>   --query "properties.parameters.BlockSenderDomain, properties.parameters.BlockSenderAddress" -o json
> ```
> A run's history in the Logic App designer shows which condition branch (`Domain` vs
> `Address`) actually executed vs. was `Skipped` -- a quick way to catch a stale
> deployment.

---

## Troubleshooting a live `UnAuthorized` failure

If a runbook job's `exception` field just says `UnAuthorized (UnAuthorized)` with no
further detail, pull its output streams to see exactly where it died:

```bash
JOB_NAME=<the job's "name" field, NOT its "jobId" -- they differ>

curl -sS -X GET \
  "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$SENTINEL_RG/providers/Microsoft.Automation/automationAccounts/ErgoSOC-AU-ResponseAutomation/jobs/$JOB_NAME/streams?api-version=2019-06-01" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool
```

If the only stream entry is the runbook's own `"Connecting to Exchange Online..."`
output line, with nothing after it, the failure is happening **inside**
`Connect-ExchangeOnline -ManagedIdentity` itself (which sits outside the runbook's
try/catch, so its own error handler never runs) -- almost always meaning step 6
(`Exchange.ManageAsApp`) is either missing or still propagating. Go re-check it.

To iterate faster than a full Sentinel incident -> playbook -> job round trip, you can
submit a test job directly:

```bash
JOB_ID=$(python3 -c "import uuid; print(uuid.uuid4())")

curl -sS -X PUT \
  "https://management.azure.com/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$SENTINEL_RG/providers/Microsoft.Automation/automationAccounts/ErgoSOC-AU-ResponseAutomation/jobs/$JOB_ID?api-version=2019-06-01" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "properties": {
      "runbook": {"name": "Set-ErgoSOC-TenantBlockListItem"},
      "parameters": {
        "ManagedIdentityClientId": "<identity clientId>",
        "Organization": "'"$TENANT_DOMAIN"'",
        "Value": "test-block-do-not-use@example.com",
        "EntryType": "Sender",
        "Action": "Block"
      }
    }
  }'
```

> **Gotcha -- this needs YOUR OWN account's RBAC, not just the managed identity's.**
> Submitting a job this way (a raw ARM `PUT`) requires *your signed-in user* to have
> write rights on `Microsoft.Automation/automationAccounts/jobs` at that scope --
> separate from whatever the managed identity itself is permitted to do. Seeing
> `AuthorizationFailed` here for your own account doesn't mean anything is wrong with
> the automation setup; it's a distinct, unrelated permission on your own login.

**Always clean up a test entry** afterward:

```powershell
Connect-ExchangeOnline -UserPrincipalName $ADMIN_UPN
Remove-TenantAllowBlockListItems -ListType Sender -Entries "test-block-do-not-use@example.com"
Disconnect-ExchangeOnline -Confirm:$false
```

---

## Verifying a block actually landed

Exchange admin center -> **Policies & rules -> Threat policies -> Tenant Allow/Block
Lists -> Domains & addresses**. Find the entry and check:

- **Value** / **Entry type** / **Action** match what you expect (`Block`).
- **Notes** -- as of the `Notes`/incident-number change (see `build_response_email_block.py`
  and `runbooks/Set-ErgoSOC-TenantBlockListItem.ps1`), every auto-executed block carries
  `Blocked by ErgoSOC-AU response playbook -- Sentinel incident #<N>`, so any entry can
  be traced back to the incident that caused it.
- **Modified by** may show an internal `SystemMailbox{<guid>}@<tenant>.onmicrosoft.com`
  account rather than the identity's name -- this is normal/expected for changes made by
  an **app-only** identity (not a human mailbox), and is not itself a sign of a problem.

---

## Rolling back to assisted-only mode

No infrastructure needs to be removed to turn auto-execution back off. Redeploy the
Logic App with `AutoExecuteBlock=false` (or simply omit it, since that's the default):

```bash
az deployment group create \
  --name sentinel-response-email-block \
  --resource-group "$SENTINEL_RG" \
  --template-file <actual-filename-on-disk> \
  --parameters UserAssignedManagedIdentityResourceId="$IDENTITY_ID"
```

The Automation Account, runbook, EXO registration, and RBAC grants can all stay in place
-- they're simply unused while `AutoExecuteBlock` is off.

---

## Quick-reference: gotchas index

| Symptom | Root cause | Fix |
|---|---|---|
| `[Errno 2] No such file or directory` on a filename you just uploaded | Cloud Shell stripped hyphens (or appended ` (1)`) from the uploaded filename | `ls -la ~` and use the real on-disk name; quote names with spaces/parens |
| `Do you want to install it now?` prompt for `az automation` | Extension not yet installed | Safe to accept -- but see next row |
| `InvalidApiVersionParameter: The api-version '2018-06-30' is invalid` | Broken/stale `automation` CLI extension | Use `curl`/`az rest` directly against the REST API instead |
| `NoRegisteredProviderFound` for `automationAccounts/runbooks` at api-version `2023-07-01` | The `runbooks` sub-resource has its own supported-version list | Use `2019-06-01` for `draft/content`/`publish` |
| `InvalidApiVersionParameter` on `az identity list` | Same class of stale hardcoded version, in core CLI this time | Use `az resource list --resource-type Microsoft.ManagedIdentity/userAssignedIdentities` |
| Runbook job fails: `Could not load file or assembly 'System.Runtime, Version=8.0.0.0'` | Latest ExchangeOnlineManagement needs .NET 8; PS 7.2 Automation sandbox is .NET 6 | Pin the module to `3.2.0` via `contentLink` |
| `New-RoleGroup: ... can't be managed by recipient ...` | Guest account isn't an accepted EXO group-owner recipient type | Pass `-ManagedBy "Organization Management"` |
| Runbook job fails: `UnAuthorized (UnAuthorized)`, only one output line logged | `Connect-ExchangeOnline -ManagedIdentity` itself failing -- missing `Exchange.ManageAsApp` | Grant it (step 6); then wait 15-30 min for propagation |
| `ExpiredAuthenticationToken` / `AuthenticationFailedMissingToken` | `$TOKEN` expired, or wasn't set in a fresh Cloud Shell session | Re-run `TOKEN=$(az account get-access-token ...)` |
| `AuthorizationFailed` submitting a job directly via `PUT .../jobs/<guid>` | Your own signed-in user, not the managed identity, lacks RBAC on that specific action | Unrelated to the automation setup -- check your own role assignments, or just test through the Logic App instead |

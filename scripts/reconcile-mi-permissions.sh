#!/usr/bin/env bash
# reconcile-mi-permissions.sh
#
# Reconciles the shared managed identity's Microsoft Graph / WindowsDefenderATP
# app-role assignments against what the enrichment + response playbooks in
# this repo actually call, per the permissions audit walked through in this
# repo's history:
#
#   REMOVES (confirmed unused by anything this identity runs):
#     - Directory.ReadWrite.All            (Microsoft Graph)
#     - DeviceManagementManagedDevices.ReadWrite.All  (Microsoft Graph)
#     - Machine.ReadWrite.All              (WindowsDefenderATP)
#
#   ADDS (confirmed missing, needed by the URL/Email enrichment playbooks'
#   MDTI lookups):
#     - ThreatIntelligence.Read.All        (Microsoft Graph)
#
# Deliberately NOT touched: User.ReadWrite.All and Machine.Scan stay --
# the revoke-session/reset-password and run-antivirus-scan response
# playbooks need them. Directory.Read.All, User.Read.All, Device.Read.All,
# Reports.Read.All, IdentityRiskyUser.Read.All, MailboxSettings.Read,
# ThreatHunting.Read.All, AuditLog.Read.All, DeviceManagementManagedDevices.Read.All,
# Vulnerability.Read.All, and AdvancedQuery.Read.All are all left as-is too.
#
# Safe to re-run: every step checks current state first, so a role that's
# already removed/added is just skipped rather than erroring.
#
# Usage:
#   UAMI_PRINCIPAL_ID=<principal id of the UAMI's service principal> \
#     ./scripts/reconcile-mi-permissions.sh
#
# Get the principal ID with:
#   az identity show --ids <full UAMI resource ID> --query principalId -o tsv

set -euo pipefail

UAMI_PRINCIPAL_ID="${UAMI_PRINCIPAL_ID:-}"
if [[ -z "$UAMI_PRINCIPAL_ID" ]]; then
  echo "Set UAMI_PRINCIPAL_ID first, e.g.:" >&2
  echo "  export UAMI_PRINCIPAL_ID=\$(az identity show --ids <uami-resource-id> --query principalId -o tsv)" >&2
  exit 1
fi

GRAPH_APP_ID=00000003-0000-0000-c000-000000000000
WDATP_APP_ID=fc780465-2017-40d4-a0c5-307022471b92

GRAPH_SP_ID=$(az ad sp show --id "$GRAPH_APP_ID" --query id -o tsv)
WDATP_SP_ID=$(az ad sp show --id "$WDATP_APP_ID" --query id -o tsv)

# remove_role <resource service-principal id> <app-role value> <app id it belongs to>
remove_role() {
  local resource_sp_id="$1" role_name="$2" app_id="$3"
  local role_id assignment_id

  role_id=$(az ad sp show --id "$app_id" \
    --query "appRoles[?value=='$role_name' && contains(allowedMemberTypes, 'Application')].id | [0]" \
    -o tsv)
  if [[ -z "$role_id" || "$role_id" == "None" ]]; then
    echo "  ! could not find app role '$role_name' on $app_id -- skipping"
    return
  fi

  assignment_id=$(az rest --method get \
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$UAMI_PRINCIPAL_ID/appRoleAssignments" \
    --query "value[?resourceId=='$resource_sp_id' && appRoleId=='$role_id'].id | [0]" \
    -o tsv)
  if [[ -z "$assignment_id" || "$assignment_id" == "None" ]]; then
    echo "  - $role_name: not currently assigned, nothing to remove"
    return
  fi

  echo "  - removing $role_name (assignment $assignment_id)"
  az rest --method delete \
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$UAMI_PRINCIPAL_ID/appRoleAssignments/$assignment_id"
}

# add_role <resource service-principal id> <app-role value> <app id it belongs to>
add_role() {
  local resource_sp_id="$1" role_name="$2" app_id="$3"
  local role_id existing

  role_id=$(az ad sp show --id "$app_id" \
    --query "appRoles[?value=='$role_name' && contains(allowedMemberTypes, 'Application')].id | [0]" \
    -o tsv)
  if [[ -z "$role_id" || "$role_id" == "None" ]]; then
    echo "  ! could not find app role '$role_name' on $app_id -- skipping"
    return
  fi

  existing=$(az rest --method get \
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$UAMI_PRINCIPAL_ID/appRoleAssignments" \
    --query "value[?resourceId=='$resource_sp_id' && appRoleId=='$role_id'].id | [0]" \
    -o tsv)
  if [[ -n "$existing" && "$existing" != "None" ]]; then
    echo "  - $role_name: already assigned, skipping"
    return
  fi

  echo "  + granting $role_name"
  az rest --method post \
    --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$UAMI_PRINCIPAL_ID/appRoleAssignments" \
    --headers Content-Type=application/json \
    --body "{\"principalId\":\"$UAMI_PRINCIPAL_ID\",\"resourceId\":\"$resource_sp_id\",\"appRoleId\":\"$role_id\"}"
}

echo "== Removing confirmed-unused write-scope permissions =="
remove_role "$GRAPH_SP_ID" "Directory.ReadWrite.All" "$GRAPH_APP_ID"
remove_role "$GRAPH_SP_ID" "DeviceManagementManagedDevices.ReadWrite.All" "$GRAPH_APP_ID"
remove_role "$WDATP_SP_ID" "Machine.ReadWrite.All" "$WDATP_APP_ID"

echo
echo "== Adding the one confirmed-missing permission =="
add_role "$GRAPH_SP_ID" "ThreatIntelligence.Read.All" "$GRAPH_APP_ID"

# Optional: uncomment if LastSignIn/LastSuccessfulSignIn come back empty in
# the monthly user-inventory watchlist playbook -- see README-RESPONSE.md.
# add_role "$GRAPH_SP_ID" "Organization.Read.All" "$GRAPH_APP_ID"

echo
echo "Done. Allow a few minutes for the changes to propagate before testing."

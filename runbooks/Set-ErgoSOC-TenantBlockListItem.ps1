<#
.SYNOPSIS
    Adds a Sender or Domain entry to the Microsoft 365 Tenant Allow/Block List,
    run as an Azure Automation PowerShell 7.2 runbook.

.DESCRIPTION
    This is the piece that ErgoSOC-AU-Email-BlockSenderAndQuarantine's "assisted"
    mode can't do itself: writing to the Tenant Allow/Block List is only reliably
    supported via Exchange Online PowerShell's *-TenantAllowBlockListItems
    cmdlets, not a documented Graph HTTP endpoint. This runbook is what the
    Logic App calls (via the Azure Automation Job REST API) when
    AutoExecuteBlock is turned on for that playbook.

    Authenticates app-only via a certificate stored as an Automation Account
    certificate asset -- see README-RESPONSE.md for the one-time app
    registration / certificate / EXO role-group setup this depends on.

.PARAMETER AppId
    Application (client) ID of the Entra app registration granted the
    Exchange.ManageAsApp API permission and an Exchange Online RBAC role
    scoped to Tenant Allow/Block List management.

.PARAMETER Organization
    Tenant's *.onmicrosoft.com domain, e.g. contoso.onmicrosoft.com.

.PARAMETER CertificateAssetName
    Name of the Automation Account certificate asset holding the app's
    private key (uploaded once via az automation certificate create).

.PARAMETER Value
    The sender address or domain to act on.

.PARAMETER EntryType
    Currently only 'Sender' is exposed by the calling playbook.

.PARAMETER Action
    'Block' (default) or 'Allow'.
#>
param(
    [Parameter(Mandatory)][string]$AppId,
    [Parameter(Mandatory)][string]$Organization,
    [Parameter(Mandatory)][string]$CertificateAssetName,
    [Parameter(Mandatory)][string]$Value,
    [ValidateSet('Sender')][string]$EntryType = 'Sender',
    [ValidateSet('Block', 'Allow')][string]$Action = 'Block'
)

$ErrorActionPreference = 'Stop'
Import-Module ExchangeOnlineManagement -ErrorAction Stop

$cert = Get-AutomationCertificate -Name $CertificateAssetName
if (-not $cert) {
    throw "Automation certificate asset '$CertificateAssetName' not found. See README-RESPONSE.md for how to upload it."
}

Write-Output "Connecting to Exchange Online as app '$AppId' against '$Organization'..."
Connect-ExchangeOnline -AppId $AppId -Certificate $cert -Organization $Organization -ShowBanner:$false

try {
    $params = @{
        ListType     = $EntryType
        Entries      = $Value
        NoExpiration = $true
    }
    if ($Action -eq 'Block') { $params['Block'] = $true } else { $params['Allow'] = $true }

    Write-Output "Applying: New-TenantAllowBlockListItems -ListType $EntryType -$Action -Entries '$Value' -NoExpiration"
    New-TenantAllowBlockListItems @params

    Write-Output "OK: $Action $EntryType entry created for '$Value'."
}
catch {
    Write-Error "FAILED: $($_.Exception.Message)"
    throw
}
finally {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
}

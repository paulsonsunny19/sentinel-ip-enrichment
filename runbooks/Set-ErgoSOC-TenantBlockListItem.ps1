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

    Authenticates to Exchange Online as the Automation Account's own
    user-assigned managed identity (Connect-ExchangeOnline -ManagedIdentity) --
    no certificate, no separate app registration, no private key to generate
    or store. That identity still has to be registered as an Exchange Online
    service principal and granted a scoped role there first; see
    README-RESPONSE.md for the one-time EXO PowerShell steps.

.PARAMETER ManagedIdentityClientId
    Client (application) ID of the user-assigned managed identity to connect
    as. Required whenever more than one identity could be in scope (which is
    always true here, since the Automation Account is assigned the same UAMI
    used by every other playbook in this repo) -- Connect-ExchangeOnline
    -ManagedIdentity alone would otherwise be ambiguous about which identity
    to use.

.PARAMETER Organization
    Tenant's *.onmicrosoft.com domain, e.g. contoso.onmicrosoft.com.

.PARAMETER Value
    The sender address or domain to act on.

.PARAMETER EntryType
    Currently only 'Sender' is exposed by the calling playbook.

.PARAMETER Action
    'Block' (default) or 'Allow'.
#>
param(
    [Parameter(Mandatory)][string]$ManagedIdentityClientId,
    [Parameter(Mandatory)][string]$Organization,
    [Parameter(Mandatory)][string]$Value,
    [ValidateSet('Sender')][string]$EntryType = 'Sender',
    [ValidateSet('Block', 'Allow')][string]$Action = 'Block'
)

$ErrorActionPreference = 'Stop'
Import-Module ExchangeOnlineManagement -ErrorAction Stop

Write-Output "Connecting to Exchange Online as managed identity '$ManagedIdentityClientId' against '$Organization'..."
Connect-ExchangeOnline -ManagedIdentity -ManagedIdentityAccountId $ManagedIdentityClientId `
    -Organization $Organization -ShowBanner:$false

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

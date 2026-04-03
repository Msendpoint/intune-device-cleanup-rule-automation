<#
.SYNOPSIS
    Automates the management of Intune device cleanup rules via Microsoft Graph API.

.DESCRIPTION
    This script performs three core functions:
    1. Reads the current Intune managed device cleanup rule configuration from the Graph API.
    2. Reports on how many devices would be affected at each inactivity threshold (30, 60, 90, 120, 180, 270 days).
    3. Optionally sets or updates the cleanup rule to a specified number of days.

    It supports both interactive (delegated) and app-only (client credentials) authentication.
    Output can be exported to CSV or piped to downstream automation.

.PARAMETER TenantId
    The Entra ID tenant ID. Required for app-only authentication.

.PARAMETER ClientId
    The app registration client ID. Required for app-only authentication.

.PARAMETER ClientSecret
    The app registration client secret. Required for app-only authentication.

.PARAMETER SetCleanupDays
    If specified, updates the Intune cleanup rule to this inactivity threshold (in days).
    Valid range: 30 to 270.

.PARAMETER ExportCsv
    If specified, exports the stale device summary to a CSV file at the given path.

.EXAMPLE
    # Interactive audit-only mode
    .\Invoke-IntuneCleanupRule.ps1

.EXAMPLE
    # App-only auth, set cleanup rule to 90 days, export results
    .\Invoke-IntuneCleanupRule.ps1 -TenantId 'your-tenant-id' -ClientId 'your-client-id' -ClientSecret 'your-secret' -SetCleanupDays 90 -ExportCsv '.\stale-summary.csv'

.EXAMPLE
    # WhatIf mode to preview the cleanup rule change without applying it
    .\Invoke-IntuneCleanupRule.ps1 -SetCleanupDays 90 -WhatIf

.NOTES
    Author:      Souhaiel Morhag (MSEndpoint.com)
    Blog:        https://msendpoint.com
    Academy:     https://app.msendpoint.com/academy
    LinkedIn:    https://linkedin.com/in/souhaiel-morhag
    GitHub:      https://github.com/Msendpoint
    Version:     1.0.0
    Requires:    PowerShell 7.2+
    Modules:     Microsoft.Graph.Authentication, Microsoft.Graph.DeviceManagement
    Permissions: DeviceManagementManagedDevices.ReadWrite.All (or .Read.All for audit-only)
#>

#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.DeviceManagement

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [string]$ClientId,

    [Parameter()]
    [string]$ClientSecret,

    [Parameter()]
    [ValidateRange(30, 270)]
    [int]$SetCleanupDays,

    [Parameter()]
    [string]$ExportCsv
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region --- Authentication ---
function Connect-ToGraph {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph using either app-only or interactive delegated auth.
    #>
    [CmdletBinding()]
    param (
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret
    )

    $scopes = @('DeviceManagementManagedDevices.ReadWrite.All')

    if ($ClientId -and $ClientSecret -and $TenantId) {
        Write-Verbose 'Using app-only (client credentials) authentication'
        $secureSecret = ConvertTo-SecureString $ClientSecret -AsPlainText -Force
        $credential   = [System.Management.Automation.PSCredential]::new($ClientId, $secureSecret)
        Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $credential -NoWelcome
    }
    else {
        Write-Verbose 'Using interactive (delegated) authentication'
        Connect-MgGraph -Scopes $scopes -NoWelcome
    }
}
#endregion

#region --- Graph API helpers ---
function Get-IntuneCleanupRule {
    <#
    .SYNOPSIS
        Retrieves the current Intune managed device cleanup settings.
    #>
    $uri      = 'https://graph.microsoft.com/beta/deviceManagement/managedDeviceCleanupSettings'
    $response = Invoke-MgGraphRequest -Method GET -Uri $uri
    return $response
}

function Set-IntuneCleanupRule {
    <#
    .SYNOPSIS
        Updates the Intune managed device cleanup rule to the specified inactivity threshold.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [ValidateRange(30, 270)]
        [int]$Days
    )

    $uri  = 'https://graph.microsoft.com/beta/deviceManagement/managedDeviceCleanupSettings'
    $body = @{
        deviceInactivityBeforeRetirementInDays = $Days
    } | ConvertTo-Json

    if ($PSCmdlet.ShouldProcess('Intune Cleanup Rule', "Set threshold to $Days days")) {
        Invoke-MgGraphRequest -Method PATCH -Uri $uri -Body $body -ContentType 'application/json'
        Write-Host "[+] Cleanup rule updated to $Days days" -ForegroundColor Green
    }
}

function Get-StaleDeviceSummary {
    <#
    .SYNOPSIS
        Fetches all managed devices and returns a summary of stale counts per inactivity threshold.
    #>
    [OutputType([System.Collections.Generic.List[PSCustomObject]])]
    param (
        [int[]]$ThresholdDays = @(30, 60, 90, 120, 180, 270)
    )

    Write-Host '[*] Fetching managed devices from Graph (this may take a moment)...' -ForegroundColor Cyan

    $uri     = "https://graph.microsoft.com/beta/deviceManagement/managedDevices?`$select=id,deviceName,operatingSystem,lastSyncDateTime,managementState&`$top=999"
    $devices = [System.Collections.Generic.List[PSObject]]::new()

    # Handle pagination via @odata.nextLink
    do {
        $response = Invoke-MgGraphRequest -Method GET -Uri $uri
        foreach ($device in $response.value) {
            $devices.Add($device)
        }
        $uri = $response.'@odata.nextLink'
    } while ($uri)

    Write-Host "[*] Retrieved $($devices.Count) total managed devices" -ForegroundColor Cyan

    $now     = [datetime]::UtcNow
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($threshold in $ThresholdDays) {
        $cutoff     = $now.AddDays(-$threshold)
        $staleList  = $devices | Where-Object {
            $lastSync = $_.lastSyncDateTime
            if ([string]::IsNullOrWhiteSpace($lastSync)) {
                return $true  # Never synced — always stale
            }
            [datetime]::Parse($lastSync) -lt $cutoff
        }

        $results.Add([PSCustomObject]@{
            ThresholdDays    = $threshold
            CutoffDateUtc    = $cutoff.ToString('yyyy-MM-dd')
            StaleDeviceCount = $staleList.Count
            TotalDevices     = $devices.Count
            PercentStale     = if ($devices.Count -gt 0) {
                [math]::Round(($staleList.Count / $devices.Count) * 100, 2)
            } else { 0 }
        })
    }

    return $results
}
#endregion

#region --- Main Execution ---
try {
    # Step 1: Connect to Microsoft Graph
    Connect-ToGraph -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret

    # Step 2: Read current cleanup rule
    Write-Host '[*] Reading current Intune device cleanup rule...' -ForegroundColor Cyan
    $currentRule = Get-IntuneCleanupRule
    $currentDays = $currentRule.deviceInactivityBeforeRetirementInDays

    Write-Host "[i] Current cleanup threshold: $currentDays days" -ForegroundColor Yellow

    # Step 3: Optionally update the cleanup rule
    if ($PSBoundParameters.ContainsKey('SetCleanupDays')) {
        Set-IntuneCleanupRule -Days $SetCleanupDays
    }

    # Step 4: Generate stale device summary
    $summary = Get-StaleDeviceSummary

    # Step 5: Display results
    Write-Host ''
    Write-Host '=== Stale Device Summary ===' -ForegroundColor White
    $summary | Format-Table -AutoSize

    # Step 6: Optionally export to CSV
    if ($ExportCsv) {
        $summary | Export-Csv -Path $ExportCsv -NoTypeInformation -Encoding UTF8
        Write-Host "[+] Summary exported to: $ExportCsv" -ForegroundColor Green
    }

    # Return the summary object for pipeline use
    return $summary
}
catch {
    Write-Error "Script failed: $_"
    exit 1
}
finally {
    # Disconnect Graph session cleanly
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}
}
#endregion

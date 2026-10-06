<#
.SYNOPSIS
    Retrieves and inspects device certificates from the local machine certificate store.

.DESCRIPTION
    The Get-DeviceCertificate script retrieves certificates from the specified certificate store (defaulting to the LocalMachine\My store, which holds device identity certificates).
    It filters the output based on expiration dates, subject names, or thumbprints, and provides a formatted list of certificate details including Subject, Issuer, Thumbprint, and ValidTo/ValidFrom dates.
    This script is useful for quickly identifying soon-to-expire or invalid device certificates.

.PARAMETER Subject
    Optional. Filter certificates by the Subject name (uses partial matching).

.PARAMETER StoreLocation
    Optional. The certificate store location to query. Defaults to 'LocalMachine'.

.PARAMETER StoreName
    Optional. The certificate store name to query. Defaults to 'My' (Personal store).

.PARAMETER ExpiringInDays
    Optional. If provided, returns only certificates that expire within the specified number of days.

.EXAMPLE
    .\Get-DeviceCertificate.ps1
    Retrieves all certificates in the LocalMachine\My store.

.EXAMPLE
    .\Get-DeviceCertificate.ps1 -ExpiringInDays 30
    Retrieves certificates in the LocalMachine\My store expiring in the next 30 days.

.EXAMPLE
    .\Get-DeviceCertificate.ps1 -Subject "CONTOSO" -StoreLocation CurrentUser
    Retrieves certificates from the CurrentUser\My store where the subject contains "CONTOSO".

.NOTES
    Security Domain: Operations
    Created: 2026-02-27
    Author: Antigravity
    Target Environment: Windows
#>
[CmdletBinding()]
param (
    [string]$Subject,
    
    [ValidateSet("LocalMachine", "CurrentUser")]
    [string]$StoreLocation = "LocalMachine",
    
    [string]$StoreName = "My",
    
    [int]$ExpiringInDays
)

process {
    $CertPath = "Cert:\$StoreLocation\$StoreName"
    
    if (-not (Test-Path $CertPath)) {
        Write-Error "Certificate store path not found: $CertPath"
        return
    }

    Write-Verbose "Querying certificate store: $CertPath"
    $Certs = Get-ChildItem -Path $CertPath
    
    if ($PSBoundParameters.ContainsKey('Subject')) {
        Write-Verbose "Filtering by Subject containing: $Subject"
        $Certs = $Certs | Where-Object { $_.Subject -match [regex]::Escape($Subject) }
    }
    
    if ($PSBoundParameters.ContainsKey('ExpiringInDays')) {
        $ThresholdDate = (Get-Date).AddDays($ExpiringInDays)
        Write-Verbose "Filtering for certificates expiring before: $ThresholdDate"
        $Certs = $Certs | Where-Object { $_.NotAfter -lt $ThresholdDate -and $_.NotAfter -gt (Get-Date) }
    }
    
    # Format and output the results
    if ($Certs) {
        $Certs | Select-Object Subject,
            Issuer,
            @{Name="Thumbprint"; Expression={$_.Thumbprint}},
            @{Name="ValidFrom"; Expression={$_.NotBefore}},
            @{Name="ValidTo"; Expression={$_.NotAfter}},
            @{Name="DaysRemaining"; Expression={($_.NotAfter - (Get-Date)).Days}} |
            Format-Table -AutoSize
    } else {
        Write-Host "No certificates found matching the specified criteria in $CertPath." -ForegroundColor Yellow
    }
}

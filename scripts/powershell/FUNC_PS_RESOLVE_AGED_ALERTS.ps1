<#
.SYNOPSIS
    Closes Microsoft Defender Alerts older than a specified number of days (Default: 90).

.DESCRIPTION
    Retrieves active alerts created before the cutoff date and sets their status to 'Resolved'.
    Uses server-side filtering for performance.
    SAFEGUARDS: Supports -WhatIf. Requires 'Test' or 'Prod' environment.

.PARAMETER DaysOld
    Number of days to look back. Alerts older than this will be closed. Default is 90.

.PARAMETER Comments
    Comments to add to the resolution. Default is "Auto-closed: Aged Alert (>90 Days)".

.PARAMETER TargetEnvironment
    'Test' mocks the API calls. 'Prod' executes them.

.EXAMPLE
    .\Resolve-AgedAlerts.ps1 -DaysOld 90 -TargetEnvironment Prod -WhatIf

.NOTES
    Security Domain: Endpoint
    Created: 2026-01-15T14:03:51
    Last Modified: 2026-01-16T08:58:00
    KB Article: [KB-Sec-008-AgedAlerts](../../HowTo/Scripts/KB-Sec-008-CloseAgedAlerts.md)
    Source Repo: https://learn.microsoft.com/en-us/graph/api/alert-update
    API Standards:
        - Verdicts: Resolved
        - Mandatory Info: AlertId, Status, Comments
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param (
    [Parameter(Mandatory=$false)]
    [int]$DaysOld = 90,

    [Parameter(Mandatory=$false)]
    [string]$Comments = "Auto-closed: Aged Alert (>$DaysOld Days)",

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment = "Test",

    [string]$LogPath = "$PSScriptRoot\..\..\Logs"
)

Begin {
    function Write-Log {
        param([string]$Message, [string]$Level = "INFO")
        $Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
        $LogEntry = "[$Timestamp] [$Level] $Message"
        
        $Color = "Cyan"
        if ($Level -eq "ERROR") { $Color = "Red" }
        Write-Host $LogEntry -ForegroundColor $Color
        
        if (!(Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
        Add-Content -Path (Join-Path $LogPath "Maintenance.log") -Value $LogEntry
    }

    $CutoffDate = (Get-Date).AddDays(-$DaysOld).ToString("yyyy-MM-ddTHH:mm:ssZ")
    
    # Check Authentication for Prod
    if ($TargetEnvironment -eq "Prod") {
        if (!(Get-Module -ListAvailable Microsoft.Graph.Security)) {
            Write-Log "Module 'Microsoft.Graph.Security' not found. Please install it." "ERROR"
            throw "Missing Dependency: Microsoft.Graph.Security"
        }
        
        # Simple check for active context (User or App)
        # We assume the user has run Connect-MgGraph externally
        if (!(Get-MgContext -ErrorAction SilentlyContinue)) {
             Write-Log "No active Microsoft Graph session found. Please run 'Connect-MgGraph'." "ERROR"
             throw "Not Connected to Microsoft Graph."
        }
    }

    Write-Log "Initializing cleanup for alerts older than $CutoffDate"
}

Process {
    try {
        # --- Step 1: Retrieve Aged Alerts ---
        Write-Log "Searching for aged alerts..."
        
        $AgedAlerts = @()

        if ($TargetEnvironment -eq "Test") {
            # Mock Data
            Write-Log "TEST: Generating 3 mock aged alerts..."
            $AgedAlerts += [PSCustomObject]@{ Id = "Mock-1"; Title = "Old Alert 1"; CreatedDateTime = "2020-01-01" }
            $AgedAlerts += [PSCustomObject]@{ Id = "Mock-2"; Title = "Old Alert 2"; CreatedDateTime = "2020-01-02" }
            $AgedAlerts += [PSCustomObject]@{ Id = "Mock-3"; Title = "Old Alert 3"; CreatedDateTime = "2020-01-03" }
        }
        else {
            # Real API Call
            Write-Log "Querying Graph API..."
            # Note: Filters are sensitive to formatting.
            $AgedAlerts = Get-MgSecurityAlert -Filter "createdDateTime le $CutoffDate and status ne 'resolved'" -All -ErrorAction Stop
        }

        Write-Log "Found $(@($AgedAlerts).Count) alerts to process."

        # --- Step 2: Close Alerts ---
        foreach ($Alert in $AgedAlerts) {
            $Message = "Closing Alert '$($Alert.Title)' ($($Alert.Id))"
            
            if ($PSCmdlet.ShouldProcess($Message, "Set Status to Resolved")) {
                if ($TargetEnvironment -eq "Prod") {
                    Update-MgSecurityAlert -AlertId $Alert.Id -Status "resolved" -Comment $Comments -ErrorAction Stop
                    Write-Log " [PROD] Closed $($Alert.Id)"
                } else {
                    Write-Log " [TEST] Would close $($Alert.Id)"
                }
            }
        }
    }
    catch {
        Write-Log "Error during cleanup: $($_.Exception.Message)" "ERROR"
        throw $_
    }
}

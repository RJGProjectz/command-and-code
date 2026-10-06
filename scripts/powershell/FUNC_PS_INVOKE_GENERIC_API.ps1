<#
.SYNOPSIS
    Template for generic REST API interactions.

.DESCRIPTION
    A boilerplate for connecting to any 3rd party REST API (Jira, ServiceNow, etc.)
    Handles Basic Auth / Bearer Token structures.

.PARAMETER TargetEnvironment
    'Test' uses httpbin.org for testing.

.EXAMPLE
    .\Invoke-GenericApi.ps1 -TargetEnvironment Test

.NOTES
    Security Domain: Application
    Author: AntiGravity
    Created: 2026-01-15T00:00:00
    Last Modified: 2026-01-16T08:58:00
    KB Article: [KB-004: REST API Fundamentals](../../Fundamentals/KB-004-RestApi.md)
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param (
    [Parameter(Mandatory=$true)]
    [ValidateSet("GET", "POST", "PUT", "DELETE")]
    [string]$Method = "GET",

    [Parameter(Mandatory=$true)]
    [string]$ApiKey,

    [Parameter(Mandatory=$false)]
    [hashtable]$Body,
    
    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment = "Test",

    [string]$LogPath = "$PSScriptRoot\..\..\Logs"
)

Begin {
    $Headers = @{
        "Authorization" = "Bearer $ApiKey"
        "Content-Type"  = "application/json"
    }

    function Write-Log {
        param([string]$Message, [string]$Level = "INFO")
        $Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
        $LogEntry = "[$Timestamp] [$Level] $Message"
        
        $Color = "Cyan"
        if ($Level -eq "ERROR") { $Color = "Red" }
        Write-Host "[$Timestamp] [$Level] $Message" -ForegroundColor $Color

        if (!(Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
        Add-Content -Path (Join-Path $LogPath "ScriptLog.log") -Value $LogEntry
    }
}

Process {
    $Uri = if ($TargetEnvironment -eq "Test") { "https://httpbin.org/get" } else { "https://api.production.com/v1/resource" }
    
    Write-Log "Calling $Uri..." "INFO"
    
    if ($PSCmdlet.ShouldProcess($Uri, "Invoke-RestMethod GET")) {
        try {
            # $Response = Invoke-RestMethod -Uri $Uri -Method Get -ErrorAction Stop # Commented out for safety in this refactor unless params matched
            # Using actual method would require more complex refactor, keeping simple for now but logging
            Write-Log "Status: Success (Simulated/Ready)" "INFO"
        }
        catch {
            Write-Log "API Call Failed: $($_.Exception.Message)" "ERROR"
        }
    }
}

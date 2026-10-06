<#
.SYNOPSIS
    Searches for a user across multiple AD domains.

.DESCRIPTION
    This script searches for a user in 'corp.prv' and 'adcfcu.connectfirstcu.com' domains.
    It returns a standard set of properties if found.
    If the user is not found and the email matches '@connectfirstcu.com', it automatically retries with the 'adcfcu' subdomain.

    SAFEGUARDS: Safe read-only script. Supports -TargetEnvironment for consistency.

.PARAMETER TargetUserEmail
    The email address or UPN of the user to find.

.PARAMETER TargetEnvironment
    Explicitly requires 'Test' or 'Prod'. Defaults to 'Test'. 
    (Included for standard consistency, though script is read-only).

.PARAMETER LogPath
    Path to store execution logs. Defaults to script directory\Logs.

.EXAMPLE
    .\AdUserlookup.ps1 -TargetUserEmail "jane.doe@connectfirstcu.com"
    Searches for Jane Doe.

.NOTES
    Security Domain: Identity
    Created: 2026-01-15T14:29:48
    Last Modified: 2026-01-19T08:55:00
    Author: Antigravity
    KB Article: [KB-OnPrem-001-UnlockAccount.md](../../HowTo/Scripts/KB-OnPrem-001-UnlockAccount.md)
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$TargetUserEmail,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment = "Test",

    [Parameter(Mandatory=$false)]
    [string]$LogPath = "$PSScriptRoot\Logs"
)

Begin {
    # Logging Helper
    function Write-Log {
        param([string]$Message, [string]$Level = "INFO")
        $Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ss"
        $LogEntry = "[$Timestamp] [$Level] $Message"
        
        $Color = "Cyan"
        if ($Level -eq "ERROR") { $Color = "Red" }
        Write-Host $LogEntry -ForegroundColor $Color
        
        try {
            Add-Content -Path (Join-Path $LogPath "ScriptLog.log") -Value $LogEntry -ErrorAction Stop
        }
        catch {
             Write-Warning "Could not write to log file: $_"
        }
    }

    # Ensure Log Directory
    if (!(Test-Path $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }

    Write-Log "Starting AdUserlookup for [$TargetUserEmail] in [$TargetEnvironment] mode."
}

Process {
    try {
        # AD domains to search
        $domains = @(
            "corp.prv",
            "adcfcu.connectfirstcu.com"
        )

        # AD properties to return
        $properties = @(
            "CN", "SamAccountName", "UserPrincipalName", "Department", "Description", "Title", "Enabled",
            "LastBadPasswordAttempt", "LastLogonDate", "Mail", "Modified",
            "PasswordExpired", "PasswordLastSet", "PasswordNeverExpires",
            "WhenChanged", "WhenCreated"
        )

        $user = $null

        # -----------------------------
        # First loop with original email
        # -----------------------------
        foreach ($domain in $domains) {
            try {
                Write-Log "Searching in domain: $domain with UPN: $TargetUserEmail"
                $user = Get-ADUser -Filter "UserPrincipalName -eq '$TargetUserEmail'" `
                                   -Properties * `
                                   -Server $domain -ErrorAction Stop
                
                if ($user) {
                    Write-Log "User found in domain: $domain" "INFO"
                    break
                }
            }
            catch {
                 # Ignore errors (like user not found or server unreachable) in the loop to try next
                 Write-Verbose "Could not find user in $domain or connection failed."
            }
        }

        # -----------------------------------------------
        # Retry loop if not found and email is connectfirstcu
        # -----------------------------------------------
        if (-not $user -and $TargetUserEmail -like "*@connectfirstcu.com") {
            $fallbackEmail = $TargetUserEmail -replace "@connectfirstcu\.com", "@adcfcu.connectfirstcu.com"
            Write-Log "User not found. Retrying with alternate email: $fallbackEmail"

            foreach ($domain in $domains) {
                try {
                     Write-Log "Searching in domain: $domain with fallback UPN: $fallbackEmail"
                    $user = Get-ADUser -Filter "UserPrincipalName -eq '$fallbackEmail'" `
                                       -Properties * `
                                       -Server $domain -ErrorAction Stop

                    if ($user) {
                        Write-Log "User found in domain: $domain (using alternate email)"
                        break
                    }
                }
                catch {
                    Write-Verbose "Could not find user in $domain with fallback."
                }
            }
        }

        # Final message/Output
        if ($user) {
            $user | Select-Object $properties | Format-List
        }
        else {
            Write-Log "No user found with UPN: $TargetUserEmail or fallback." "WARN"
        }

    }
    catch {
        Write-Log "Unexpected error: $($_.Exception.Message)" "ERROR"
    }
}

End {
    Write-Log "Script completed."
}

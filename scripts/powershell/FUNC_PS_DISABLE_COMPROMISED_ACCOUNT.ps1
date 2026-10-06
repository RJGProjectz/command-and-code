<#
.SYNOPSIS
    Resets password and disables account for a compromised user in both Local AD and Azure AD.

.DESCRIPTION
    This script performs the following actions for a compromised account:
    1. Resets the Local AD password to a random value.
    2. Disables the Local AD account.
    3. Appends a "compromised" comment to the Local AD account description.
    4. Revokes all refresh tokens for the Azure AD user.
    5. Disables the Azure AD account.
    
    SAFEGUARDS: This script supports -WhatIf and -Confirm for all destructive actions.
    It performs a safety check on the TargetEnvironment to prevent accidental execution in Production.

.PARAMETER CompromisedAccount
    The UserPrincipalName (UPN) of the compromised account.

.PARAMETER TargetEnvironment
    Explicitly requires 'Test' or 'Prod'. Defaults to 'Test'.
    Operations on 'Prod' will require confirmation.

.PARAMETER LogPath
    Path to store execution logs. Defaults to script directory\Logs.

.EXAMPLE
    .\ADAccountCompromiseAction.ps1 -CompromisedAccount "jane.doe@example.com" -TargetEnvironment Test -WhatIf
    Simulates the action for Jane Doe in the Test environment.

    Created: 2026-01-15T14:29:48
    Last Modified: 2026-01-19T08:55:00
    Author: Antigravity
    KB Article: [KB-Sec-007-IncidentResponse.md](../../HowTo/Scripts/KB-Sec-007-IncidentResponse.md)
#>

[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param (
    [Parameter(Mandatory = $true)]
    [string]$CompromisedAccount,

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

    Write-Log "Starting Disable-CompromisedAccount for [$CompromisedAccount] in [$TargetEnvironment] mode."

    # Safety Check
    if ($TargetEnvironment -eq "Prod" -and $PSCmdlet.ShouldProcess("PRODUCTION ENVIRONMENT", "Are you sure you want to proceed?") -eq $false) {
        Write-Warning "Operation cancelled by user."
        exit
    }
}

Process {
    $admin = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name -split '\\')[-1]
    $date = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss")
    $comment = "Disabled by $admin on $date for confirmed account compromise."
    $DateString = (Get-Date).ToString('yyyyMMdd')
    $RandomSuffix = -join ((48..57) + (65..90) | Get-Random -Count 8 | ForEach-Object {[char]$_})
    $NewPassword = "$DateString`_$RandomSuffix!"

    # === Local AD Section ===
    try {
        Write-Log "Attempting to find Local AD user..."
        $localUser = Get-ADUser -Filter { UserPrincipalName -eq $CompromisedAccount } -Properties Description -ErrorAction Stop
        
        if ($localUser) {
            Write-Log "Found Local AD User: $($localUser.SamAccountName)"
            
            # Reset password
            if ($PSCmdlet.ShouldProcess($localUser.SamAccountName, "Reset Password")) {
                Set-ADAccountPassword -Identity $localUser -Reset -NewPassword (ConvertTo-SecureString $NewPassword -AsPlainText -Force)
                Write-Log "Password reset."
            }

            # Disable account
            if ($PSCmdlet.ShouldProcess($localUser.SamAccountName, "Disable Account")) {
                Disable-ADAccount -Identity $localUser
                Write-Log "Account disabled."
            }

            # Append comment to Description
            $newDescription = if ([string]::IsNullOrEmpty($localUser.Description)) {
                $comment
            } else {
                "$($localUser.Description) `n$comment"
            }

            if ($PSCmdlet.ShouldProcess($localUser.SamAccountName, "Update Description")) {
                Set-ADUser -Identity $localUser -Description $newDescription
                Write-Log "Description updated."
            }
        }
    }
    catch {
        Write-Log "Error processing Local AD user: $($_.Exception.Message)" "ERROR"
    }

    # === AzureAD / Entra Section ===
    try {
        Write-Log "Connecting to Azure AD..."
        # Check if already connected or simply try to connect. 
        # Note: In a real scenario, might want better session handling.
        try {
            Get-AzureADTenantDetail -ErrorAction Stop | Out-Null
        } catch {
             Connect-AzureAD -ErrorAction Stop | Out-Null
        }

        $azureUser = Get-AzureADUser -Filter "UserPrincipalName eq '$CompromisedAccount'" -ErrorAction Stop
        
        if ($azureUser) {
             Write-Log "Found Azure AD User: $($azureUser.ObjectId)"

            # Revoke Azure AD sessions
            if ($PSCmdlet.ShouldProcess($azureUser.UserPrincipalName, "Revoke All Refresh Tokens")) {
                Revoke-AzureADUserAllRefreshToken -ObjectId $azureUser.ObjectId
                Write-Log "Azure AD sessions revoked."
            }

            # Disable Azure AD account
            if ($PSCmdlet.ShouldProcess($azureUser.UserPrincipalName, "Disable Azure AD Account")) {
                Set-AzureADUser -ObjectId $azureUser.ObjectId -AccountEnabled $false
                Write-Log "Azure AD account disabled."
            }
        }
        else {
            Write-Log "Azure AD user not found." "WARN"
        }
    }
    catch {
        Write-Log "Error processing Azure AD user: $($_.Exception.Message)" "ERROR"
    }
}

End {
    Write-Log "Script completed."
}
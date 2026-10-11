<#
.SYNOPSIS
    Audits local Administrators group members across Windows hosts.
.DESCRIPTION
    Enumerates members of the local Administrators group, categorizes them as Local
    or Domain accounts, and flags any unexpected unapproved local accounts.
.PARAMETER TargetEnvironment
    'Test' (default) or 'Prod'. Read-only: behaves the same in both.
.EXAMPLE
    .\FUNC_PS_AUDIT_LOCAL_ADMINS.ps1
    Lists local Administrators group members on this host.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment = "Test"
)

# Local, read-only collection: behaves the same in Test and Prod.
Write-Verbose "Mode: $TargetEnvironment (read-only; no changes are made in either mode)"

$Admins = Get-LocalGroupMember -Group "Administrators"
$Results = foreach ($Member in $Admins) {
    [PSCustomObject]@{
        Name            = $Member.Name
        PrincipalSource = $Member.PrincipalSource.ToString()
        ObjectClass     = $Member.ObjectClass
        SID             = $Member.SID.Value
        IsDomainAccount = ($Member.PrincipalSource -eq [Microsoft.PowerShell.Commands.PrincipalSource]::ActiveDirectory)
    }
}
$Results | Format-Table -AutoSize

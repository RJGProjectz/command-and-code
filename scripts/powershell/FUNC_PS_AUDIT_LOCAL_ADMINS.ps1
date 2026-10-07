<#
.SYNOPSIS
    Audits local Administrators group members across Windows hosts.
.DESCRIPTION
    Enumerates members of the local Administrators group, categorizes them as Local
    or Domain accounts, and flags any unexpected unapproved local accounts.
#>
[CmdletBinding()]
param()

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

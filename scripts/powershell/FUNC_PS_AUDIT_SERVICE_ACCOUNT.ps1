<#
.SYNOPSIS
    Read-only audit of Windows service accounts: who runs services and scheduled tasks, and how risky those identities are.

.DESCRIPTION
    Script Name: FUNC_PS_AUDIT_SERVICE_ACCOUNT
    Collects a snapshot of this host and (optionally) Active Directory, then runs the checks below on it and emits
    one finding per issue as objects and as NDJSON events (GOLDEN_STANDARDS 4.7):

      SA-SERVICE-INVENTORY    every service with its StartName and identity type (info)
      SA-TYPED-PASSWORD       service runs as a named user, so a password is stored in LSA secrets (use gMSA/virtual)
      SA-TASK-NAMED-USER      scheduled task runs as a named user (stored password when LogonType is Password)
      SA-SPN-USER             user account with a servicePrincipalName: Kerberoasting candidate
      SA-STALE-PASSWORD       service user whose password is older than -StalePasswordDays (or never set)
      SA-PRIVILEGED           adminCount=1, privileged AD group in tokenGroups, or local Administrators member
      SA-INTERACTIVE-ALLOWED  service user not denied local and RDP logon on this host (user rights)
      SA-GMSA-RETRIEVERS      gMSA whose password any domain computer/user can retrieve (else info inventory)
      SA-ACCOUNT-NOT-FOUND    a service/task identity that could not be resolved (NeedsReview)
      SA-COLLECTION           a collection step failed, e.g. not elevated or no RSAT (NeedsReview)

    The script never changes the host or the directory. -InputPath analyses a saved snapshot (no live queries), which
    is how the Pester fixtures run on Linux CI. -ExportSnapshotPath saves the collected snapshot for later analysis.
    SAFEGUARDS: read-only in both environments; -WhatIf skips every collection step (dry run); Prod asks for
    confirmation unless -WhatIf or -Force.

.PARAMETER TargetEnvironment
    'Test' or 'Prod'. Defaults to 'Test'. The audit is read-only in both; Prod asks for confirmation first.

.PARAMETER InputPath
    JSON snapshot to analyse instead of querying the live host (see tests/powershell/fixtures/serviceaccount/).

.PARAMETER ExportSnapshotPath
    Write the collected snapshot to this JSON file (for offline analysis or a before/after diff).

.PARAMETER StalePasswordDays
    Age in days after which a service user's password counts as stale. Default 365.

.PARAMETER SkipActiveDirectory
    Do not query AD (standalone or workgroup host). Local identities are still checked.

.PARAMETER LogPath
    Directory for the text log and NDJSON event log. Defaults to .\Logs beside the script.

.PARAMETER Force
    Skips the interactive Prod confirmation. Only for approved, unattended automation runners.

.EXAMPLE
    .\FUNC_PS_AUDIT_SERVICE_ACCOUNT.ps1 -WhatIf
    Dry run: shows which collection steps would run and reads nothing.

.EXAMPLE
    .\FUNC_PS_AUDIT_SERVICE_ACCOUNT.ps1 | Where-Object result -ne 'Info' | Format-Table check, severity, account, message
    Audits this host and AD (elevated PowerShell with RSAT) and lists the findings.

.EXAMPLE
    .\FUNC_PS_AUDIT_SERVICE_ACCOUNT.ps1 -InputPath .\app01-snapshot.json -StalePasswordDays 180
    Analyses a snapshot saved earlier with -ExportSnapshotPath.

.OUTPUTS
    PSCustomObject per finding (check, severity, result, target, account, message, details). The same findings and
    the run log are appended as NDJSON to <LogPath>\FUNC_PS_AUDIT_SERVICE_ACCOUNT.ndjson.

.NOTES
    Purpose: Inventory service identities and flag the ones attackers abuse (stored passwords, SPNs, admin rights).
    Security Context: Service accounts with typed passwords and SPNs are Kerberoasted (T1558.003) and reused as valid
        accounts (T1078.002); privileged or interactive-capable ones turn one cracked hash into domain access.
    Security Domain: Identity
    Author: RJGProjectz
    Version: 1.0
    Created: 2026-10-18T23:00:00Z
    Last Modified: 2026-10-18T23:00:00Z
    KB Article: [Service account audit](../../docs/tasks/assurance/service-account-audit.md)
    Source Repo: [Win32_Service](https://learn.microsoft.com/windows/win32/cimwin32prov/win32-service),
        [Get-ADServiceAccount](https://learn.microsoft.com/powershell/module/activedirectory/get-adserviceaccount),
        [Get-ADUser](https://learn.microsoft.com/powershell/module/activedirectory/get-aduser),
        [tokenGroups](https://learn.microsoft.com/windows/win32/adschema/a-tokengroups),
        [Protected accounts and groups](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
    API Standards:
        - Verdicts/Options: result = Finding | Info | NeedsReview; severity = info | low | medium | high
        - Mandatory Info: none (all parameters optional)
    Requires: elevated session for user rights (secedit) and local group data; RSAT ActiveDirectory module for AD checks.

    NAMING CONVENTION:
    - File: FUNC_PS_AUDIT_SERVICE_ACCOUNT.ps1
    - Functions: approved Verb-Noun. Read-only verbs only (Get, ConvertTo, Test, Write).

    CHANGE LOG:
    - 2026-10-18T23:00:00Z 1.0 RJGProjectz: first version (WP-68).
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
param (
    [Parameter(Mandatory = $false)]
    [ValidateSet('Test', 'Prod')]
    [string]$TargetEnvironment = 'Test',

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$InputPath,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$ExportSnapshotPath,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 36500)]
    [int]$StalePasswordDays = 365,

    [Parameter(Mandatory = $false)]
    [switch]$SkipActiveDirectory,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$LogPath = (Join-Path -Path $PSScriptRoot -ChildPath 'Logs'),

    [Parameter(Mandatory = $false)]
    [switch]$Force
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:ToolName    = 'FUNC_PS_AUDIT_SERVICE_ACCOUNT'
$script:ToolVersion = '1.0'
$script:ExecutionId = [guid]::NewGuid().ToString()
$script:NdjsonPath  = Join-Path -Path $LogPath -ChildPath "$($script:ToolName).ndjson"

# Well-known privileged groups (Microsoft "Appendix C: Protected Accounts and Groups in Active Directory").
# Builtin groups have fixed SIDs; domain groups are <domain SID>-<RID>.
$script:PrivilegedBuiltinSids = @{
    'S-1-5-32-544' = 'Administrators'; 'S-1-5-32-548' = 'Account Operators'; 'S-1-5-32-549' = 'Server Operators'
    'S-1-5-32-550' = 'Print Operators'; 'S-1-5-32-551' = 'Backup Operators'
}
$script:PrivilegedDomainRids = @{
    '512' = 'Domain Admins'; '516' = 'Domain Controllers'; '518' = 'Schema Admins'; '519' = 'Enterprise Admins'
    '521' = 'Read-only Domain Controllers'; '526' = 'Key Admins'; '527' = 'Enterprise Key Admins'
}
# gMSA retrievers that mean "every machine or user in the domain can read this password".
$script:BroadRetrieverPattern = '^CN=(Domain Computers|Domain Users|Authenticated Users|Everyone|Users),'

function Write-Log {
    <# Console (colored) + text log + NDJSON event. The ONLY permitted use of Write-Host. #>
    # Write-Log is the mandated helper name; PSSA's compatibility data flags it as a built-in on some platforms.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )

    $timestampUtc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    $logLine = "[$timestampUtc] [$Level] $Message"

    $consoleColor = switch ($Level) { 'ERROR' { 'Red' } 'WARN' { 'Yellow' } default { 'Cyan' } }
    Write-Host $logLine -ForegroundColor $consoleColor

    $logEvent = [ordered]@{
        timestamp    = $timestampUtc
        host         = [System.Net.Dns]::GetHostName()
        tool         = $script:ToolName
        version      = $script:ToolVersion
        execution_id = $script:ExecutionId
        environment  = $TargetEnvironment
        level        = $Level
        action       = 'log'
        message      = $Message
    }

    # -WhatIf:$false so logging still happens during a -WhatIf run (WhatIfPreference propagates to cmdlets).
    Add-Content -Path (Join-Path -Path $LogPath -ChildPath 'ScriptLog.log') -Value $logLine -WhatIf:$false
    Add-Content -Path $script:NdjsonPath -Value ($logEvent | ConvertTo-Json -Compress -Depth 5) -WhatIf:$false
}

function Get-PropertyValue {
    <# StrictMode-safe property read for JSON snapshots, where optional fields may be missing. #>
    param($InputObject, [string]$Name, $Default = $null)
    if ($null -eq $InputObject) { return $Default }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $Default
    }
    if ($InputObject.PSObject.Properties.Name -contains $Name) { return $InputObject.$Name }
    return $Default
}

function ConvertTo-UtcDate {
    <# Accepts an ISO 8601 string or a DateTime (PowerShell 7 ConvertFrom-Json parses dates itself). #>
    param($Value)
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [System.DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc) }
        return $Value.ToUniversalTime()
    }
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    return [datetime]::Parse([string]$Value, [System.Globalization.CultureInfo]::InvariantCulture, $styles)
}

function ConvertTo-IsoString {
    param($Value)
    $utcDate = ConvertTo-UtcDate -Value $Value
    if ($null -eq $utcDate) { return $null }
    return $utcDate.ToString('yyyy-MM-ddTHH:mm:ssZ')
}

function Get-IdentityType {
    <# Classifies a service StartName or task UserId. Only NamedUser identities carry a typed, stored password. #>
    param([string]$Identity)
    if ([string]::IsNullOrWhiteSpace($Identity)) { return 'None' }
    $normalized = $Identity.Trim().ToUpperInvariant()
    if ($normalized -in @('LOCALSYSTEM', 'SYSTEM', 'NT AUTHORITY\SYSTEM', 'S-1-5-18')) { return 'LocalSystem' }
    if ($normalized -in @('NT AUTHORITY\LOCALSERVICE', 'NT AUTHORITY\LOCAL SERVICE', 'LOCAL SERVICE', 'LOCALSERVICE', 'S-1-5-19')) { return 'LocalService' }
    if ($normalized -in @('NT AUTHORITY\NETWORKSERVICE', 'NT AUTHORITY\NETWORK SERVICE', 'NETWORK SERVICE', 'NETWORKSERVICE', 'S-1-5-20')) { return 'NetworkService' }
    if ($normalized.StartsWith('NT SERVICE\')) { return 'VirtualAccount' }
    if ($normalized.StartsWith('NT AUTHORITY\') -or $normalized.StartsWith('BUILTIN\') -or $normalized.StartsWith('S-1-5-')) { return 'BuiltIn' }
    if ($normalized.EndsWith('$')) { return 'ManagedServiceAccount' }
    return 'NamedUser'
}

function Get-AccountName {
    <# DOMAIN\sam, .\sam or sam@upn -> @{ Domain; Sam }. The UPN prefix is usually, not always, the sAMAccountName. #>
    param([string]$Identity)
    $trimmed = $Identity.Trim()
    $slashMatch = [regex]::Match($trimmed, '^(?<domain>[^\\]+)\\(?<sam>.+)$')
    if ($slashMatch.Success) { return @{ Domain = $slashMatch.Groups['domain'].Value; Sam = $slashMatch.Groups['sam'].Value } }
    $upnMatch = [regex]::Match($trimmed, '^(?<sam>[^@]+)@(?<domain>.+)$')
    if ($upnMatch.Success) { return @{ Domain = $upnMatch.Groups['domain'].Value; Sam = $upnMatch.Groups['sam'].Value } }
    return @{ Domain = ''; Sam = $trimmed }
}

function Test-IsLocalDomain {
    param([string]$Domain, [string]$ComputerName)
    return ($Domain -eq '' -or $Domain -eq '.' -or $Domain -ieq $ComputerName)
}

function ConvertTo-AuditFinding {
    param(
        [string]$Check, [string]$Severity, [string]$Result, [string]$Target, [string]$Account, [string]$Message,
        [System.Collections.IDictionary]$Details = @{}
    )
    [PSCustomObject]@{
        check    = $Check
        severity = $Severity
        result   = $Result
        target   = $Target
        account  = $Account
        message  = $Message
        details  = $Details
    }
}

function Get-ServiceAccountSnapshot {
    <# Live, read-only collection. Each step is wrapped in ShouldProcess so -WhatIf reads nothing. #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([switch]$SkipAd)

    $computerName = [System.Net.Dns]::GetHostName()
    $snapshot = [ordered]@{
        SchemaVersion       = '1.0'
        ComputerName        = $computerName
        CollectedUtc        = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        DomainSid           = $null
        DomainNetBiosName   = $null
        Services            = @()
        ScheduledTasks      = @()
        LocalAdministrators = @()
        UserRights          = $null
        Accounts            = @()
        CollectionErrors    = @()
    }
    $errors = [System.Collections.Generic.List[object]]::new()
    $accounts = [System.Collections.Generic.List[object]]::new()

    if ($PSCmdlet.ShouldProcess($computerName, 'Read services (Win32_Service)')) {
        try {
            $snapshot.Services = @(Get-CimInstance -ClassName Win32_Service | ForEach-Object {
                    [ordered]@{ Name = $_.Name; DisplayName = $_.DisplayName; StartName = $_.StartName; StartMode = $_.StartMode; State = $_.State }
                })
        }
        catch { $errors.Add([ordered]@{ Step = 'Services'; Message = $_.Exception.Message }) }
    }

    if ($PSCmdlet.ShouldProcess($computerName, 'Read scheduled task principals (Get-ScheduledTask)')) {
        try {
            $snapshot.ScheduledTasks = @(Get-ScheduledTask | ForEach-Object {
                    [ordered]@{
                        TaskPath = $_.TaskPath; TaskName = $_.TaskName; UserId = $_.Principal.UserId
                        LogonType = [string]$_.Principal.LogonType; RunLevel = [string]$_.Principal.RunLevel
                    }
                })
        }
        catch { $errors.Add([ordered]@{ Step = 'ScheduledTasks'; Message = $_.Exception.Message }) }
    }

    if ($PSCmdlet.ShouldProcess($computerName, 'Read local Administrators members')) {
        try {
            $snapshot.LocalAdministrators = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object {
                    [ordered]@{ Name = $_.Name; Sid = $_.SID.Value }
                })
        }
        catch { $errors.Add([ordered]@{ Step = 'LocalAdministrators'; Message = $_.Exception.Message }) }
    }

    if ($PSCmdlet.ShouldProcess($computerName, 'Export user rights (secedit /export /areas USER_RIGHTS)')) {
        # secedit writes the policy to a file; the temp file is ours and is deleted afterwards. Needs elevation.
        $rightsFile = [System.IO.Path]::GetTempFileName()
        try {
            $seceditRun = Start-Process -FilePath 'secedit.exe' -ArgumentList @('/export', '/cfg', "`"$rightsFile`"", '/areas', 'USER_RIGHTS', '/quiet') `
                -Wait -PassThru -NoNewWindow
            if ($seceditRun.ExitCode -ne 0) { throw "secedit exited with code $($seceditRun.ExitCode) (run elevated)." }
            $rights = [ordered]@{}
            foreach ($line in (Get-Content -LiteralPath $rightsFile -Encoding Unicode)) {
                $rightMatch = [regex]::Match($line, '^\s*(?<right>Se\w+)\s*=\s*(?<value>.*)$')
                if ($rightMatch.Success) {
                    $rights[$rightMatch.Groups['right'].Value] = @($rightMatch.Groups['value'].Value -split ',' |
                            ForEach-Object { $_.Trim() } | Where-Object { $_ })
                }
            }
            $snapshot.UserRights = $rights
        }
        catch { $errors.Add([ordered]@{ Step = 'UserRights'; Message = $_.Exception.Message }) }
        finally { Remove-Item -LiteralPath $rightsFile -Force -ErrorAction SilentlyContinue -WhatIf:$false }
    }

    # Named identities referenced by services and tasks: these are the accounts whose details we need.
    $referenced = @(@($snapshot.Services | ForEach-Object { $_.StartName }) + @($snapshot.ScheduledTasks | ForEach-Object { $_.UserId }) |
            Where-Object { (Get-IdentityType -Identity $_) -in @('NamedUser', 'ManagedServiceAccount') } | Sort-Object -Unique)

    $localNames = @($referenced | ForEach-Object { Get-AccountName -Identity $_ } |
            Where-Object { Test-IsLocalDomain -Domain $_.Domain -ComputerName $computerName } | ForEach-Object { $_.Sam } | Sort-Object -Unique)
    if ($localNames.Count -gt 0 -and $PSCmdlet.ShouldProcess($computerName, 'Read local user accounts used by services/tasks')) {
        foreach ($localName in $localNames) {
            try {
                $localUser = Get-LocalUser -Name $localName
                $accounts.Add([ordered]@{
                        SamAccountName = $localUser.Name; Source = 'Local'; ObjectClass = 'user'; Sid = $localUser.SID.Value
                        Enabled = [bool]$localUser.Enabled; PasswordLastSet = (ConvertTo-IsoString -Value $localUser.PasswordLastSet)
                        PasswordNeverExpires = ($null -eq $localUser.PasswordExpires); AdminCount = 0
                        ServicePrincipalNames = @(); GroupSids = @(); PrincipalsAllowedToRetrieveManagedPassword = @()
                    })
            }
            catch { $errors.Add([ordered]@{ Step = "LocalUser:$localName"; Message = $_.Exception.Message }) }
        }
    }

    if (-not $SkipAd -and $PSCmdlet.ShouldProcess('Active Directory', 'Read gMSA/MSA, SPN users and service identities (tokenGroups)')) {
        try {
            if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) { throw 'ActiveDirectory module (RSAT) not installed; use -SkipActiveDirectory on standalone hosts.' }
            Import-Module ActiveDirectory -Verbose:$false
            $domain = Get-ADDomain
            $snapshot.DomainSid = $domain.DomainSID.Value
            $snapshot.DomainNetBiosName = $domain.NetBIOSName
            $userProperties = @('servicePrincipalName', 'PasswordLastSet', 'PasswordNeverExpires', 'adminCount', 'Enabled', 'SID')

            $adObjects = [System.Collections.Generic.List[object]]::new()
            foreach ($managed in @(Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword, ServicePrincipalNames, PasswordLastSet, adminCount, Enabled, objectClass)) {
                $adObjects.Add(@{ Object = $managed; Managed = $true })
            }
            foreach ($spnUser in @(Get-ADUser -Filter 'servicePrincipalName -like "*"' -Properties $userProperties)) {
                $adObjects.Add(@{ Object = $spnUser; Managed = $false })
            }
            $known = @($adObjects | ForEach-Object { $_.Object.SamAccountName.ToLowerInvariant() })
            foreach ($identity in $referenced) {
                $name = Get-AccountName -Identity $identity
                if ((Test-IsLocalDomain -Domain $name.Domain -ComputerName $computerName) -or $known -contains $name.Sam.ToLowerInvariant()) { continue }
                if ($name.Sam.EndsWith('$')) { continue }   # gMSA/MSA already listed by Get-ADServiceAccount
                try {
                    $adObjects.Add(@{ Object = (Get-ADUser -Identity $name.Sam -Properties $userProperties); Managed = $false })
                    $known += $name.Sam.ToLowerInvariant()
                }
                catch { Write-Verbose "AD user not found: $identity" }   # reported later as SA-ACCOUNT-NOT-FOUND
            }

            foreach ($entry in $adObjects) {
                $adObject = $entry.Object
                # tokenGroups is constructed (base-scope read per object) - only read for this small set of accounts.
                $tokenGroups = @((Get-ADObject -Identity $adObject.DistinguishedName -Properties tokenGroups).tokenGroups | ForEach-Object { $_.Value })
                $adminCount = Get-PropertyValue -InputObject $adObject -Name 'adminCount' -Default 0
                $accounts.Add([ordered]@{
                        SamAccountName = $adObject.SamAccountName; Source = 'AD'; ObjectClass = [string]$adObject.ObjectClass
                        Sid = $adObject.SID.Value; Enabled = [bool]$adObject.Enabled
                        PasswordLastSet = (ConvertTo-IsoString -Value $adObject.PasswordLastSet)
                        PasswordNeverExpires = [bool](Get-PropertyValue -InputObject $adObject -Name 'PasswordNeverExpires' -Default $false)
                        AdminCount = [int]$(if ($null -eq $adminCount) { 0 } else { $adminCount })
                        ServicePrincipalNames = @(if ($entry.Managed) { $adObject.ServicePrincipalNames } else { $adObject.servicePrincipalName })
                        GroupSids = $tokenGroups
                        PrincipalsAllowedToRetrieveManagedPassword = @(if ($entry.Managed) { $adObject.PrincipalsAllowedToRetrieveManagedPassword } else { @() })
                    })
            }
        }
        catch { $errors.Add([ordered]@{ Step = 'ActiveDirectory'; Message = $_.Exception.Message }) }
    }

    $snapshot.Accounts = @($accounts)
    $snapshot.CollectionErrors = @($errors)
    return [PSCustomObject]$snapshot
}

function Test-PrincipalListed {
    <# True when a user-rights entry (*SID or name) matches the account SID, one of its group SIDs, or its name. #>
    param([string[]]$Entries, $Account, [string]$Domain)
    $candidates = @(@([string](Get-PropertyValue -InputObject $Account -Name 'Sid' -Default '')) + @(Get-PropertyValue -InputObject $Account -Name 'GroupSids' -Default @()))
    $sam = [string](Get-PropertyValue -InputObject $Account -Name 'SamAccountName' -Default '')
    $candidates += @($sam, "$Domain\$sam")
    foreach ($entry in @($Entries)) {
        $value = ([string]$entry).TrimStart('*')
        foreach ($candidate in $candidates) {
            if ($candidate -and $value -ieq $candidate) { return $true }
        }
    }
    return $false
}

function Get-ServiceAccountFinding {
    <# Pure analysis of a snapshot: no I/O, so the fixtures can test every check. #>
    param([Parameter(Mandatory = $true)]$Snapshot, [int]$StaleDays = 365)

    $computerName = [string](Get-PropertyValue -InputObject $Snapshot -Name 'ComputerName' -Default '')
    $collectedUtc = ConvertTo-UtcDate -Value (Get-PropertyValue -InputObject $Snapshot -Name 'CollectedUtc')
    if ($null -eq $collectedUtc) { $collectedUtc = [DateTime]::UtcNow }
    $domainSid = [string](Get-PropertyValue -InputObject $Snapshot -Name 'DomainSid' -Default '')
    $domainName = [string](Get-PropertyValue -InputObject $Snapshot -Name 'DomainNetBiosName' -Default '')
    $services = @(Get-PropertyValue -InputObject $Snapshot -Name 'Services' -Default @())
    $tasks = @(Get-PropertyValue -InputObject $Snapshot -Name 'ScheduledTasks' -Default @())
    $localAdmins = @(Get-PropertyValue -InputObject $Snapshot -Name 'LocalAdministrators' -Default @())
    $userRights = Get-PropertyValue -InputObject $Snapshot -Name 'UserRights'
    $accounts = @(Get-PropertyValue -InputObject $Snapshot -Name 'Accounts' -Default @())

    foreach ($collectionError in @(Get-PropertyValue -InputObject $Snapshot -Name 'CollectionErrors' -Default @())) {
        $step = [string](Get-PropertyValue -InputObject $collectionError -Name 'Step' -Default 'unknown')
        ConvertTo-AuditFinding -Check 'SA-COLLECTION' -Severity 'medium' -Result 'NeedsReview' -Target $step -Account '' `
            -Message "Collection step '$step' failed; checks that need it are incomplete: $(Get-PropertyValue -InputObject $collectionError -Name 'Message' -Default '')"
    }

    $accountBySam = @{}
    foreach ($account in $accounts) {
        $accountBySam[([string]$account.SamAccountName).ToLowerInvariant()] = $account
    }

    # Accounts to analyse: every named identity used on this host, plus every SPN user and managed account in AD.
    $analyse = [ordered]@{}
    $usage = @{}

    foreach ($service in $services) {
        $startName = [string](Get-PropertyValue -InputObject $service -Name 'StartName' -Default '')
        $identityType = Get-IdentityType -Identity $startName
        ConvertTo-AuditFinding -Check 'SA-SERVICE-INVENTORY' -Severity 'info' -Result 'Info' -Target $service.Name -Account $startName `
            -Message "Service '$($service.Name)' runs as '$startName' ($identityType)." `
            -Details ([ordered]@{ identity_type = $identityType; start_mode = (Get-PropertyValue -InputObject $service -Name 'StartMode'); state = (Get-PropertyValue -InputObject $service -Name 'State') })

        if ($identityType -eq 'NamedUser') {
            ConvertTo-AuditFinding -Check 'SA-TYPED-PASSWORD' -Severity 'medium' -Result 'Finding' -Target $service.Name -Account $startName `
                -Message "Service '$($service.Name)' runs as named account '$startName'; its password is stored in LSA secrets. Move it to a gMSA or virtual account." `
                -Details ([ordered]@{ identity_type = $identityType })
        }
        if ($identityType -in @('NamedUser', 'ManagedServiceAccount')) {
            $key = (Get-AccountName -Identity $startName).Sam.ToLowerInvariant()
            $analyse[$key] = $startName
            if (-not $usage.ContainsKey($key)) { $usage[$key] = [System.Collections.Generic.List[string]]::new() }
            $usage[$key].Add("service:$($service.Name)")
        }
    }

    foreach ($task in $tasks) {
        $userId = [string](Get-PropertyValue -InputObject $task -Name 'UserId' -Default '')
        $logonType = [string](Get-PropertyValue -InputObject $task -Name 'LogonType' -Default '')
        $taskTarget = "$(Get-PropertyValue -InputObject $task -Name 'TaskPath' -Default '\')$(Get-PropertyValue -InputObject $task -Name 'TaskName' -Default '')"
        if ($logonType -eq 'Group') { continue }   # runs as whoever is logged on, no stored identity
        $identityType = Get-IdentityType -Identity $userId
        if ($identityType -ne 'NamedUser') {
            if ($identityType -eq 'ManagedServiceAccount') {
                $key = (Get-AccountName -Identity $userId).Sam.ToLowerInvariant()
                $analyse[$key] = $userId
            }
            continue
        }
        # Password / InteractiveOrPassword store the password with the task; S4U and Interactive do not.
        $storesPassword = $logonType -in @('Password', 'InteractiveOrPassword')
        $severity = if ($storesPassword) { 'medium' } elseif ($logonType -eq 'S4U') { 'low' } else { 'info' }
        $taskResult = if ($severity -eq 'info') { 'Info' } else { 'Finding' }
        ConvertTo-AuditFinding -Check 'SA-TASK-NAMED-USER' -Severity $severity -Result $taskResult -Target $taskTarget -Account $userId `
            -Message "Scheduled task '$taskTarget' runs as named account '$userId' (LogonType $logonType)." `
            -Details ([ordered]@{ logon_type = $logonType; stores_password = $storesPassword; run_level = (Get-PropertyValue -InputObject $task -Name 'RunLevel') })
        $key = (Get-AccountName -Identity $userId).Sam.ToLowerInvariant()
        $analyse[$key] = $userId
        if (-not $usage.ContainsKey($key)) { $usage[$key] = [System.Collections.Generic.List[string]]::new() }
        $usage[$key].Add("task:$taskTarget")
    }

    foreach ($account in $accounts) {
        $key = ([string]$account.SamAccountName).ToLowerInvariant()
        $spns = @(Get-PropertyValue -InputObject $account -Name 'ServicePrincipalNames' -Default @())
        $isManaged = ([string](Get-PropertyValue -InputObject $account -Name 'ObjectClass' -Default 'user')) -like 'msDS-*'
        if ($isManaged -or ($spns.Count -gt 0 -and $key -ne 'krbtgt')) { $analyse[$key] = [string]$account.SamAccountName }
    }

    $privilegedDomainSids = @{}
    if ($domainSid) {
        foreach ($rid in $script:PrivilegedDomainRids.Keys) { $privilegedDomainSids["$domainSid-$rid"] = $script:PrivilegedDomainRids[$rid] }
    }

    foreach ($key in $analyse.Keys) {
        $identity = $analyse[$key]
        $usedBy = @(if ($usage.ContainsKey($key)) { $usage[$key] })
        if (-not $accountBySam.ContainsKey($key)) {
            ConvertTo-AuditFinding -Check 'SA-ACCOUNT-NOT-FOUND' -Severity 'medium' -Result 'NeedsReview' -Target ($usedBy -join ', ') -Account $identity `
                -Message "Identity '$identity' is used on this host but was not found in AD or the local accounts: deleted account, other domain, or collection gap." `
                -Details ([ordered]@{ used_by = $usedBy })
            continue
        }

        $account = $accountBySam[$key]
        $sam = [string]$account.SamAccountName
        $objectClass = [string](Get-PropertyValue -InputObject $account -Name 'ObjectClass' -Default 'user')
        $isManaged = $objectClass -like 'msDS-*'
        $source = [string](Get-PropertyValue -InputObject $account -Name 'Source' -Default 'AD')
        $spns = @(Get-PropertyValue -InputObject $account -Name 'ServicePrincipalNames' -Default @())
        $groupSids = @(Get-PropertyValue -InputObject $account -Name 'GroupSids' -Default @())
        $accountSid = [string](Get-PropertyValue -InputObject $account -Name 'Sid' -Default '')
        $adminCount = [int](Get-PropertyValue -InputObject $account -Name 'AdminCount' -Default 0)
        $accountDomain = if ($source -eq 'Local') { $computerName } else { $domainName }

        if ($isManaged) {
            $retrievers = @(Get-PropertyValue -InputObject $account -Name 'PrincipalsAllowedToRetrieveManagedPassword' -Default @())
            $broad = @($retrievers | Where-Object { [string]$_ -match $script:BroadRetrieverPattern })
            if ($broad.Count -gt 0) {
                ConvertTo-AuditFinding -Check 'SA-GMSA-RETRIEVERS' -Severity 'high' -Result 'Finding' -Target $sam -Account $sam `
                    -Message "Managed account '$sam' lets a domain-wide group retrieve its password: $($broad -join '; '). Limit it to the hosts that run the service." `
                    -Details ([ordered]@{ object_class = $objectClass; retrievers = $retrievers; used_by = $usedBy })
            }
            else {
                ConvertTo-AuditFinding -Check 'SA-GMSA-RETRIEVERS' -Severity 'info' -Result 'Info' -Target $sam -Account $sam `
                    -Message "Managed account '$sam' ($objectClass); password retrievers: $($retrievers -join '; ')." `
                    -Details ([ordered]@{ object_class = $objectClass; retrievers = $retrievers; used_by = $usedBy })
            }
        }

        # Privilege: adminCount=1 (protected by SDProp now or in the past), privileged group in tokenGroups, or local admin.
        $privilegedGroups = @()
        foreach ($groupSid in $groupSids) {
            if ($script:PrivilegedBuiltinSids.ContainsKey([string]$groupSid)) { $privilegedGroups += $script:PrivilegedBuiltinSids[[string]$groupSid] }
            elseif ($privilegedDomainSids.ContainsKey([string]$groupSid)) { $privilegedGroups += $privilegedDomainSids[[string]$groupSid] }
        }
        $isLocalAdmin = @($localAdmins | Where-Object {
                ($accountSid -and [string](Get-PropertyValue -InputObject $_ -Name 'Sid' -Default '') -ieq $accountSid) -or
                ((Get-AccountName -Identity ([string](Get-PropertyValue -InputObject $_ -Name 'Name' -Default ''))).Sam -ieq $sam)
            }).Count -gt 0
        if ($isLocalAdmin) { $privilegedGroups += "local Administrators on $computerName" }
        $isPrivileged = ($adminCount -eq 1) -or ($privilegedGroups.Count -gt 0)
        if ($isPrivileged) {
            ConvertTo-AuditFinding -Check 'SA-PRIVILEGED' -Severity 'high' -Result 'Finding' -Target $sam -Account $sam `
                -Message "Service account '$sam' is privileged (adminCount=$adminCount; groups: $(@($privilegedGroups | Sort-Object -Unique) -join ', ')). Give it only the rights the service needs." `
                -Details ([ordered]@{ admin_count = $adminCount; privileged_groups = @($privilegedGroups | Sort-Object -Unique); used_by = $usedBy })
        }

        if ($isManaged) { continue }   # gMSA/MSA passwords are random and rotated by AD; the user checks below do not apply

        $passwordLastSet = ConvertTo-UtcDate -Value (Get-PropertyValue -InputObject $account -Name 'PasswordLastSet')
        $passwordAgeDays = if ($null -eq $passwordLastSet) { $null } else { [int][math]::Floor(($collectedUtc - $passwordLastSet).TotalDays) }
        $neverExpires = [bool](Get-PropertyValue -InputObject $account -Name 'PasswordNeverExpires' -Default $false)

        if ($spns.Count -gt 0 -and $key -ne 'krbtgt') {
            $spnSeverity = if ($isPrivileged -or ($null -ne $passwordAgeDays -and $passwordAgeDays -gt $StaleDays)) { 'high' } else { 'medium' }
            ConvertTo-AuditFinding -Check 'SA-SPN-USER' -Severity $spnSeverity -Result 'Finding' -Target $sam -Account $sam `
                -Message "User account '$sam' has $($spns.Count) SPN(s): any domain user can request a ticket and crack it offline (Kerberoasting). Move the SPN to a gMSA or use a 25+ character random password." `
                -Details ([ordered]@{ spns = $spns; password_age_days = $passwordAgeDays; privileged = $isPrivileged; used_by = $usedBy })
        }

        if ($null -eq $passwordAgeDays -or $passwordAgeDays -gt $StaleDays) {
            $ageText = if ($null -eq $passwordAgeDays) { 'never set' } else { "$passwordAgeDays days old" }
            ConvertTo-AuditFinding -Check 'SA-STALE-PASSWORD' -Severity 'medium' -Result 'Finding' -Target $sam -Account $sam `
                -Message "Password of service account '$sam' is $ageText (threshold $StaleDays days)." `
                -Details ([ordered]@{ password_last_set = (ConvertTo-IsoString -Value $passwordLastSet); password_age_days = $passwordAgeDays; password_never_expires = $neverExpires; used_by = $usedBy })
        }

        # Logon rights are per host: only judge accounts that this host actually uses.
        if ($usedBy.Count -eq 0) { continue }
        if ($null -eq $userRights) {
            ConvertTo-AuditFinding -Check 'SA-INTERACTIVE-ALLOWED' -Severity 'medium' -Result 'NeedsReview' -Target $computerName -Account $sam `
                -Message "User rights were not collected (run elevated); cannot tell whether '$sam' may log on interactively." `
                -Details ([ordered]@{ used_by = $usedBy })
        }
        else {
            $denyLocal = Test-PrincipalListed -Entries @(Get-PropertyValue -InputObject $userRights -Name 'SeDenyInteractiveLogonRight' -Default @()) -Account $account -Domain $accountDomain
            $denyRemote = Test-PrincipalListed -Entries @(Get-PropertyValue -InputObject $userRights -Name 'SeDenyRemoteInteractiveLogonRight' -Default @()) -Account $account -Domain $accountDomain
            if (-not ($denyLocal -and $denyRemote)) {
                ConvertTo-AuditFinding -Check 'SA-INTERACTIVE-ALLOWED' -Severity 'medium' -Result 'Finding' -Target $computerName -Account $sam `
                    -Message "Service account '$sam' is not denied interactive logon on $computerName (deny local: $denyLocal, deny RDP: $denyRemote). Add it to 'Deny log on locally' and 'Deny log on through Remote Desktop Services'." `
                    -Details ([ordered]@{ deny_interactive = $denyLocal; deny_remote_interactive = $denyRemote; used_by = $usedBy })
            }
        }
    }
}

function ConvertTo-FindingEvent {
    <# GOLDEN 4.7 NDJSON line: mandatory fields + recommended level/environment/action/target/result. #>
    param([Parameter(Mandatory = $true)]$Finding, [string]$AuditedHost)
    $level = if ($Finding.result -eq 'Info') { 'INFO' } else { 'WARN' }
    $findingEvent = [ordered]@{
        timestamp    = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        host         = $AuditedHost
        tool         = $script:ToolName
        version      = $script:ToolVersion
        execution_id = $script:ExecutionId
        environment  = $TargetEnvironment
        level        = $level
        action       = 'audit'
        check        = $Finding.check
        severity     = $Finding.severity
        result       = $Finding.result
        target       = $Finding.target
        account      = $Finding.account
        message      = $Finding.message
        details      = $Finding.details
    }
    return ($findingEvent | ConvertTo-Json -Compress -Depth 10)
}

if (-not (Test-Path -Path $LogPath)) {
    New-Item -ItemType Directory -Path $LogPath -Force -WhatIf:$false | Out-Null
}

Write-Log -Message "Starting $($script:ToolName) in [$TargetEnvironment] mode (read-only)."

# Production gate: explicit confirmation unless -WhatIf (simulation) or -Force (approved runner).
if ($TargetEnvironment -eq 'Prod' -and -not $WhatIfPreference -and -not $Force) {
    if (-not $PSCmdlet.ShouldContinue('Query the PRODUCTION host and directory (read-only)?', 'Production confirmation')) {
        Write-Log -Message 'Operation cancelled by user.' -Level 'WARN'
        exit 1
    }
}

try {
    if ($InputPath) {
        Write-Log -Message "Analysing snapshot $InputPath (no live queries)."
        $snapshot = Get-Content -LiteralPath $InputPath -Raw | ConvertFrom-Json
    }
    else {
        $snapshot = Get-ServiceAccountSnapshot -SkipAd:$SkipActiveDirectory
        if ($WhatIfPreference) {
            Write-Log -Message 'WhatIf: no collection step ran, nothing to analyse.'
            return
        }
    }

    if ($ExportSnapshotPath) {
        $snapshot | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $ExportSnapshotPath -Encoding UTF8 -WhatIf:$false
        Write-Log -Message "Snapshot saved to $ExportSnapshotPath."
    }

    $auditedHost = [string](Get-PropertyValue -InputObject $snapshot -Name 'ComputerName' -Default ([System.Net.Dns]::GetHostName()))
    $findings = @(Get-ServiceAccountFinding -Snapshot $snapshot -StaleDays $StalePasswordDays)
    foreach ($finding in $findings) {
        Add-Content -Path $script:NdjsonPath -Value (ConvertTo-FindingEvent -Finding $finding -AuditedHost $auditedHost) -WhatIf:$false
        $finding
    }

    $issueCount = @($findings | Where-Object { $_.result -ne 'Info' }).Count
    Write-Log -Message "Audit complete: $($findings.Count) events, $issueCount findings or review items. NDJSON: $($script:NdjsonPath)" `
        -Level $(if ($issueCount -gt 0) { 'WARN' } else { 'INFO' })
}
catch {
    Write-Log -Message "Error: $($_.Exception.Message)" -Level 'ERROR'
    throw
}
finally {
    Write-Log -Message 'Script completed.'
}

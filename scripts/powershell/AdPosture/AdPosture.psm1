<#
.SYNOPSIS
    Read-only Active Directory environment posture engine. Evaluates one domain-wide posture
    catalog where every check carries a three-framework crosswalk (DISA STIG, CIS Windows Server
    Domain Controller profile, and documented best practice) and grades the observed value against
    each framework that applies to it.

.DESCRIPTION
    Module Name   : AdPosture.psm1
    Purpose       : Collect domain facts once (Get-AdPostureContext), then evaluate each catalog
                    check against its STIG / CIS / best-practice expectation (Invoke-AdPostureCheck).
                    Expectation evaluation is delegated to the shared CIS engine's Test-CisExpectation
                    so the operator model (eq, ne, range, in, regex, set, any, all, ...) is identical.
    Security      : Security Domain: Compliance / Hardening. Read-only: the collector only reads AD
                    through the ActiveDirectory module. Nothing in the directory is changed.
    Author        : RJGProjectz
    Version       : 1.0.0
    Created       : 2026-10-26T00:00:00Z
    Last Modified : 2026-10-26T00:00:00Z
    KB Article    : docs/tasks/assurance/ad-environment-posture-audit.md
    API Standards : Result Status values Pass | Fail | NotApplicable | Error. Catalog schema
                    cc.adposture.catalog/1. STIG rule identifiers are representative; confirm them
                    against the STIG version your organisation is assessed against.
#>

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# Reuse the shared CIS engine's pure expectation evaluator and formatters.
Import-Module (Join-Path $PSScriptRoot '..\CisAudit\CisAudit.psm1') -Force

function Import-AdPostureCatalog {
    <#
    .SYNOPSIS
        Loads an AD posture catalog JSON file and checks its schema tag.
    .EXAMPLE
        Import-AdPostureCatalog -Path ./ad-posture-v1.json
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $catalog = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($catalog.schema -ne 'cc.adposture.catalog/1') {
        throw "Unsupported AD posture catalog schema '$($catalog.schema)' in $Path"
    }
    return $catalog
}

function Format-AdPostureExpect {
    <#
    .SYNOPSIS
        Human-readable form of a framework expectation for reports (delegates to the CIS formatter).
    .EXAMPLE
        Format-AdPostureExpect -Expect ([PSCustomObject]@{ op = 'range'; min = 14; max = $null })
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowNull()]$Expect)
    if ($null -eq $Expect) { return 'n/a' }
    return (Format-CisExpectation -Expect $Expect)
}

function Get-AdPostureFrameworkList {
    <#
    .SYNOPSIS
        Ordered list of the frameworks present on a check: stig, cis, bestPractice (best practice is
        always last so it is the minimum bar). A framework whose expect is absent/null is skipped.
    .EXAMPLE
        Get-AdPostureFrameworkList -Check $check
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Check)

    $order = @('stig', 'cis', 'bestPractice')
    $present = @()
    foreach ($name in $order) {
        if ($Check.frameworks.PSObject.Properties.Name -notcontains $name) { continue }
        $fw = $Check.frameworks.$name
        if ($null -eq $fw) { continue }
        if ($fw.PSObject.Properties.Name -notcontains 'expect' -or $null -eq $fw.expect) { continue }
        $present += $name
    }
    return , @($present)
}

function Invoke-AdPostureCheck {
    <#
    .SYNOPSIS
        Evaluates one AD posture check against a collected context and returns the result row.
    .DESCRIPTION
        Reads the observed value from $Context.Facts by the check's 'collector' key. If the fact is
        missing from the context (could not be collected), the check reports Error. Otherwise each
        framework expectation (stig / cis / bestPractice) is evaluated with Test-CisExpectation. The
        overall Status is decided by -Bar: 'BestPractice' (default) passes when the best-practice
        expectation passes (the minimum bar); 'Strictest' passes only when every present framework
        passes. Per-framework verdicts are always recorded in the Stig / Cis / BestPractice fields.
    .EXAMPLE
        Invoke-AdPostureCheck -Check $catalog.checks[0] -Context $context -Bar BestPractice
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Check,
        [Parameter(Mandatory = $true)]$Context,
        [ValidateSet('BestPractice', 'Strictest')][string]$Bar = 'BestPractice'
    )

    $collector = [string]$Check.collector
    $facts = $Context.Facts
    $hasFact = $false
    $actual = $null
    if ($facts -is [System.Collections.IDictionary]) { $hasFact = $facts.Contains($collector) }
    else { $hasFact = @($facts.PSObject.Properties.Name) -contains $collector }
    if ($hasFact) { $actual = $facts[$collector] }

    $frameworks = Get-AdPostureFrameworkList -Check $Check
    $perFramework = [ordered]@{}
    $expectedParts = @()

    # Collector error: the value could not be read. The whole check is Error; frameworks are 'Error'.
    $collectorError = $false
    if (-not $hasFact) { $collectorError = $true }
    elseif ($Context.PSObject.Properties.Name -contains 'Errors' -and $null -ne $Context.Errors -and
            $Context.Errors -is [System.Collections.IDictionary] -and $Context.Errors.Contains($collector)) {
        $collectorError = $true
    }

    foreach ($name in $frameworks) {
        $fw = $Check.frameworks.$name
        $expectText = Format-AdPostureExpect -Expect $fw.expect
        $label = switch ($name) { 'stig' { 'STIG' } 'cis' { 'CIS' } 'bestPractice' { 'BP' } default { $name } }
        $idText = if ($fw.PSObject.Properties.Name -contains 'id' -and $fw.id) { " [$($fw.id)]" } else { '' }
        $expectedParts += "$label$($idText): $expectText"
        if ($collectorError) {
            $perFramework[$name] = 'Error'
            continue
        }
        $ok = Test-CisExpectation -Expect $fw.expect -Actual $actual
        $perFramework[$name] = if ($ok) { 'Pass' } else { 'Fail' }
    }

    # Mark frameworks declared n/a on this check (e.g. CIS has no AD-specific item) explicitly.
    foreach ($name in @('stig', 'cis', 'bestPractice')) {
        if ($perFramework.Contains($name)) { continue }
        $perFramework[$name] = 'n/a'
    }

    if ($collectorError) {
        $status = 'Error'
    }
    elseif ($frameworks.Count -eq 0) {
        $status = 'NotApplicable'
    }
    elseif ($Bar -eq 'Strictest') {
        $failed = @($frameworks | Where-Object { $perFramework[$_] -eq 'Fail' })
        $status = if ($failed.Count -eq 0) { 'Pass' } else { 'Fail' }
    }
    else {
        # BestPractice bar: grade on best practice if present, else the strictest present framework.
        $barName = if ($frameworks -contains 'bestPractice') { 'bestPractice' } else { $frameworks[0] }
        $status = if ($perFramework[$barName] -eq 'Pass') { 'Pass' } else { 'Fail' }
    }

    $detailParts = @()
    if ($collectorError) {
        $reason = if ($Context.PSObject.Properties.Name -contains 'Errors' -and $null -ne $Context.Errors -and
            $Context.Errors -is [System.Collections.IDictionary] -and $Context.Errors.Contains($collector)) {
            [string]$Context.Errors[$collector]
        }
        else { "Fact '$collector' was not collected" }
        $detailParts += $reason
    }
    else {
        foreach ($name in $frameworks) { $detailParts += "$name=$($perFramework[$name])" }
    }

    return [PSCustomObject]@{
        Id           = $Check.id
        Title        = $Check.title
        Category     = [string]$Check.category
        Collector    = $collector
        Status       = $status
        Bar          = $Bar
        Expected     = ($expectedParts -join ' ; ')
        Actual       = (Format-CisValue -Value $actual)
        Stig         = $perFramework['stig']
        Cis          = $perFramework['cis']
        BestPractice = $perFramework['bestPractice']
        Source       = "AD: $collector"
        Detail       = ($detailParts -join ' ; ')
    }
}

function Get-AdPostureContext {
    <#
    .SYNOPSIS
        Collects domain-wide facts once (read-only) into a context the checks read. Requires the
        RSAT ActiveDirectory module and a reachable domain. Each fact is collected independently;
        a fact that cannot be read is recorded in .Errors and its check reports Error.
    .DESCRIPTION
        -StaleDays sets the inactivity window for stale-account facts (default 90). -Server and
        -Credential are passed through to the ActiveDirectory cmdlets when supplied.
    .EXAMPLE
        $ctx = Get-AdPostureContext
    .EXAMPLE
        $ctx = Get-AdPostureContext -Server dc01.contoso.com -StaleDays 60
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][int]$StaleDays = 90,
        [Parameter(Mandatory = $false)][string]$Server,
        [Parameter(Mandatory = $false)][System.Management.Automation.PSCredential]$Credential
    )

    Import-Module ActiveDirectory -ErrorAction Stop

    $facts = @{}
    $errors = @{}
    $meta = @{}
    $common = @{}
    if ($Server) { $common['Server'] = $Server }
    if ($Credential) { $common['Credential'] = $Credential }

    # Helper: run a collector scriptblock, storing its value under each named fact, or the error.
    $collect = {
        param([string[]]$Names, [scriptblock]$Script)
        try {
            $value = & $Script
            if ($Names.Count -eq 1) { $facts[$Names[0]] = $value }
            elseif ($value -is [System.Collections.IDictionary]) { foreach ($n in $Names) { $facts[$n] = $value[$n] } }
        }
        catch { foreach ($n in $Names) { $errors[$n] = $_.Exception.Message } }
    }

    $domain = Get-ADDomain @common
    $meta['Domain'] = [string]$domain.DNSRoot
    $meta['Forest'] = [string]$domain.Forest
    $domainDn = [string]$domain.DistinguishedName
    $facts['Domain.FunctionalLevelName'] = [string]$domain.DomainMode
    $facts['Domain.FunctionalLevel'] = [int][Enum]::Parse([Microsoft.ActiveDirectory.Management.ADDomainMode], [string]$domain.DomainMode)

    & $collect @('PasswordPolicy.MinPasswordLength', 'PasswordPolicy.PasswordHistoryCount',
        'PasswordPolicy.MaxPasswordAgeDays', 'PasswordPolicy.MinPasswordAgeDays',
        'PasswordPolicy.ComplexityEnabled', 'PasswordPolicy.ReversibleEncryptionEnabled',
        'Lockout.Threshold', 'Lockout.DurationMinutes', 'Lockout.ResetCounterMinutes') {
        $p = Get-ADDefaultDomainPasswordPolicy @common
        @{
            'PasswordPolicy.MinPasswordLength'             = [int]$p.MinPasswordLength
            'PasswordPolicy.PasswordHistoryCount'          = [int]$p.PasswordHistoryCount
            'PasswordPolicy.MaxPasswordAgeDays'            = [int]$p.MaxPasswordAge.TotalDays
            'PasswordPolicy.MinPasswordAgeDays'            = [int]$p.MinPasswordAge.TotalDays
            'PasswordPolicy.ComplexityEnabled'             = [bool]$p.ComplexityEnabled
            'PasswordPolicy.ReversibleEncryptionEnabled'   = [bool]$p.ReversibleEncryptionEnabled
            'Lockout.Threshold'                            = [int]$p.LockoutThreshold
            'Lockout.DurationMinutes'                      = [int]$p.LockoutDuration.TotalMinutes
            'Lockout.ResetCounterMinutes'                  = [int]$p.LockoutObservationWindow.TotalMinutes
        }
    }

    & $collect @('Krbtgt.PasswordAgeDays') {
        $k = Get-ADUser -Identity 'krbtgt' -Properties PasswordLastSet @common
        [int]((Get-Date) - $k.PasswordLastSet).TotalDays
    }

    # Privileged-group membership counts (recursive, so nested members are included).
    & $collect @('Group.SchemaAdmins.Count') { @(Get-ADGroupMember -Identity 'Schema Admins' -Recursive @common).Count }
    & $collect @('Group.EnterpriseAdmins.Count') { @(Get-ADGroupMember -Identity 'Enterprise Admins' -Recursive @common).Count }
    & $collect @('Group.DomainAdmins.Count') { @(Get-ADGroupMember -Identity 'Domain Admins' -Recursive @common).Count }

    & $collect @('MachineAccountQuota') {
        $o = Get-ADObject -Identity $domainDn -Properties 'ms-DS-MachineAccountQuota' @common
        [int]$o.'ms-DS-MachineAccountQuota'
    }

    & $collect @('RecycleBin.Enabled') {
        $forest = Get-ADForest @common
        [bool](@($forest.EnabledFeatures | Where-Object { $_ -match 'Recycle Bin' }).Count -gt 0)
    }

    & $collect @('Delegation.UnconstrainedNonDcCount') {
        # TRUSTED_FOR_DELEGATION (0x80000) on accounts that are not domain controllers.
        $accts = @(Get-ADObject -LDAPFilter '(userAccountControl:1.2.840.113556.1.4.803:=524288)' -Properties userAccountControl, primaryGroupID @common)
        @($accts | Where-Object { [int]$_.primaryGroupID -ne 516 }).Count  # 516 = Domain Controllers
    }

    & $collect @('Spn.UserAccountsWithSpnCount') {
        # User objects (not computers, not gMSA) with a servicePrincipalName -> Kerberoastable.
        @(Get-ADUser -LDAPFilter '(&(servicePrincipalName=*)(!(objectClass=msDS-GroupManagedServiceAccount)))' @common |
            Where-Object { $_.SamAccountName -ne 'krbtgt' }).Count
    }

    $staleCutoff = (Get-Date).AddDays(-1 * [math]::Abs($StaleDays))
    $meta['StaleDays'] = $StaleDays
    & $collect @('Accounts.StaleEnabledUsersCount') {
        @(Get-ADUser -Filter { Enabled -eq $true } -Properties LastLogonTimestamp @common |
            Where-Object { $_.LastLogonTimestamp -and ([datetime]::FromFileTime($_.LastLogonTimestamp) -lt $staleCutoff) }).Count
    }
    & $collect @('Accounts.StaleEnabledComputersCount') {
        @(Get-ADComputer -Filter { Enabled -eq $true } -Properties LastLogonTimestamp @common |
            Where-Object { $_.LastLogonTimestamp -and ([datetime]::FromFileTime($_.LastLogonTimestamp) -lt $staleCutoff) }).Count
    }
    & $collect @('Accounts.PasswordNeverExpiresEnabledCount') {
        @(Get-ADUser -Filter { Enabled -eq $true -and PasswordNeverExpires -eq $true } @common).Count
    }

    & $collect @('BuiltinGuest.Enabled') {
        $g = Get-ADUser -Identity ($domain.DomainSID.Value + '-501') -Properties Enabled @common
        [bool]$g.Enabled
    }
    & $collect @('BuiltinAdministrator.Renamed') {
        $a = Get-ADUser -Identity ($domain.DomainSID.Value + '-500') @common
        [bool]($a.SamAccountName -ne 'Administrator')
    }

    & $collect @('ProtectedUsers.Count') {
        @(Get-ADGroupMember -Identity 'Protected Users' -Recursive @common).Count
    }

    & $collect @('Laps.ComputerCoveragePct') {
        $computers = @(Get-ADComputer -Filter { Enabled -eq $true } -Properties 'msLAPS-PasswordExpirationTime', 'ms-Mcs-AdmPwdExpirationTime' @common)
        if ($computers.Count -eq 0) { return 0 }
        $covered = @($computers | Where-Object { $_.'msLAPS-PasswordExpirationTime' -or $_.'ms-Mcs-AdmPwdExpirationTime' }).Count
        [int][math]::Round(100 * $covered / $computers.Count, 0)
    }

    & $collect @('Trusts.WithoutSidFilteringCount') {
        # SID filtering (quarantine) should be on for external/forest trusts. SIDFilteringQuarantined
        # true means filtering is enforced. Count trusts where it is not enforced.
        @(Get-ADTrust -Filter * @common | Where-Object { -not $_.SIDFilteringQuarantined -and -not $_.IntraForest }).Count
    }

    & $collect @('Tombstone.LifetimeDays') {
        $cfgNc = (Get-ADRootDSE @common).configurationNamingContext
        $dsService = "CN=Directory Service,CN=Windows NT,CN=Services,$cfgNc"
        $o = Get-ADObject -Identity $dsService -Properties tombstoneLifetime @common
        if ($null -eq $o.tombstoneLifetime) { 60 } else { [int]$o.tombstoneLifetime }  # absent default is 60 days
    }

    return [PSCustomObject]@{
        Facts  = $facts
        Errors = $errors
        Meta   = $meta
    }
}

Export-ModuleMember -Function Import-AdPostureCatalog, Format-AdPostureExpect, Get-AdPostureFrameworkList,
    Invoke-AdPostureCheck, Get-AdPostureContext

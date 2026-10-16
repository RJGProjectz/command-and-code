<#
.SYNOPSIS
    Evaluation engine for data-driven CIS Benchmark audits on Windows.

.DESCRIPTION
    Script Name   : CisAudit.psm1
    Purpose       : Evaluates the checks in a CIS catalog (scripts/cis/catalogs/*.json, built by
                    tools/build_cis_catalog.py) against a host. Collection (secedit, auditpol,
                    registry, services) is separated from evaluation: every check runs against a
                    context object, so Pester can feed fixture data instead of a live system.
    Inputs        : Catalog object (Import-CisCatalog) and a context (Get-CisLiveContext or a fixture).
    Outputs       : One result object per CIS recommendation: Id, Title, Level, Section, Status
                    (Pass / Fail / NotApplicable / Error), Expected, Actual, Source, Detail.
    Security      : Security Domain: Compliance / Hardening. Read-only. secedit /export writes a
                    temporary .inf to $env:TEMP and deletes it; nothing on the host is changed.
    Author        : RJGProjectz
    Version       : 1.0.0
    Created       : 2026-10-16T14:45:00Z
    Last Modified : 2026-10-16T14:45:00Z
    KB Article    : docs/tasks/hardening/windows-11-cis-audit-tool.md
    Source Repo   : https://learn.microsoft.com/windows-server/administration/windows-commands/secedit-export
                    https://learn.microsoft.com/windows-server/administration/windows-commands/auditpol-get

.EXAMPLE
    Import-Module ./CisAudit.psm1
    $catalog = Import-CisCatalog -Path ../../cis/catalogs/windows11-enterprise-v5.1.0.json
    $context = Get-CisLiveContext
    $catalog.checks | ForEach-Object { Invoke-CisCheck -Check $_ -Context $context }
#>

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:SectionNames = @{
    '1'  = 'Account Policies'
    '2'  = 'Local Policies'
    '5'  = 'System Services'
    '9'  = 'Windows Defender Firewall'
    '17' = 'Advanced Audit Policy'
    '18' = 'Administrative Templates (Computer)'
    '19' = 'Administrative Templates (User)'
}

function Import-CisCatalog {
    <#
    .SYNOPSIS
        Loads a CIS catalog JSON file and checks its schema tag.
    .EXAMPLE
        Import-CisCatalog -Path ./windows11-enterprise-v5.1.0.json
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $catalog = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($catalog.schema -ne 'cc.cis.catalog/1') {
        throw "Unsupported catalog schema '$($catalog.schema)' in $Path"
    }
    return $catalog
}

function Get-CisSectionName {
    <#
    .SYNOPSIS
        Top-level CIS section name for a recommendation section number.
    .EXAMPLE
        Get-CisSectionName -Section '17'
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Section)
    if ($script:SectionNames.ContainsKey($Section)) { return $script:SectionNames[$Section] }
    return "Section $Section"
}

# --------------------------------------------------------------------------- parsers (pure)

function ConvertFrom-CisSeceditText {
    <#
    .SYNOPSIS
        Parses a secedit /export .inf into System Access values and Privilege Rights SID lists.
    .EXAMPLE
        ConvertFrom-CisSeceditText -Text (Get-Content cfg.inf -Raw)
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)

    $systemAccess = @{}
    $privilegeRights = @{}
    $section = ''
    foreach ($rawLine in ($Text -split "`r?`n")) {
        $line = $rawLine.Trim()
        $header = [regex]::Match($line, '^\[(.+)\]$')
        if ($header.Success) { $section = $header.Groups[1].Value; continue }
        $eq = $line.IndexOf('=')
        if ($eq -lt 1) { continue }
        $key = $line.Substring(0, $eq).Trim()
        $value = $line.Substring($eq + 1).Trim()
        switch ($section) {
            'System Access' {
                if ($value.Length -ge 2 -and $value.StartsWith('"') -and $value.EndsWith('"')) {
                    $value = $value.Substring(1, $value.Length - 2)
                }
                $systemAccess[$key] = $value
            }
            'Privilege Rights' {
                $privilegeRights[$key] = @($value -split ',' | ForEach-Object { $_.Trim().TrimStart('*') } | Where-Object { $_ })
            }
        }
    }
    return [PSCustomObject]@{ SystemAccess = $systemAccess; PrivilegeRights = $privilegeRights }
}

function ConvertFrom-CisAuditpolCsv {
    <#
    .SYNOPSIS
        Maps auditpol /get /category:* /r CSV output to Subcategory -> normalized setting.
    .DESCRIPTION
        'Success and Failure' becomes 'Success, Failure' (the catalog's form). Subcategory names are
        the English names; a non-English OS needs a matching catalog.
    .EXAMPLE
        ConvertFrom-CisAuditpolCsv -Lines (auditpol.exe /get /category:* /r)
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Lines)

    $map = @{}
    $rows = @($Lines | Where-Object { $_ -and $_.Trim() } | ConvertFrom-Csv)
    foreach ($row in $rows) {
        $name = [string]$row.Subcategory
        if (-not $name) { continue }
        $setting = ([string]$row.'Inclusion Setting').Trim()
        if ($setting -eq 'Success and Failure') { $setting = 'Success, Failure' }
        $map[$name.Trim()] = $setting
    }
    return $map
}

function ConvertTo-CisRegistryPath {
    <#
    .SYNOPSIS
        Converts 'HKLM\Software\...' to a PowerShell Registry:: provider path.
    .EXAMPLE
        ConvertTo-CisRegistryPath -Key 'HKLM\Software\Policies'
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Key)

    $hives = @{ 'HKLM' = 'HKEY_LOCAL_MACHINE'; 'HKU' = 'HKEY_USERS'; 'HKCU' = 'HKEY_CURRENT_USER' }
    $parts = $Key -split '\\', 2
    $hive = $hives[$parts[0].ToUpperInvariant()]
    if (-not $hive) { throw "Unsupported registry hive in '$Key'" }
    $rest = if ($parts.Count -gt 1) { $parts[1] } else { '' }
    return "Registry::$hive\$rest"
}

function Get-CisPrincipalLeafName {
    <#
    .SYNOPSIS
        Last segment of an account name, lower-case ('NT AUTHORITY\LOCAL SERVICE' -> 'local service').
    .EXAMPLE
        Get-CisPrincipalLeafName -Name 'BUILTIN\Administrators'
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Name)
    $leaf = ($Name -split '\\')[-1]
    return $leaf.Trim().ToLowerInvariant()
}

# --------------------------------------------------------------------------- expectations (pure)

function Test-CisExpectation {
    <#
    .SYNOPSIS
        Evaluates one catalog expectation against an observed value. Returns $true or $false.
    .DESCRIPTION
        Operators: eq, ne, range, regex, notRegex, any, all, in, set (exact / superset over
        alternative name sets), notEmpty, absent. Numbers compare numerically, text
        case-insensitively. $null means "not set".
    .EXAMPLE
        Test-CisExpectation -Expect ([PSCustomObject]@{ op = 'range'; min = 14; max = $null }) -Actual 14
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Expect,
        [Parameter(Mandatory = $false)][AllowNull()]$Actual
    )

    switch ($Expect.op) {
        'absent'   { return ($null -eq $Actual) }
        'notEmpty' { return ($null -ne $Actual -and ([string]($Actual -join '')).Trim().Length -gt 0) }
        'any'      { foreach ($e in $Expect.of) { if (Test-CisExpectation -Expect $e -Actual $Actual) { return $true } }; return $false }
        'all'      { foreach ($e in $Expect.of) { if (-not (Test-CisExpectation -Expect $e -Actual $Actual)) { return $false } }; return $true }
    }
    if ($Expect.op -eq 'set') {
        $observed = @(@($Actual) | Where-Object { $null -ne $_ -and [string]$_ -ne '' } |
            ForEach-Object { Get-CisPrincipalLeafName -Name ([string]$_) } | Sort-Object -Unique)
        foreach ($alternative in $Expect.anyOf) {
            $wanted = @(@($alternative) | Where-Object { $null -ne $_ -and [string]$_ -ne '' } |
                ForEach-Object { Get-CisPrincipalLeafName -Name ([string]$_) } | Sort-Object -Unique)
            $missing = @($wanted | Where-Object { $observed -notcontains $_ })
            if ($Expect.mode -eq 'superset') {
                if ($missing.Count -eq 0) { return $true }
            }
            else {
                $extra = @($observed | Where-Object { $wanted -notcontains $_ })
                if ($missing.Count -eq 0 -and $extra.Count -eq 0) { return $true }
            }
        }
        return $false
    }
    if ($null -eq $Actual) { return $false }
    $text = [string]$Actual
    switch ($Expect.op) {
        'eq' {
            $a = 0L; $b = 0L
            if ([long]::TryParse($text, [ref]$a) -and [long]::TryParse([string]$Expect.value, [ref]$b)) { return ($a -eq $b) }
            return [string]::Equals($text, [string]$Expect.value, [StringComparison]::OrdinalIgnoreCase)
        }
        'ne' {
            return -not [string]::Equals($text, [string]$Expect.value, [StringComparison]::OrdinalIgnoreCase)
        }
        'range' {
            $n = 0L
            if (-not [long]::TryParse($text, [ref]$n)) { return $false }
            if ($null -ne $Expect.min -and $n -lt [long]$Expect.min) { return $false }
            if ($null -ne $Expect.max -and $n -gt [long]$Expect.max) { return $false }
            return $true
        }
        'regex'    { return [regex]::IsMatch($text, [string]$Expect.pattern) }
        'notRegex' { return -not [regex]::IsMatch($text, [string]$Expect.pattern) }
        'in'       { foreach ($v in $Expect.values) { if ([string]::Equals($text, [string]$v, [StringComparison]::OrdinalIgnoreCase)) { return $true } }; return $false }
    }
    throw "Unknown expectation operator '$($Expect.op)'"
}

function Format-CisExpectation {
    <#
    .SYNOPSIS
        Human-readable form of an expectation for reports.
    .EXAMPLE
        Format-CisExpectation -Expect ([PSCustomObject]@{ op = 'eq'; value = '1' })
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Expect)

    switch ($Expect.op) {
        'eq'       { return [string]$Expect.value }
        'ne'       { return "not $($Expect.value)" }
        'range'    {
            if ($null -eq $Expect.max) { return ">= $($Expect.min)" }
            if ($null -eq $Expect.min) { return "<= $($Expect.max)" }
            return "$($Expect.min)..$($Expect.max)"
        }
        'regex'    { return "matches /$($Expect.pattern)/" }
        'notRegex' { return "does not match /$($Expect.pattern)/" }
        'in'       { return (@($Expect.values) -join ' | ') }
        'any'      { return ((@($Expect.of) | ForEach-Object { Format-CisExpectation -Expect $_ }) -join ' | ') }
        'all'      { return ((@($Expect.of) | ForEach-Object { Format-CisExpectation -Expect $_ }) -join ' & ') }
        'notEmpty' { return '(any non-empty value)' }
        'absent'   { return '(must not exist)' }
        'set'      {
            $alts = @($Expect.anyOf | ForEach-Object { $s = @($_); if ($s.Count -eq 0) { 'No One' } else { $s -join ', ' } })
            $prefix = if ($Expect.mode -eq 'superset') { 'includes ' } else { '' }
            return $prefix + ($alts -join ' | ')
        }
    }
    return [string]$Expect.op
}

function Format-CisValue {
    <#
    .SYNOPSIS
        Report form of an observed value ($null -> '(not set)', arrays joined).
    .EXAMPLE
        Format-CisValue -Value @('a', 'b')
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $false)][AllowNull()]$Value)
    if ($null -eq $Value) { return '(not set)' }
    $items = @($Value)
    if ($items.Count -eq 0) { return '(none)' }
    return ($items -join ', ')
}

# --------------------------------------------------------------------------- collection

function Get-CisLiveContext {
    <#
    .SYNOPSIS
        Collects live host data once (secedit, auditpol) and returns the context the checks read.
    .DESCRIPTION
        secedit /export and auditpol need an elevated session. When a source cannot be read, its
        error is kept in the context and every check that needs it reports Status 'Error'.
    .EXAMPLE
        $context = Get-CisLiveContext
    #>
    [CmdletBinding()]
    param()

    $secPolicy = $null; $secError = $null
    $auditPolicy = $null; $auditError = $null
    $inf = Join-Path ([IO.Path]::GetTempPath()) ("cc_cis_{0}.inf" -f [guid]::NewGuid().ToString('N'))
    try {
        $null = & secedit.exe /export /cfg $inf /areas SECURITYPOLICY USER_RIGHTS /quiet 2>&1
        if (-not (Test-Path -LiteralPath $inf)) { throw 'secedit /export produced no file (run elevated)' }
        $secPolicy = ConvertFrom-CisSeceditText -Text (Get-Content -LiteralPath $inf -Raw -Encoding Unicode)
    }
    catch { $secError = $_.Exception.Message }
    finally { if (Test-Path -LiteralPath $inf) { Remove-Item -LiteralPath $inf -Force } }

    try {
        $lines = @(& auditpol.exe /get /category:* /r 2>&1 | ForEach-Object { [string]$_ })
        if (-not ($lines | Where-Object { $_ -like '*Inclusion Setting*' })) {
            throw ("auditpol failed: " + (($lines | Where-Object { $_.Trim() }) -join ' ').Trim())
        }
        $auditPolicy = ConvertFrom-CisAuditpolCsv -Lines $lines
    }
    catch { $auditError = $_.Exception.Message }

    return [PSCustomObject]@{
        SecurityPolicy      = $secPolicy
        SecurityPolicyError = $secError
        AuditPolicy         = $auditPolicy
        AuditPolicyError    = $auditError
        ReadRegistry        = { param($Key, $Name) Read-CisRegistryValue -Key $Key -Name $Name }
        ListUserHives       = { Get-CisLoadedUserHive }
        ReadService         = { param($Name) $s = Get-Service -Name $Name -ErrorAction SilentlyContinue; if ($s) { [string]$s.Status } else { $null } }
        ResolveSid          = { param($Sid) Resolve-CisSid -Sid $Sid }
    }
}

function Read-CisRegistryValue {
    <#
    .SYNOPSIS
        Reads one registry value; returns $null when the key or value does not exist.
    .EXAMPLE
        Read-CisRegistryValue -Key 'HKLM\System\CurrentControlSet\Control\Lsa' -Name 'LmCompatibilityLevel'
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Key, [Parameter(Mandatory = $true)][string]$Name)
    $path = ConvertTo-CisRegistryPath -Key $Key
    $item = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
    if (-not $item) { return $null }
    if (@($item.GetValueNames()) -notcontains $Name) { return $null }
    return $item.GetValue($Name, $null, 'DoNotExpandEnvironmentNames')
}

function Get-CisLoadedUserHive {
    <#
    .SYNOPSIS
        SIDs of the domain/local user hives loaded under HKEY_USERS (S-1-5-21-*, not _Classes).
    .EXAMPLE
        Get-CisLoadedUserHive
    #>
    [CmdletBinding()]
    param()
    return @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
        ForEach-Object { $_.PSChildName } | Where-Object { $_ -match '^S-1-5-21-[\d-]+$' })
}

function Resolve-CisSid {
    <#
    .SYNOPSIS
        Translates a SID to an account name; returns the SID text when it cannot be translated.
    .EXAMPLE
        Resolve-CisSid -Sid 'S-1-5-32-544'
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Sid)
    if ($Sid -notmatch '^S-\d') { return $Sid }
    try {
        return ([Security.Principal.SecurityIdentifier]::new($Sid)).Translate([Security.Principal.NTAccount]).Value
    }
    catch { return $Sid }
}

# --------------------------------------------------------------------------- evaluation

function Invoke-CisTest {
    <#
    .SYNOPSIS
        Evaluates one test of a check. Returns Status, Actual, Source, Detail.
    .EXAMPLE
        Invoke-CisTest -Test $check.tests[0] -Context $context
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Test, [Parameter(Mandatory = $true)]$Context)

    $actual = $null
    $source = ''
    switch ($Test.source) {
        'SecurityPolicy' {
            $source = "secedit [System Access] $($Test.key)"
            if ($null -eq $Context.SecurityPolicy) { return ConvertTo-CisTestResult -Status 'Error' -Actual $null -Source $source -Detail "Security policy unavailable: $($Context.SecurityPolicyError)" }
            if ($Context.SecurityPolicy.SystemAccess.ContainsKey($Test.key)) { $actual = $Context.SecurityPolicy.SystemAccess[$Test.key] }
        }
        'UserRight' {
            $source = "secedit [Privilege Rights] $($Test.right)"
            if ($null -eq $Context.SecurityPolicy) { return ConvertTo-CisTestResult -Status 'Error' -Actual $null -Source $source -Detail "Security policy unavailable: $($Context.SecurityPolicyError)" }
            $sids = @()
            if ($Context.SecurityPolicy.PrivilegeRights.ContainsKey($Test.right)) { $sids = @($Context.SecurityPolicy.PrivilegeRights[$Test.right]) }
            $actual = @($sids | ForEach-Object { [string](& $Context.ResolveSid $_) })
        }
        'AuditPolicy' {
            $source = "auditpol $($Test.subcategory)"
            if ($null -eq $Context.AuditPolicy) { return ConvertTo-CisTestResult -Status 'Error' -Actual $null -Source $source -Detail "Audit policy unavailable: $($Context.AuditPolicyError)" }
            if ($Context.AuditPolicy.ContainsKey($Test.subcategory)) { $actual = $Context.AuditPolicy[$Test.subcategory] }
            else { return ConvertTo-CisTestResult -Status 'Error' -Actual $null -Source $source -Detail "Subcategory '$($Test.subcategory)' not in auditpol output (non-English OS?)" }
        }
        'Service' {
            $source = "service $($Test.name)"
            $actual = & $Context.ReadService $Test.name
        }
        'Registry' {
            $source = "$($Test.key)\$($Test.name)"
            if ($Test.key -match '^HKU\\') { return Invoke-CisUserHiveTest -Test $Test -Context $Context }
            $actual = & $Context.ReadRegistry $Test.key $Test.name
            if ($null -eq $actual) {
                $mustNotExist = ($Test.PSObject.Properties.Name -contains 'mustNotExist') -and $Test.mustNotExist
                $allowMissing = ($Test.PSObject.Properties.Name -contains 'allowMissing') -and $Test.allowMissing
                if ($mustNotExist -or $allowMissing) { return ConvertTo-CisTestResult -Status 'Pass' -Actual $null -Source $source -Detail '' }
                return ConvertTo-CisTestResult -Status 'Fail' -Actual $null -Source $source -Detail 'Value not set'
            }
            if (($Test.PSObject.Properties.Name -contains 'mustNotExist') -and $Test.mustNotExist) {
                return ConvertTo-CisTestResult -Status 'Fail' -Actual $actual -Source $source -Detail 'Value must not exist'
            }
        }
        default { return ConvertTo-CisTestResult -Status 'Error' -Actual $null -Source $Test.source -Detail "Unsupported test source '$($Test.source)'" }
    }
    $status = if (Test-CisExpectation -Expect $Test.expect -Actual $actual) { 'Pass' } else { 'Fail' }
    return ConvertTo-CisTestResult -Status $status -Actual $actual -Source $source -Detail ''
}

function Invoke-CisUserHiveTest {
    <#
    .SYNOPSIS
        Evaluates an HKU\[USER SID]\... registry test against every loaded user hive.
    .EXAMPLE
        Invoke-CisUserHiveTest -Test $test -Context $context
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Test, [Parameter(Mandatory = $true)]$Context)

    $relative = ($Test.key -replace '^HKU\\', '')
    $hives = @(& $Context.ListUserHives)
    $source = "HKU\<each user>\$relative\$($Test.name)"
    if ($hives.Count -eq 0) { return ConvertTo-CisTestResult -Status 'NotApplicable' -Actual $null -Source $source -Detail 'No user hives loaded' }
    $allowMissing = ($Test.PSObject.Properties.Name -contains 'allowMissing') -and $Test.allowMissing
    $failures = @()
    $observed = @()
    foreach ($sid in $hives) {
        $value = & $Context.ReadRegistry "HKU\$sid\$relative" $Test.name
        $observed += "$sid=$(Format-CisValue -Value $value)"
        $ok = if ($null -eq $value) { $allowMissing } else { Test-CisExpectation -Expect $Test.expect -Actual $value }
        if (-not $ok) { $failures += $sid }
    }
    $status = if ($failures.Count -eq 0) { 'Pass' } else { 'Fail' }
    $detail = if ($failures.Count) { "Non-compliant hives: $($failures -join ', ')" } else { '' }
    return ConvertTo-CisTestResult -Status $status -Actual ($observed -join '; ') -Source $source -Detail $detail
}

function ConvertTo-CisTestResult {
    <#
    .SYNOPSIS
        Builds the per-test result object used inside Invoke-CisCheck.
    .EXAMPLE
        ConvertTo-CisTestResult -Status Pass -Actual 1 -Source 'HKLM\X\Y' -Detail ''
    #>
    [CmdletBinding()]
    param([string]$Status, [AllowNull()]$Actual, [string]$Source, [AllowEmptyString()][string]$Detail)
    return [PSCustomObject]@{ Status = $Status; Actual = $Actual; Source = $Source; Detail = $Detail }
}

function Invoke-CisCheck {
    <#
    .SYNOPSIS
        Evaluates one CIS recommendation (all of its tests must pass) and returns the result row.
    .EXAMPLE
        Invoke-CisCheck -Check $catalog.checks[0] -Context (Get-CisLiveContext)
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Check, [Parameter(Mandatory = $true)]$Context)

    $tests = $null
    if ($Check.PSObject.Properties.Name -contains 'variants') {
        foreach ($variant in $Check.variants) {
            if ($null -eq $variant.when) { $tests = $variant.tests; break }
            $conditionMet = $true
            foreach ($condition in $variant.when) {
                if ((Invoke-CisTest -Test $condition -Context $Context).Status -ne 'Pass') { $conditionMet = $false; break }
            }
            if ($conditionMet) { $tests = $variant.tests; break }
        }
    }
    else { $tests = $Check.tests }

    $results = @()
    try { $results = @($tests | ForEach-Object { Invoke-CisTest -Test $_ -Context $Context }) }
    catch { $results = @(ConvertTo-CisTestResult -Status 'Error' -Actual $null -Source '' -Detail $_.Exception.Message) }

    $status = 'Pass'
    if ($results | Where-Object { $_.Status -eq 'Error' }) { $status = 'Error' }
    elseif ($results | Where-Object { $_.Status -eq 'Fail' }) { $status = 'Fail' }
    elseif (@($results | Where-Object { $_.Status -eq 'NotApplicable' }).Count -eq $results.Count) { $status = 'NotApplicable' }

    return [PSCustomObject]@{
        Id          = $Check.id
        Title       = $Check.title
        Level       = $Check.level
        Section     = Get-CisSectionName -Section $Check.section
        Status      = $status
        Expected    = (@($tests | ForEach-Object { Format-CisExpectation -Expect $_.expect }) -join ' ; ')
        Actual      = (@($results | ForEach-Object { Format-CisValue -Value $_.Actual }) -join ' ; ')
        Source      = (@($results | ForEach-Object { $_.Source }) -join ' ; ')
        Detail      = (@($results | Where-Object { $_.Detail } | ForEach-Object { $_.Detail }) -join ' ; ')
    }
}

function Select-CisCheck {
    <#
    .SYNOPSIS
        Filters catalog checks by profile level (L2 includes L1), ID wildcard and section.
    .EXAMPLE
        Select-CisCheck -Catalog $catalog -Level L1 -Id '2.3.*'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Catalog,
        [ValidateSet('L1', 'L2')][string]$Level = 'L1',
        [string[]]$Id = @('*'),
        [string[]]$Section = @()
    )
    $levels = if ($Level -eq 'L2') { @('L1', 'L2') } else { @('L1') }
    return @($Catalog.checks | Where-Object {
            $check = $_
            ($levels -contains $check.level) -and
            (@($Id | Where-Object { $check.id -like $_ }).Count -gt 0) -and
            ($Section.Count -eq 0 -or $Section -contains $check.section)
        })
}

Export-ModuleMember -Function Import-CisCatalog, Get-CisSectionName, ConvertFrom-CisSeceditText,
    ConvertFrom-CisAuditpolCsv, ConvertTo-CisRegistryPath, Get-CisPrincipalLeafName, Test-CisExpectation,
    Format-CisExpectation, Format-CisValue, Get-CisLiveContext, Read-CisRegistryValue, Get-CisLoadedUserHive,
    Resolve-CisSid, Invoke-CisTest, Invoke-CisUserHiveTest, Invoke-CisCheck, Select-CisCheck

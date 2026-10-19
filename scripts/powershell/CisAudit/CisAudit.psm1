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
    Version       : 1.1.0
    Created       : 2026-10-16T14:45:00Z
    Last Modified : 2026-10-19T03:30:00Z
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

# Advanced Audit Policy subcategory name -> GUID (MS-GPAC 2.2.1.2; same table as `auditpol /list
# /subcategory:* /v` on Windows 11 26200). GUIDs are language-independent, names are not.
$script:AuditSubcategoryGuid = @{
    'Security State Change' = '{0CCE9210-69AE-11D9-BED3-505054503030}'
    'Security System Extension' = '{0CCE9211-69AE-11D9-BED3-505054503030}'
    'System Integrity' = '{0CCE9212-69AE-11D9-BED3-505054503030}'
    'IPsec Driver' = '{0CCE9213-69AE-11D9-BED3-505054503030}'
    'Other System Events' = '{0CCE9214-69AE-11D9-BED3-505054503030}'
    'Logon' = '{0CCE9215-69AE-11D9-BED3-505054503030}'
    'Logoff' = '{0CCE9216-69AE-11D9-BED3-505054503030}'
    'Account Lockout' = '{0CCE9217-69AE-11D9-BED3-505054503030}'
    'IPsec Main Mode' = '{0CCE9218-69AE-11D9-BED3-505054503030}'
    'IPsec Quick Mode' = '{0CCE9219-69AE-11D9-BED3-505054503030}'
    'IPsec Extended Mode' = '{0CCE921A-69AE-11D9-BED3-505054503030}'
    'Special Logon' = '{0CCE921B-69AE-11D9-BED3-505054503030}'
    'Other Logon/Logoff Events' = '{0CCE921C-69AE-11D9-BED3-505054503030}'
    'Network Policy Server' = '{0CCE9243-69AE-11D9-BED3-505054503030}'
    'User / Device Claims' = '{0CCE9247-69AE-11D9-BED3-505054503030}'
    'Group Membership' = '{0CCE9249-69AE-11D9-BED3-505054503030}'
    'Access Rights' = '{0CCE924B-69AE-11D9-BED3-505054503030}'
    'File System' = '{0CCE921D-69AE-11D9-BED3-505054503030}'
    'Registry' = '{0CCE921E-69AE-11D9-BED3-505054503030}'
    'Kernel Object' = '{0CCE921F-69AE-11D9-BED3-505054503030}'
    'SAM' = '{0CCE9220-69AE-11D9-BED3-505054503030}'
    'Certification Services' = '{0CCE9221-69AE-11D9-BED3-505054503030}'
    'Application Generated' = '{0CCE9222-69AE-11D9-BED3-505054503030}'
    'Handle Manipulation' = '{0CCE9223-69AE-11D9-BED3-505054503030}'
    'File Share' = '{0CCE9224-69AE-11D9-BED3-505054503030}'
    'Filtering Platform Packet Drop' = '{0CCE9225-69AE-11D9-BED3-505054503030}'
    'Filtering Platform Connection' = '{0CCE9226-69AE-11D9-BED3-505054503030}'
    'Other Object Access Events' = '{0CCE9227-69AE-11D9-BED3-505054503030}'
    'Detailed File Share' = '{0CCE9244-69AE-11D9-BED3-505054503030}'
    'Removable Storage' = '{0CCE9245-69AE-11D9-BED3-505054503030}'
    'Central Policy Staging' = '{0CCE9246-69AE-11D9-BED3-505054503030}'
    'Sensitive Privilege Use' = '{0CCE9228-69AE-11D9-BED3-505054503030}'
    'Non Sensitive Privilege Use' = '{0CCE9229-69AE-11D9-BED3-505054503030}'
    'Other Privilege Use Events' = '{0CCE922A-69AE-11D9-BED3-505054503030}'
    'Process Creation' = '{0CCE922B-69AE-11D9-BED3-505054503030}'
    'Process Termination' = '{0CCE922C-69AE-11D9-BED3-505054503030}'
    'DPAPI Activity' = '{0CCE922D-69AE-11D9-BED3-505054503030}'
    'RPC Events' = '{0CCE922E-69AE-11D9-BED3-505054503030}'
    'Plug and Play Events' = '{0CCE9248-69AE-11D9-BED3-505054503030}'
    'Token Right Adjusted Events' = '{0CCE924A-69AE-11D9-BED3-505054503030}'
    'Audit Policy Change' = '{0CCE922F-69AE-11D9-BED3-505054503030}'
    'Authentication Policy Change' = '{0CCE9230-69AE-11D9-BED3-505054503030}'
    'Authorization Policy Change' = '{0CCE9231-69AE-11D9-BED3-505054503030}'
    'MPSSVC Rule-Level Policy Change' = '{0CCE9232-69AE-11D9-BED3-505054503030}'
    'Filtering Platform Policy Change' = '{0CCE9233-69AE-11D9-BED3-505054503030}'
    'Other Policy Change Events' = '{0CCE9234-69AE-11D9-BED3-505054503030}'
    'User Account Management' = '{0CCE9235-69AE-11D9-BED3-505054503030}'
    'Computer Account Management' = '{0CCE9236-69AE-11D9-BED3-505054503030}'
    'Security Group Management' = '{0CCE9237-69AE-11D9-BED3-505054503030}'
    'Distribution Group Management' = '{0CCE9238-69AE-11D9-BED3-505054503030}'
    'Application Group Management' = '{0CCE9239-69AE-11D9-BED3-505054503030}'
    'Other Account Management Events' = '{0CCE923A-69AE-11D9-BED3-505054503030}'
    'Directory Service Access' = '{0CCE923B-69AE-11D9-BED3-505054503030}'
    'Directory Service Changes' = '{0CCE923C-69AE-11D9-BED3-505054503030}'
    'Directory Service Replication' = '{0CCE923D-69AE-11D9-BED3-505054503030}'
    'Detailed Directory Service Replication' = '{0CCE923E-69AE-11D9-BED3-505054503030}'
    'Credential Validation' = '{0CCE923F-69AE-11D9-BED3-505054503030}'
    'Kerberos Service Ticket Operations' = '{0CCE9240-69AE-11D9-BED3-505054503030}'
    'Other Account Logon Events' = '{0CCE9241-69AE-11D9-BED3-505054503030}'
    'Kerberos Authentication Service' = '{0CCE9242-69AE-11D9-BED3-505054503030}'
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
        Maps auditpol /get /category:* /r CSV output to subcategory -> normalized setting.
    .DESCRIPTION
        Fallback source when auditpol /backup is unavailable. Each row is keyed by its subcategory
        GUID ({0CCE...}, upper case) and by its name. 'Success and Failure' becomes
        'Success, Failure' (the catalog's form). The setting text is localized by Windows, so on a
        non-English OS prefer ConvertFrom-CisAuditpolBackup.
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
        $guid = ([string]$row.'Subcategory GUID').Trim().ToUpperInvariant()
        if ($guid) { $map[$guid] = $setting }
    }
    return $map
}

function ConvertFrom-CisAuditpolBackup {
    <#
    .SYNOPSIS
        Maps an auditpol /backup CSV (GPO audit.csv format) to subcategory GUID -> normalized setting.
    .DESCRIPTION
        Uses the numeric 'Setting Value' column (bit 1 = Success, bit 2 = Failure; MS-GPAC 2.2.1.3),
        so the result does not depend on the Windows display language. Only rows for the System
        policy target with a subcategory GUID are used.
    .EXAMPLE
        ConvertFrom-CisAuditpolBackup -Lines (Get-Content audit.csv)
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$Lines)

    $names = @{ 0 = 'No Auditing'; 1 = 'Success'; 2 = 'Failure'; 3 = 'Success, Failure' }
    $map = @{}
    $rows = @($Lines | Where-Object { $_ -and $_.Trim() } | ConvertFrom-Csv)
    foreach ($row in $rows) {
        $guid = ([string]$row.'Subcategory GUID').Trim().ToUpperInvariant()
        if (-not $guid -or ([string]$row.'Policy Target').Trim() -ne 'System') { continue }
        $value = 0
        if (-not [int]::TryParse(([string]$row.'Setting Value').Trim(), [ref]$value)) { continue }
        $map[$guid] = $names[$value -band 3]
    }
    return $map
}

function Get-CisAuditSubcategoryGuid {
    <#
    .SYNOPSIS
        GUID ({0CCE...}, upper case) of an Advanced Audit Policy subcategory, or $null if unknown.
    .EXAMPLE
        Get-CisAuditSubcategoryGuid -Name 'Credential Validation'
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Name)
    if ($script:AuditSubcategoryGuid.ContainsKey($Name)) { return $script:AuditSubcategoryGuid[$Name].ToUpperInvariant() }
    return $null
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
    $auditPolicy = $null; $auditError = $null; $auditSource = $null
    $inf = Join-Path ([IO.Path]::GetTempPath()) ("cc_cis_{0}.inf" -f [guid]::NewGuid().ToString('N'))
    try {
        $null = & secedit.exe /export /cfg $inf /areas SECURITYPOLICY USER_RIGHTS /quiet 2>&1
        if (-not (Test-Path -LiteralPath $inf)) { throw 'secedit /export produced no file (run elevated)' }
        $secPolicy = ConvertFrom-CisSeceditText -Text (Get-Content -LiteralPath $inf -Raw -Encoding Unicode)
    }
    catch { $secError = $_.Exception.Message }
    finally { if (Test-Path -LiteralPath $inf) { Remove-Item -LiteralPath $inf -Force } }

    # Audit policy: auditpol /backup gives numeric settings by GUID (language-independent); fall
    # back to /get /r when the backup cannot be written.
    $csv = Join-Path ([IO.Path]::GetTempPath()) ("cc_cis_{0}.csv" -f [guid]::NewGuid().ToString('N'))
    try {
        $null = & auditpol.exe /backup "/file:$csv" 2>&1
        if (Test-Path -LiteralPath $csv) {
            $auditPolicy = ConvertFrom-CisAuditpolBackup -Lines ([IO.File]::ReadAllLines($csv))
            $auditSource = 'auditpol /backup'
        }
        if (-not $auditPolicy -or $auditPolicy.Count -eq 0) {
            $lines = @(& auditpol.exe /get /category:* /r 2>&1 | ForEach-Object { [string]$_ })
            if (-not ($lines | Where-Object { $_ -match '\{0CCE9[0-9A-F]{3}-' })) {
                throw ("auditpol failed: " + (($lines | Where-Object { $_.Trim() }) -join ' ').Trim())
            }
            $auditPolicy = ConvertFrom-CisAuditpolCsv -Lines $lines
            $auditSource = 'auditpol /get /r'
        }
    }
    catch { $auditPolicy = $null; $auditSource = $null; $auditError = $_.Exception.Message }
    finally { if (Test-Path -LiteralPath $csv) { Remove-Item -LiteralPath $csv -Force } }

    return [PSCustomObject]@{
        SecurityPolicy      = $secPolicy
        SecurityPolicyError = $secError
        AuditPolicy         = $auditPolicy
        AuditPolicyError    = $auditError
        AuditPolicySource   = $auditSource
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
            $guid = Get-CisAuditSubcategoryGuid -Name $Test.subcategory
            if ($guid -and $Context.AuditPolicy.ContainsKey($guid)) { $actual = $Context.AuditPolicy[$guid] }
            elseif ($Context.AuditPolicy.ContainsKey($Test.subcategory)) { $actual = $Context.AuditPolicy[$Test.subcategory] }
            else { return ConvertTo-CisTestResult -Status 'Error' -Actual $null -Source $source -Detail "Subcategory '$($Test.subcategory)' not found in audit policy output" }
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

function Get-CisExitCode {
    <#
    .SYNOPSIS
        Process exit code for an audit run: 0 = OK, 1 = non-compliant (Fail), 2 = incomplete (Error).
    .DESCRIPTION
        -FailOn None always returns 0. Fail returns 1 when any check failed. FailOrError also returns
        2 when any check could not be evaluated (checked first: an incomplete audit is not a pass).
    .EXAMPLE
        Get-CisExitCode -Results $results -FailOn Fail
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Results,
        [ValidateSet('None', 'Fail', 'FailOrError')][string]$FailOn = 'None'
    )
    if ($FailOn -eq 'None') { return 0 }
    if ($FailOn -eq 'FailOrError' -and @($Results | Where-Object { $_.Status -eq 'Error' }).Count -gt 0) { return 2 }
    if (@($Results | Where-Object { $_.Status -eq 'Fail' }).Count -gt 0) { return 1 }
    return 0
}

function Test-CisSupportedEdition {
    <#
    .SYNOPSIS
        $true for Windows editions that honor the full Group Policy set the benchmark targets
        (Enterprise / Education families); $false for Home (Core), Pro and others.
    .EXAMPLE
        Test-CisSupportedEdition -EditionId 'Professional'
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$EditionId)
    # Server editions (ServerStandard, ServerDatacenter, ServerAzureEdition...) honor the full set.
    return ($EditionId -match '^(Enterprise|Education|IoTEnterprise|Server)')
}

function ConvertTo-CisHostRole {
    <#
    .SYNOPSIS
        Host role from Win32_OperatingSystem.ProductType (1 = work station, 2 = domain controller,
        3 = server): Workstation, DomainController or MemberServer. A standalone (workgroup) server
        is MemberServer, which is the profile CIS applies to it.
    .EXAMPLE
        ConvertTo-CisHostRole -ProductType 2
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowNull()]$ProductType)
    switch ([string]$ProductType) {
        '1' { return 'Workstation' }
        '2' { return 'DomainController' }
        '3' { return 'MemberServer' }
        default { return 'Unknown' }
    }
}

function Test-CisCatalogRole {
    <#
    .SYNOPSIS
        $true when the catalog's server profile matches the host role: MS -> MemberServer,
        DC -> DomainController, no profile (client benchmark) -> Workstation.
    .EXAMPLE
        Test-CisCatalogRole -Catalog $catalog -HostRole MemberServer
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Catalog,
        [Parameter(Mandatory = $true)][string]$HostRole
    )
    $profileName = if ($Catalog.PSObject.Properties.Name -contains 'profile') { [string]$Catalog.profile } else { '' }
    $wanted = switch ($profileName) { 'MS' { 'MemberServer' } 'DC' { 'DomainController' } default { 'Workstation' } }
    return ($HostRole -eq $wanted)
}

Export-ModuleMember -Function Import-CisCatalog, Get-CisSectionName, ConvertFrom-CisSeceditText,
    ConvertFrom-CisAuditpolCsv, ConvertFrom-CisAuditpolBackup, Get-CisAuditSubcategoryGuid,
    ConvertTo-CisRegistryPath, Get-CisPrincipalLeafName, Test-CisExpectation,
    Format-CisExpectation, Format-CisValue, Get-CisLiveContext, Read-CisRegistryValue, Get-CisLoadedUserHive,
    Resolve-CisSid, Invoke-CisTest, Invoke-CisUserHiveTest, Invoke-CisCheck, Select-CisCheck,
    Get-CisExitCode, Test-CisSupportedEdition, ConvertTo-CisHostRole, Test-CisCatalogRole

<#
.SYNOPSIS
    Read-only Azure / Entra ID identity posture engine. Evaluates one Azure posture catalog where every
    check carries a CIS Microsoft Azure Foundations Benchmark and Microsoft Cloud Security Benchmark
    (MCSB) crosswalk, and grades observed values against each framework.

.DESCRIPTION
    Module Name   : AzurePosture.psm1
    Purpose       : Collect Azure / Entra ID facts once (Get-AzurePostureContext), then evaluate each
                    catalog check against its CIS / MCSB / best-practice expectation
                    (Invoke-AzurePostureCheck). Expectation evaluation is delegated to the shared CIS
                    engine's Test-CisExpectation so the operator model (eq, ne, range, in, regex, set,
                    any, all, ...) is identical to the Windows and AD posture engines.
    Security      : Security Domain: Compliance / Hardening. Read-only: the collector makes GET
                    requests to the Microsoft Graph v1.0 API via the az CLI. No Azure resource is
                    changed. Requires az login with a user or service principal that holds the
                    Global Reader or Security Reader built-in Entra ID role.
    Author        : RJGProjectz
    Version       : 1.0.0
    Created       : 2026-10-29T00:00:00Z
    Last Modified : 2026-10-29T00:00:00Z
    KB Article    : docs/tasks/assurance/azure-posture-audit.md
    API Standards : Result Status values Pass | Fail | NotApplicable | Error. Catalog schema
                    cc.azposture.catalog/1. CIS IDs are indicative; confirm against the version your
                    Defender for Cloud regulatory-compliance view enforces.
#>

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# Reuse the shared CIS engine's pure expectation evaluator and formatters.
Import-Module (Join-Path $PSScriptRoot '..\CisAudit\CisAudit.psm1') -Force

# Graph API base URL used by every collector.
$script:GraphBase = 'https://graph.microsoft.com/v1.0'

# Global Administrator built-in role definition ID (stable across all tenants).
$script:GlobalAdminRoleId = '62e90394-69f5-4237-9190-012177145e10'

# guestUserRoleId GUID to access level (0=Restricted, 1=Limited, 2=Default/Full).
$script:GuestRoleToLevel = @{
    '9ae39eba-78d6-4ef4-a42d-c98eb55b1eb6' = 0  # Restricted
    '2af84b1e-32c8-42b7-82bc-daa82404023b' = 1  # Limited
    '10dae51f-b6af-4016-8d66-8c2a99b929b3' = 2  # Default (full)
}

function Import-AzurePostureCatalog {
    <#
    .SYNOPSIS
        Loads an Azure posture catalog JSON file and validates its schema tag.
    .EXAMPLE
        Import-AzurePostureCatalog -Path ./azure-identity-posture-v1.json
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $catalog = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($catalog.schema -ne 'cc.azposture.catalog/1') {
        throw "Unsupported Azure posture catalog schema '$($catalog.schema)' in $Path"
    }
    return $catalog
}

function Format-AzurePostureExpect {
    <#
    .SYNOPSIS
        Human-readable form of a framework expectation for reports (delegates to the CIS formatter).
    .EXAMPLE
        Format-AzurePostureExpect -Expect ([PSCustomObject]@{ op = 'range'; min = 2; max = 4 })
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowNull()]$Expect)
    if ($null -eq $Expect) { return 'n/a' }
    return (Format-CisExpectation -Expect $Expect)
}

function Get-AzurePostureFrameworkList {
    <#
    .SYNOPSIS
        Ordered list of the frameworks present on a check: cis, mcsb, bestPractice. A framework whose
        expect is absent or null is skipped. Best practice is always last (minimum bar).
    .EXAMPLE
        Get-AzurePostureFrameworkList -Check $check
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Check)

    $order = @('cis', 'mcsb', 'bestPractice')
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

function Invoke-AzurePostureCheck {
    <#
    .SYNOPSIS
        Evaluates one Azure posture check against a collected context and returns the result row.
    .DESCRIPTION
        Reads the observed value from $Context.Facts by the check's 'collector' key. If the fact is
        missing from the context (could not be collected), the check reports Error. Otherwise each
        framework expectation (cis / mcsb / bestPractice) is evaluated with Test-CisExpectation. The
        overall Status is decided by -Bar: 'BestPractice' (default) passes when the best-practice
        expectation passes; 'Strictest' passes only when every present framework passes. Per-framework
        verdicts are always recorded in the Cis / Mcsb / BestPractice fields.
    .EXAMPLE
        Invoke-AzurePostureCheck -Check $catalog.checks[0] -Context $context -Bar BestPractice
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

    $frameworks = Get-AzurePostureFrameworkList -Check $Check
    $perFramework = [ordered]@{}
    $expectedParts = @()

    $collectorError = $false
    if (-not $hasFact) { $collectorError = $true }
    elseif ($Context.PSObject.Properties.Name -contains 'Errors' -and $null -ne $Context.Errors -and
            $Context.Errors -is [System.Collections.IDictionary] -and $Context.Errors.Contains($collector)) {
        $collectorError = $true
    }

    foreach ($name in $frameworks) {
        $fw = $Check.frameworks.$name
        $expectText = Format-AzurePostureExpect -Expect $fw.expect
        $label = switch ($name) { 'cis' { 'CIS' } 'mcsb' { 'MCSB' } 'bestPractice' { 'BP' } default { $name } }
        $idText = if ($fw.PSObject.Properties.Name -contains 'id' -and $fw.id) { " [$($fw.id)]" } else { '' }
        $expectedParts += "$label$($idText): $expectText"
        if ($collectorError) {
            $perFramework[$name] = 'Error'
            continue
        }
        $ok = Test-CisExpectation -Expect $fw.expect -Actual $actual
        $perFramework[$name] = if ($ok) { 'Pass' } else { 'Fail' }
    }

    foreach ($name in @('cis', 'mcsb', 'bestPractice')) {
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
        Cis          = $perFramework['cis']
        Mcsb         = $perFramework['mcsb']
        BestPractice = $perFramework['bestPractice']
        Source       = "Azure Graph: $collector"
        Detail       = ($detailParts -join ' ; ')
    }
}

function Get-AzurePostureContext {
    <#
    .SYNOPSIS
        Collects Azure / Entra ID identity facts once (read-only, via az CLI + Graph v1.0) into a
        context the checks read. Requires 'az' to be installed and already logged in (az login).
    .DESCRIPTION
        Each fact is collected independently; a fact that cannot be read is recorded in .Errors and
        its check reports Error. A 403 / Unauthorized usually means the signed-in account lacks the
        needed Entra ID role (Global Reader or Security Reader) or the feature requires Azure AD P2.
        -TenantId targets a specific tenant; omit to use the signed-in account's default tenant.
    .EXAMPLE
        $ctx = Get-AzurePostureContext
    .EXAMPLE
        $ctx = Get-AzurePostureContext -TenantId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][string]$TenantId
    )

    # Verify az CLI is available and logged in.
    try {
        $null = Get-Command az -ErrorAction Stop
        $account = az account show 2>$null | ConvertFrom-Json
        if (-not $account) { throw 'az account show returned no output — run az login first.' }
    }
    catch {
        throw "az CLI prerequisite check failed: $($_.Exception.Message)"
    }

    $graphBase = $script:GraphBase
    $gaRoleId = $script:GlobalAdminRoleId
    $guestRoleMap = $script:GuestRoleToLevel
    $tenantSwitch = if ($TenantId) { @('--tenant', $TenantId) } else { @() }

    $facts = @{}
    $errors = @{}
    $meta = @{}

    # Helper: run a collector scriptblock; store results in $facts or record the error per fact name.
    $collect = {
        param([string[]]$Names, [scriptblock]$Script)
        try {
            $value = & $Script
            if ($Names.Count -eq 1) {
                $facts[$Names[0]] = $value
            }
            elseif ($value -is [System.Collections.IDictionary]) {
                foreach ($n in $Names) { $facts[$n] = $value[$n] }
            }
        }
        catch {
            $msg = $_.Exception.Message
            foreach ($n in $Names) { $errors[$n] = $msg }
        }
    }

    # Helper: invoke az rest and return parsed JSON.
    $azRest = {
        param([string]$Uri)
        $raw = az rest --method GET --uri $Uri @tenantSwitch 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "az rest GET $Uri failed (exit $LASTEXITCODE): $($raw -join ' ')"
        }
        return ($raw | ConvertFrom-Json)
    }

    # ---------------------------------------------------------------------- tenant metadata
    try {
        $orgInfo = & $azRest "$graphBase/organization"
        if ($orgInfo.value) {
            $meta['TenantId'] = [string]$orgInfo.value[0].id
            $meta['TenantName'] = [string]$orgInfo.value[0].displayName
        }
    }
    catch { $meta['TenantId'] = 'unknown'; $meta['TenantName'] = 'unknown' }

    # ---------------------------------------------------------------------- Security Defaults
    & $collect @('Entra.SecurityDefaults.IsEnabled') {
        $policy = & $azRest "$graphBase/policies/identitySecurityDefaultsEnforcementPolicy"
        [string]([bool]$policy.isEnabled)
    }

    # ---------------------------------------------------------------------- Conditional Access
    & $collect @('Entra.ConditionalAccess.EnabledPolicyCount',
                 'Entra.ConditionalAccess.HasMfaAllUsers',
                 'Entra.ConditionalAccess.HasBlockLegacyAuth',
                 'Entra.ConditionalAccess.HasSignInRiskPolicy',
                 'Entra.ConditionalAccess.HasUserRiskPolicy') {
        $resp = & $azRest "$graphBase/identity/conditionalAccess/policies"
        $enabled = @($resp.value | Where-Object { $_.state -eq 'enabled' })

        $hasMfaAll = $false
        $hasBlockLegacy = $false
        $hasSignInRisk = $false
        $hasUserRisk = $false

        foreach ($p in $enabled) {
            $includeUsers = @(if ($p.conditions.users) { $p.conditions.users.includeUsers } else { @() })
            $grants = @()
            if ($p.grantControls -and $p.grantControls.builtInControls) {
                $grants = @($p.grantControls.builtInControls)
            }
            $isBlock = ($p.grantControls -and $p.grantControls.operator -eq 'block') -or
                       ($grants -contains 'block')
            $clientTypes = @(if ($p.conditions.clientAppTypes) { $p.conditions.clientAppTypes } else { @() })

            # MFA for all users: includes 'All' users and grants MFA
            if ($includeUsers -contains 'All' -and $grants -contains 'mfa') {
                $hasMfaAll = $true
            }

            # Block legacy auth: targets legacy client types with a block control
            $legacyTypes = @('exchangeActiveSync', 'other')
            $targetsLegacy = @($legacyTypes | Where-Object { $clientTypes -contains $_ }).Count -gt 0
            if ($targetsLegacy -and $isBlock) {
                $hasBlockLegacy = $true
            }

            # Sign-in risk policy
            if ($p.conditions.signInRiskLevels -and @($p.conditions.signInRiskLevels).Count -gt 0) {
                $hasSignInRisk = $true
            }

            # User risk policy
            if ($p.conditions.userRiskLevels -and @($p.conditions.userRiskLevels).Count -gt 0) {
                $hasUserRisk = $true
            }
        }

        @{
            'Entra.ConditionalAccess.EnabledPolicyCount'   = [int]$enabled.Count
            'Entra.ConditionalAccess.HasMfaAllUsers'       = [string]$hasMfaAll
            'Entra.ConditionalAccess.HasBlockLegacyAuth'   = [string]$hasBlockLegacy
            'Entra.ConditionalAccess.HasSignInRiskPolicy'  = [string]$hasSignInRisk
            'Entra.ConditionalAccess.HasUserRiskPolicy'    = [string]$hasUserRisk
        }
    }

    # ---------------------------------------------------------------------- Authorization Policy
    & $collect @('Entra.GuestAccess.UserRoleLevel',
                 'Entra.GuestAccess.AllowInvitesFrom',
                 'Entra.Users.AllowedToCreateTenants',
                 'Entra.Users.AllowedToCreateApps',
                 'Entra.Users.LegacyConsentPolicyAssigned') {
        $authPolicy = & $azRest "$graphBase/policies/authorizationPolicy"

        # guestUserRoleId GUID -> access level integer (0=Restricted, 1=Limited, 2=Full)
        $guestGuid = [string]$authPolicy.guestUserRoleId
        $level = if ($guestRoleMap.ContainsKey($guestGuid)) { $guestRoleMap[$guestGuid] } else { 2 }

        # Legacy consent policy: true if the broad legacy policy is assigned
        $consentPolicies = @(if ($authPolicy.permissionGrantPoliciesAssigned) {
            $authPolicy.permissionGrantPoliciesAssigned } else { @() })
        $legacyConsent = $consentPolicies -contains 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy-policy'

        $userPerms = $authPolicy.defaultUserRolePermissions
        @{
            'Entra.GuestAccess.UserRoleLevel'          = [int]$level
            'Entra.GuestAccess.AllowInvitesFrom'       = [string]$authPolicy.allowInvitesFrom
            'Entra.Users.AllowedToCreateTenants'       = [string]([bool]$userPerms.allowedToCreateTenants)
            'Entra.Users.AllowedToCreateApps'          = [string]([bool]$userPerms.allowedToCreateApps)
            'Entra.Users.LegacyConsentPolicyAssigned'  = [string]$legacyConsent
        }
    }

    # ---------------------------------------------------------------------- Global Administrators
    & $collect @('Entra.GlobalAdmin.UserCount', 'Entra.GlobalAdmin.ExternalUserCount') {
        $uri = "$graphBase/directoryRoles?`$filter=roleTemplateId eq '$gaRoleId'"
        $roles = (& $azRest $uri).value
        if (-not $roles -or $roles.Count -eq 0) {
            return @{
                'Entra.GlobalAdmin.UserCount'         = 0
                'Entra.GlobalAdmin.ExternalUserCount' = 0
            }
        }
        $roleId = [string]$roles[0].id
        $members = (& $azRest "$graphBase/directoryRoles/$roleId/members").value
        $userMembers = @($members | Where-Object {
            $_.'@odata.type' -eq '#microsoft.graph.user' -or
            -not $_.'@odata.type'
        })
        $external = @($userMembers | Where-Object {
            [string]$_.userType -eq 'Guest' -or [string]$_.userPrincipalName -match '#EXT#'
        })
        @{
            'Entra.GlobalAdmin.UserCount'         = [int]$userMembers.Count
            'Entra.GlobalAdmin.ExternalUserCount' = [int]$external.Count
        }
    }

    # ---------------------------------------------------------------------- PIM eligible assignments
    & $collect @('Entra.PIM.EligibleAssignmentCount') {
        $resp = & $azRest "$graphBase/roleManagement/directory/roleEligibilityScheduleInstances"
        [int](@($resp.value)).Count
    }

    # ---------------------------------------------------------------------- PIM Global Admin policy settings
    & $collect @('Entra.PIM.GlobalAdmin.RequireMfaOnActivation',
                 'Entra.PIM.GlobalAdmin.RequireJustificationOnActivation',
                 'Entra.PIM.GlobalAdmin.RequireApprovalOnActivation') {
        # Get role management policy assignments for GA scope
        $uri = "$graphBase/roleManagement/directory/roleManagementPolicyAssignments" +
               "?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'" +
               " and roleDefinitionId eq '$gaRoleId'" +
               "&`$expand=policy(`$expand=rules)"
        $assignments = (& $azRest $uri).value

        if (-not $assignments -or $assignments.Count -eq 0) {
            throw "No PIM policy assignment found for Global Administrator role (role may not be managed by PIM or requires P2 license)"
        }

        $policy = $assignments[0].policy
        $enablementRule = @($policy.rules | Where-Object { $_.id -eq 'Enablement_EndUser_Assignment' })
        $approvalRule   = @($policy.rules | Where-Object { $_.id -eq 'Approval_EndUser_Assignment' })

        $requireMfa  = $false
        $requireJust = $false
        $requireAppr = $false

        if ($enablementRule.Count -gt 0) {
            $enabled = @($enablementRule[0].enabledRules)
            $requireMfa  = $enabled -contains 'MultiFactorAuthentication'
            $requireJust = $enabled -contains 'Justification'
        }
        if ($approvalRule.Count -gt 0) {
            $requireAppr = [bool]$approvalRule[0].setting.isApprovalRequired
        }

        @{
            'Entra.PIM.GlobalAdmin.RequireMfaOnActivation'           = [string]$requireMfa
            'Entra.PIM.GlobalAdmin.RequireJustificationOnActivation'  = [string]$requireJust
            'Entra.PIM.GlobalAdmin.RequireApprovalOnActivation'       = [string]$requireAppr
        }
    }

    return [PSCustomObject]@{
        Facts  = $facts
        Errors = $errors
        Meta   = $meta
    }
}

Export-ModuleMember -Function Import-AzurePostureCatalog, Format-AzurePostureExpect,
    Get-AzurePostureFrameworkList, Invoke-AzurePostureCheck, Get-AzurePostureContext

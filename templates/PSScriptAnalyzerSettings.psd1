@{
    # https://github.com/PowerShell/PSScriptAnalyzer
    # Default rules stay on (incl. PSAvoidUsingCmdletAliases, PSAvoidUsingPlainTextForPassword,
    # PSUseDeclaredVarsMoreThanAssignments, PSUseSingularNouns, PSUseApprovedVerbs,
    # PSAvoidUsingInvokeExpression, PSAvoidUsingConvertToSecureStringWithPlainText).
    IncludeDefaultRules = $true
    Severity            = @('Error', 'Warning')

    # Write-Host is permitted ONLY inside Write-Log / logging helpers (Script Standard §5.1).
    # Excluding the rule means reviewers/gate must enforce that restriction.
    ExcludeRules        = @('PSAvoidUsingWriteHost')

    Rules = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.2')
        }
    }

    CustomRulePath = @(
        # Path to custom rules if written
    )
}

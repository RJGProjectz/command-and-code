# Script Contract Test Suite (Pester v5)
# Applies the GOLDEN_STANDARDS script contract to every script in scripts/powershell:
# parses cleanly, ASCII-only, has .EXAMPLE help, exposes a non-mandatory
# TargetEnvironment ('Test'/'Prod', default 'Test') that the script reads, and -
# for scripts with a Test-mode gate - makes no live calls when run in Test.

BeforeDiscovery {
    $scriptRoot = Join-Path $PSScriptRoot '../../scripts/powershell'
    $scripts = foreach ($file in Get-ChildItem -Path $scriptRoot -Filter '*.ps1' | Sort-Object Name) {
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$parseErrors)

        # A Test gate is an `if` whose condition compares $TargetEnvironment to 'Test' and whose body returns.
        $gate = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.IfStatementAst] -and
            $node.Clauses[0].Item1.Extent.Text -match '\$TargetEnvironment\s+-eq\s+[''"]Test[''"]' -and
            $node.Clauses[0].Item2.Extent.Text -match '\breturn\b'
        }, $true)

        @{ Name = $file.Name; Path = $file.FullName; HasTestGate = [bool]$gate }
    }
    $gatedScripts = @($scripts | Where-Object { $_.HasTestGate })
}

Describe 'Script contract: <Name>' -ForEach $scripts {

    BeforeAll {
        $tokens = $null
        $parseErrors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)
        $targetEnvParam = if ($ast.ParamBlock) {
            $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'TargetEnvironment' }
        }
    }

    It 'parses without errors' {
        $parseErrors | Should -BeNullOrEmpty
    }

    It 'does not put statements before begin/process/end blocks' {
        # With any statement in front, PowerShell runs `process { }` as a command named "process".
        $strayBlocks = @($ast.EndBlock.Statements | Where-Object {
            $_ -is [System.Management.Automation.Language.PipelineAst] -and
            $_.PipelineElements[0] -is [System.Management.Automation.Language.CommandAst] -and
            $_.PipelineElements[0].GetCommandName() -in @('begin', 'process', 'end')
        })
        $strayBlocks | Should -BeNullOrEmpty
    }

    It 'is ASCII-only (Windows PowerShell 5.1 reads it without a BOM)' {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
    }

    It 'has comment-based help with at least one .EXAMPLE' {
        $help = $ast.GetHelpContent()
        $help | Should -Not -BeNullOrEmpty
        $help.Examples.Count | Should -BeGreaterThan 0
    }

    It 'declares TargetEnvironment restricted to Test/Prod' {
        $targetEnvParam | Should -Not -BeNullOrEmpty
        $validateSet = $targetEnvParam.Attributes | Where-Object { $_.TypeName.Name -eq 'ValidateSet' }
        @($validateSet.PositionalArguments.Value) | Should -Be @('Test', 'Prod')
    }

    It "defaults TargetEnvironment to 'Test' and does not make it mandatory" {
        $targetEnvParam.DefaultValue.Value | Should -Be 'Test'
        $mandatory = $targetEnvParam.Attributes.NamedArguments |
            Where-Object { $_.ArgumentName -eq 'Mandatory' -and $_.Argument.Extent.Text -eq '$true' }
        $mandatory | Should -BeNullOrEmpty
    }

    It 'reads TargetEnvironment in the script body' {
        $references = $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.VariableExpressionAst] -and
            $node.VariablePath.UserPath -eq 'TargetEnvironment'
        }, $true)
        # One reference is the parameter declaration itself.
        @($references).Count | Should -BeGreaterThan 1
    }
}

Describe 'Test mode makes no live calls: <Name>' -ForEach $gatedScripts {

    BeforeAll {
        $command = Get-Command -Name $Path
        $arguments = @{ TargetEnvironment = 'Test' }
        $unsupported = @()
        foreach ($parameter in $command.Parameters.Values) {
            $isMandatory = $parameter.Attributes | Where-Object {
                $_ -is [System.Management.Automation.ParameterAttribute] -and $_.Mandatory
            }
            if (-not $isMandatory -or $parameter.Name -eq 'TargetEnvironment') { continue }

            $validateSet = $parameter.Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
            $arguments[$parameter.Name] = switch ($parameter.ParameterType) {
                { $validateSet } { $validateSet.ValidValues[0]; break }
                ([string])       { 'contract-test'; break }
                ([string[]])     { @('contract-test'); break }
                ([int])          { 1; break }
                ([int[]])        { @(1); break }
                ([securestring]) { [securestring]::new(); break }
                ([switch])       { $true; break }
                default          { $unsupported += "$($parameter.Name) [$($parameter.ParameterType.Name)]"; $null }
            }
        }

        $liveCommands = @('Invoke-RestMethod', 'Invoke-WebRequest', 'Invoke-Command', 'Remove-Item') |
            Where-Object { Get-Command -Name $_ -ErrorAction SilentlyContinue }
        foreach ($liveCommand in $liveCommands) {
            Mock -CommandName $liveCommand -MockWith { throw "Live call made in Test mode" }
        }
    }

    It 'runs in Test mode without making live calls' {
        if ($unsupported) { Set-ItResult -Skipped -Because "no dummy value for mandatory $($unsupported -join ', ')" }

        { & $Path @arguments *> $null } | Should -Not -Throw
        foreach ($liveCommand in $liveCommands) {
            Should -Invoke -CommandName $liveCommand -Times 0 -Exactly
        }
    }
}

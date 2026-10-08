<#
.SYNOPSIS
Command & Code Terminal Companion CLI Wrapper (PowerShell)
#>
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
)

$CliScript = Join-Path $PSScriptRoot "cc_cli.py"
& python $CliScript @Arguments

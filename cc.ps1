<#
.SYNOPSIS
Command & Code Terminal Companion CLI Wrapper (PowerShell Root)
#>
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
)

$CliScript = Join-Path $PSScriptRoot "tools/cc_cli.py"
& python $CliScript @Arguments

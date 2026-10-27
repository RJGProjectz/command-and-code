<#
.SYNOPSIS
    Retrieves posture-audit report files (and bundles) from one or more audited assets back to the
    worker running this script, over SMB, SSH/SCP or a local/mounted path. Pull-only and read-only:
    it NEVER executes anything on the endpoint and uses NO PowerShell remoting, New-PSSession or WinRM.

.DESCRIPTION
    Script Name   : Collect-PostureReports.ps1
    Purpose       : The worker-side half of the WP-97 posture-audit retrieval flow. After each asset
                    has run its audit (and optionally Export-PostureBundle.ps1) locally, the operator
                    runs this from a jumpstation or laptop to copy the resulting files back. The owner
                    requires ZERO dependency on PSRemoting/WinRM, so retrieval is a plain file copy:
                    an SMB admin-share read, an scp.exe pull, or a copy from a mounted/redirected/USB
                    path. Files land under <Destination>\<asset>\ so each asset's evidence stays
                    separate.
    Inputs        : -Asset list, a -Method and a -RemotePath template describing where the reports
                    live on each asset.
    Outputs       : Matching report files copied into <Destination>\<asset>\. Per-asset copy counts
                    are logged; unreachable assets are warned about and skipped.
    Security      : Security Domain: Compliance / Hardening. Read-only with respect to the endpoints:
                    it only reads/copies files FROM them (Copy-Item / scp.exe download). It never
                    runs code on an endpoint and deliberately avoids Invoke-Command, New-PSSession and
                    all WinRM. SMB credentials, when supplied, are used only to mount the share via
                    New-PSDrive and are never written out.
    Author        : RJGProjectz
    Version       : 1.0.0
    Created       : 2026-10-26T00:00:00Z
    Last Modified : 2026-10-26T00:00:00Z
    KB Article    : docs/tasks/assurance/posture-audit-lab-test.md

.PARAMETER TargetEnvironment
    'Test' (default) or 'Prod'. The copy behaves the same in both; recorded in the run log.

.PARAMETER Asset
    One or more asset names/hosts to pull reports from. For -Method Local, any label works (used as
    the per-asset sub-folder name).

.PARAMETER Method
    How to reach the reports: 'Smb' (admin share / UNC, optionally with -Credential), 'Scp'
    (scp.exe over SSH, with -SshUser) or 'Local' (a mounted drive, redirected folder or USB path).

.PARAMETER RemotePath
    Where the reports live on the asset. The literal token {asset} is replaced with the asset name,
    so one template serves every asset. By method:
      Smb   - a share/UNC tail, e.g. 'C$\Tools\PostureAudit\scripts\powershell' (becomes \\<asset>\<tail>)
      Scp   - a remote path, e.g. '/opt/postureaudit' or 'C:/Tools/PostureAudit'
      Local - a mounted/redirected/USB path, e.g. 'E:\' or '\\nas\evidence\{asset}'

.PARAMETER Destination
    Root folder for retrieved evidence. Default: .\posture-evidence. Files go to <Destination>\<asset>\.

.PARAMETER Pattern
    Filename patterns to copy. Default: posture-bundle-*, posture-*, adposture-*, cis-*.

.PARAMETER Credential
    SMB credential for -Method Smb. Used only to mount the share with New-PSDrive.

.PARAMETER SshUser
    SSH username for -Method Scp (the scp source becomes <SshUser>@<asset>:<RemotePath>/<pattern>).

.EXAMPLE
    # Pull from two Windows member servers over the admin share
    .\Collect-PostureReports.ps1 -Asset SRV01,SRV02 -Method Smb -RemotePath 'C$\Tools\PostureAudit\scripts\powershell'
.EXAMPLE
    # Pull from a Linux-managed host over SSH/SCP
    .\Collect-PostureReports.ps1 -Asset dc01.lab.local -Method Scp -SshUser labadmin -RemotePath '/opt/postureaudit'
.EXAMPLE
    # Copy from a USB drive after an air-gapped transfer
    .\Collect-PostureReports.ps1 -Asset WKSTN07 -Method Local -RemotePath 'E:\'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Test', 'Prod')]
    [string]$TargetEnvironment = 'Test',

    [Parameter(Mandatory = $true)]
    [string[]]$Asset,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Smb', 'Scp', 'Local')]
    [string]$Method = 'Smb',

    [Parameter(Mandatory = $true)]
    [string]$RemotePath,

    [Parameter(Mandatory = $false)]
    [string]$Destination = '.\posture-evidence',

    [Parameter(Mandatory = $false)]
    [string[]]$Pattern = @('posture-bundle-*', 'posture-*', 'adposture-*', 'cis-*'),

    [Parameter(Mandatory = $false)]
    [System.Management.Automation.PSCredential]$Credential,

    [Parameter(Mandatory = $false)]
    [string]$SshUser
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

function Write-CollectLog {
    # Console logging helper (the only place Write-Host is used, GOLDEN_STANDARDS section 5.1).
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO')
    $colors = @{ INFO = 'Cyan'; WARN = 'Yellow'; ERROR = 'Red' }
    Write-Host "[$Level] $Message" -ForegroundColor $colors[$Level]
}

function Copy-MatchingFile {
    # Copies every file under $Root matching any pattern into $AssetDest, de-duplicated. Returns the
    # count copied. Read-only against the source: it only reads and copies, never deletes or executes.
    param([string]$Root, [string[]]$Patterns, [string]$AssetDest)
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $count = 0
    foreach ($pat in $Patterns) {
        $found = @(Get-ChildItem -Path $Root -Filter $pat -File -ErrorAction SilentlyContinue)
        foreach ($item in $found) {
            if (-not $seen.Add($item.FullName)) { continue }
            Copy-Item -LiteralPath $item.FullName -Destination $AssetDest -Force
            $count++
        }
    }
    return $count
}

if ($Method -eq 'Scp' -and -not $SshUser) {
    throw "-SshUser is required for -Method Scp."
}

Write-CollectLog "Posture report collection - method $Method - $TargetEnvironment - $(@($Asset).Count) asset(s)"
Write-Verbose "Mode: $TargetEnvironment (read-only pull; no remoting, no code execution on endpoints)"

if (-not (Test-Path -LiteralPath $Destination)) { $null = New-Item -ItemType Directory -Path $Destination }
$destRoot = (Resolve-Path -LiteralPath $Destination).Path

$results = foreach ($asset in $Asset) {
    $assetDest = Join-Path $destRoot $asset
    if (-not (Test-Path -LiteralPath $assetDest)) { $null = New-Item -ItemType Directory -Path $assetDest }
    $resolvedRemote = $RemotePath.Replace('{asset}', $asset)
    $copied = 0
    $status = 'ok'

    try {
        switch ($Method) {
            'Local' {
                if (-not (Test-Path -LiteralPath $resolvedRemote)) {
                    Write-CollectLog "Asset '$asset': path '$resolvedRemote' not reachable - skipping." 'WARN'
                    $status = 'unreachable'
                }
                else {
                    $copied = Copy-MatchingFile -Root $resolvedRemote -Patterns $Pattern -AssetDest $assetDest
                }
            }
            'Smb' {
                $unc = if ($resolvedRemote -like '\\*') { $resolvedRemote } else { "\\$asset\$resolvedRemote" }
                $driveName = $null
                try {
                    $searchRoot = $unc
                    if ($Credential) {
                        $driveName = 'CC' + ([guid]::NewGuid().ToString('N').Substring(0, 8))
                        $null = New-PSDrive -Name $driveName -PSProvider FileSystem -Root $unc -Credential $Credential -ErrorAction Stop
                        $searchRoot = "${driveName}:\"
                    }
                    if (-not (Test-Path -LiteralPath $searchRoot)) {
                        Write-CollectLog "Asset '$asset': share '$unc' not reachable - skipping." 'WARN'
                        $status = 'unreachable'
                    }
                    else {
                        $copied = Copy-MatchingFile -Root $searchRoot -Patterns $Pattern -AssetDest $assetDest
                    }
                }
                finally {
                    if ($driveName -and (Get-PSDrive -Name $driveName -ErrorAction SilentlyContinue)) {
                        Remove-PSDrive -Name $driveName -Force -ErrorAction SilentlyContinue
                    }
                }
            }
            'Scp' {
                $scp = Get-Command -Name 'scp.exe' -ErrorAction SilentlyContinue
                if (-not $scp) { $scp = Get-Command -Name 'scp' -ErrorAction SilentlyContinue }
                if (-not $scp) {
                    throw "scp client not found on PATH (OpenSSH client required for -Method Scp)."
                }
                $remoteBase = $resolvedRemote.TrimEnd('/')
                foreach ($pat in $Pattern) {
                    $source = "{0}@{1}:{2}/{3}" -f $SshUser, $asset, $remoteBase, $pat
                    # scp exits non-zero when a glob matches nothing; that is expected, so tolerate it.
                    & $scp.Source -q -p $source $assetDest 2>$null
                }
                $copied = @(Get-ChildItem -Path $assetDest -File -ErrorAction SilentlyContinue).Count
            }
        }
    }
    catch {
        Write-CollectLog "Asset '$asset': $($_.Exception.Message)" 'ERROR'
        $status = 'error'
    }

    if ($status -eq 'ok') {
        Write-CollectLog "Asset '$asset': $copied file(s) -> $assetDest"
    }
    [PSCustomObject]@{
        Asset       = $asset
        Method      = $Method
        Status      = $status
        FilesCopied = $copied
        Destination = $assetDest
    }
}

$results = @($results)
$totalFiles = ($results | Measure-Object -Property FilesCopied -Sum).Sum
Write-CollectLog ("Done: {0} asset(s), {1} file(s) copied into {2}" -f $results.Count, $totalFiles, $destRoot)
$results

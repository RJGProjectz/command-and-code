<#
.SYNOPSIS
    Shows the ancestors and descendants of a process.
.DESCRIPTION
    Builds a process tree from Win32_Process. Parent links are only followed when the
    parent's creation time is earlier than the child's, which protects against PID reuse
    (a recycled PID would otherwise appear as a false parent). Read-only.
    Compatible with Windows PowerShell 5.1 and PowerShell 7 on Windows.
.PARAMETER ProcessId
    The process to centre the tree on.
.PARAMETER AsObject
    Output objects (Depth, Relation, ProcessId, ParentProcessId, Name, CreationDate,
    ExecutablePath, CommandLine) instead of an indented text tree.
.EXAMPLE
    .\Get-ProcessTree.ps1 -ProcessId 4321
.EXAMPLE
    .\Get-ProcessTree.ps1 -ProcessId 4321 -AsObject | Export-Csv tree.csv -NoTypeInformation
.NOTES
    Part of Command & Code.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [int]$ProcessId,

    [switch]$AsObject
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$all = Get-CimInstance -ClassName Win32_Process
$byId = @{}
foreach ($p in $all) { $byId[[int]$p.ProcessId] = $p }

if (-not $byId.ContainsKey($ProcessId)) {
    throw "Process $ProcessId is not running."
}

function Test-IsRealParent {
    param($Parent, $Child)
    if (-not $Parent -or -not $Child) { return $false }
    if ($Parent.ProcessId -eq $Child.ProcessId) { return $false }
    if ($null -eq $Parent.CreationDate -or $null -eq $Child.CreationDate) { return $true }
    return $Parent.CreationDate -le $Child.CreationDate
}

function ConvertTo-TreeNode {
    param($Process, [int]$Depth, [string]$Relation)
    [pscustomobject]@{
        Depth           = $Depth
        Relation        = $Relation
        ProcessId       = [int]$Process.ProcessId
        ParentProcessId = [int]$Process.ParentProcessId
        Name            = $Process.Name
        CreationDate    = $Process.CreationDate
        ExecutablePath  = $Process.ExecutablePath
        CommandLine     = $Process.CommandLine
    }
}

# Ancestors: walk up while the parent is genuinely older than the child.
$ancestors = [System.Collections.Generic.List[object]]::new()
$current = $byId[$ProcessId]
$seen = @{ $ProcessId = $true }
while ($true) {
    $parentId = [int]$current.ParentProcessId
    if ($seen.ContainsKey($parentId) -or -not $byId.ContainsKey($parentId)) { break }
    $parent = $byId[$parentId]
    if (-not (Test-IsRealParent -Parent $parent -Child $current)) { break }
    $ancestors.Insert(0, $parent)
    $seen[$parentId] = $true
    $current = $parent
}

$nodes = [System.Collections.Generic.List[object]]::new()
$depth = 0
foreach ($a in $ancestors) {
    $nodes.Add((ConvertTo-TreeNode -Process $a -Depth $depth -Relation 'Ancestor'))
    $depth++
}
$nodes.Add((ConvertTo-TreeNode -Process $byId[$ProcessId] -Depth $depth -Relation 'Target'))

# Descendants: depth-first, children must be newer than their parent.
$visited = @{ $ProcessId = $true }
function Add-DescendantNode {
    param($Parent, [int]$Depth)
    $children = $all | Where-Object {
        [int]$_.ParentProcessId -eq [int]$Parent.ProcessId -and (Test-IsRealParent -Parent $Parent -Child $_)
    } | Sort-Object CreationDate
    foreach ($child in $children) {
        if ($visited.ContainsKey([int]$child.ProcessId)) { continue }
        $visited[[int]$child.ProcessId] = $true
        $nodes.Add((ConvertTo-TreeNode -Process $child -Depth $Depth -Relation 'Descendant'))
        Add-DescendantNode -Parent $child -Depth ($Depth + 1)
    }
}
Add-DescendantNode -Parent $byId[$ProcessId] -Depth ($depth + 1)

if ($AsObject) {
    $nodes
} else {
    foreach ($n in $nodes) {
        $marker = if ($n.Relation -eq 'Target') { '>> ' } else { '   ' }
        '{0}{1}{2} [{3}]  {4}' -f $marker, ('  ' * $n.Depth), $n.Name, $n.ProcessId, $n.CommandLine
    }
}

<#
.SYNOPSIS
Retrieves active network connections from a Windows endpoint.

.DESCRIPTION
Script Name: FUNC_PS_GET_ENDPOINT_CONNECTIONS
This script acts as a wrapper around Get-NetTCPConnection and Get-Process to quickly 
correlate active TCP connections with their owning process names and PIDs. It normalizes 
the output into custom objects for easy sorting and pipeline consumption by other security tools.

.NOTES
    Security Domain: Operations
Purpose: Correlate active connections to processes during live triage.
Security Context: Identifying suspicious outbound connections to unknown infrastructure or unusual processes acting as servers prevents lateral movement and exfiltration.
Author: SecurityBrain
Version: 1.1
Date Created: 2026-03-14
Last Updated: 2026-03-14

.PARAMETER ProcessName
Filter the results to only show connections owned by a specific process name (e.g., "powershell"). Must be provided, or use '*' for all.

.EXAMPLE
.\FUNC_PS_GET_ENDPOINT_CONNECTIONS.ps1 -ProcessName "powershell"

.OUTPUTS
PSCustomObject containing LocalAddress, LocalPort, RemoteAddress, RemotePort, State, PID, ProcessName
#>

[CmdletBinding(DefaultParameterSetName="None")]
param (
    [Parameter(ParameterSetName="ByProcess", Mandatory=$true, HelpMessage="Enter process name to filter, or '*' for all")]
    [ValidateNotNullOrEmpty()]
    [string]$ProcessName
)

# Enforce brief help output if run without parameters
if ($PSCmdlet.ParameterSetName -eq "None") {
    Write-Warning "No parameters provided. You must specify -ProcessName. For detailed usage and examples, run with -h or -Help."
    return
}

try {
    Write-Verbose "Fetching active TCP connections..."
    $connections = Get-NetTCPConnection -State Established, Listen -ErrorAction Stop
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($conn in $connections) {
        $procName = "Unknown"
        if ($conn.OwningProcess -ne 0) {
            # Catch exceptions per process silently in case the process has already terminated
            try {
                $proc = Get-Process -Id $conn.OwningProcess -ErrorAction Stop
                if ($proc) {
                    $procName = $proc.Name
                }
            } catch {
                Write-Verbose "Could not resolve process name for PID $($conn.OwningProcess)"
            }
        }

        # Filter out connections that do not match the target process
        # We check this so we don't return irrelevant noise to the SOC analyst
        if ($procName -like "*$ProcessName*") {
            $results.Add([PSCustomObject] @{
                LocalAddress  = $conn.LocalAddress
                LocalPort     = $conn.LocalPort
                RemoteAddress = $conn.RemoteAddress
                RemotePort    = $conn.RemotePort
                State         = $conn.State
                PID           = $conn.OwningProcess
                ProcessName   = $procName
            })
        }
    }

    Write-Output ($results | Sort-Object RemoteAddress)

} catch {
    Write-Error "Failed to retrieve endpoint connections: $_"
}

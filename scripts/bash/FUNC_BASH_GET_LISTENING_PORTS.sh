#!/bin/bash
# ==========================================
# Script Name: FUNC_BASH_GET_LISTENING_PORTS
# Description: Wrapper to safely extract listening ports and bind them to process names across Linux distributions.
# Purpose: Post-exploitation analysis and beaconing investigation.
# Inputs: None. (Execution context must be root).
# Outputs: Structured CSV formatted string to standard output.
# Security Context: Identifies backdoors, C2 implants, or reverse shells bound to uncommon ports on critical servers.
# Author: RJGProjectz
# Version: 1.1
# Date Created: 2026-03-14
# Last Updated: 2026-03-14
# ==========================================

# Enable strict error handling and failing on pipes
set -euo pipefail

# Security Best Practice: Validate input/execution state
# Ensure the script is run as root for full process inspection without failing mid-execution.
if [ "$EUID" -ne 0 ]; then 
  >&2 echo "ERROR: Please run as root to resolve PIDs"
  exit 1
fi

get_listening_ports() {
    # Provide clear structured output (CSV) 
    echo "Protocol,LocalAddress,Port,PID,Process"
    
    # Execute ss and parse via safe loops.
    # Output is structured to ensure it can be easily ingested by AI or SIEM processing.
    while IFS=, read -r proto addr pid_info; do
        if [[ -n "$addr" && -n "$pid_info" ]]; then
            local port ip proc pid
            
            # Using grep/cut safely with quotes to extract ports and processes
            port=$(echo "$addr" | rev | cut -d: -f1 | rev)
            ip=$(echo "$addr" | rev | cut -d: -f2- | rev)
            
            # Fallback to "Unknown" if the process name is obfuscated or already closed
            proc=$(echo "$pid_info" | grep -o '("[^"]*"' | tr -d '"(' || echo "Unknown")
            pid=$(echo "$pid_info" | grep -o 'pid=[0-9]*' | cut -d= -f2 || echo "Unknown")
            
            echo "$proto,$ip,$port,$pid,$proc"
        fi
    done < <(ss -tulpn | tail -n +2 | awk '{print $1","$5","$7}')
}

# Invoke the main function
get_listening_ports

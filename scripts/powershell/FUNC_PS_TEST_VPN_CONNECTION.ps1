<#
.SYNOPSIS
    Diagnoses and optionally repairs common Virtual Private Network (VPN) issues, specifically for Global Protect.

.DESCRIPTION
    1. Checks the Global Protect Service (PanGPS) status.
    2. Verifies the existence and validity of Device and User certificates (using advanced Registry/FileSystem probing and LDAP resolution).
    3. Tests network reachability to specified Portal/Gateway addresses.
    4. Flushes DNS/NetBT and restarts networking components if -Repair is specified.

.PARAMETER Portal
    The FQDN of the VPN Portal (e.g., vpn.example.com).

.PARAMETER Repair
    Switch to allow automated service restarts and DNS flushes.

.PARAMETER DebugMode
    Enable verbose diagnostic logging for troubleshooting (e.g., SID probing, binary blob parsing, and LDAP template resolution).

.PARAMETER ApiKey
    Optional API Key for authenticated portal checks.

.PARAMETER TargetEnvironment
    Mandatory. Specifies the environment context for the diagnostics. Use 'Test' or 'Prod'.

.EXAMPLE
    .\Test-VpnConnection.ps1 -TargetEnvironment Prod
    Standard diagnostic run for the currently logged-on user. Default portal (vpn.example.com) is used.

.EXAMPLE
    .\Test-VpnConnection.ps1 -TargetEnvironment Prod -DebugMode
    Run with elevated diagnostic logging to troubleshoot certificate template mismatches or SID resolution issues.

.EXAMPLE
    .\Test-VpnConnection.ps1 -TargetEnvironment Prod -Repair -DebugMode -Portal "vpn.example.com"
    Comprehensive diagnostic and repair run. Restarts services, flushes DNS, and provides detailed LDAP-resolved certificate info.

.NOTES
    Security Domain: Network
    Created: 2026-01-16T14:40:00
    Last Modified: 2026-02-27T15:00:00
    Author: Antigravity
    KB Article: [KB-Net-001-VpnTroubleshooting.md](../../HowTo/Scripts/KB-Net-001-VpnTroubleshooting.md)
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$Portal = "vpn.example.com",

    [switch]$Repair,

    [switch]$DebugMode,

    [Parameter(Mandatory=$false)]
    [string]$ApiKey,

    [Parameter(Mandatory=$true)]
    [ValidateSet("Test", "Prod")]
    [string]$TargetEnvironment
)

function Get-CertificateFromRegistryBlob {
    <#
    .SYNOPSIS
        Parses a Microsoft SystemCertificates 'Blob' value and extracts the X509Certificate2 object.
    .DESCRIPTION
        Registry certificates in HKEY_USERS\<SID>\Software\Microsoft\SystemCertificates\My\Certificates
        are stored in a TLV (Type-Length-Value) format. Type 0x20 usually denotes the raw certificate data.
    #>
    param([byte[]]$Blob)
    
    if (-not $Blob -or $Blob.Length -lt 8) { return $null }
    
    $offset = 0
    while ($offset -lt $Blob.Length) {
        $type = [BitConverter]::ToUInt32($Blob, $offset)
        $length = [BitConverter]::ToUInt32($Blob, $offset + 8)
        $valueOffset = $offset + 12
        
        if ($type -eq 0x20) { # CERT_VALUE_TYPE (Raw Certificate)
            try {
                $certData = New-Object byte[] $length
                [Buffer]::BlockCopy($Blob, $valueOffset, $certData, 0, $length)
                return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$certData)
            } catch {
                return $null
            }
        }
        $offset += 12 + $length
    }
    return $null
}

function Get-CertificateTemplate {
    <#
    .SYNOPSIS
        Resolves the Certificate Template name or display name from a certificate extension.
    .DESCRIPTION
        Handles both friendly names and OID-based template references by resolving them via LDAP if necessary.
    #>
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)
    
    $TemplateName = "Unknown"
    # OIDs for Certificate Template Name (1.3.6.1.4.1.311.20.2) and Template Information (1.3.6.1.4.1.311.21.7)
    $Extension = $Cert.Extensions | Where-Object { $_.Oid.Value -eq "1.3.6.1.4.1.311.21.7" -or $_.Oid.Value -eq "1.3.6.1.4.1.311.20.2" }
    
    if (-not $Extension) { return "None" }

    $fmt = $Extension.Format(0)
    # Case 1: Format shows "Template=Name(OID)"
    if ($fmt -match "Template=([^\(]+?)\s*\(") { 
        $TemplateName = $Matches[1].Trim() 
    }
    # Case 2: Format shows "Template=OID" (Common when template name isn't locally cached)
    elseif ($fmt -match "Template=([0-9\.]+)") {
        $oid = $Matches[1]
        $TemplateName = $oid
        try {
            $rootDSE = [ADSI]"LDAP://RootDSE"
            $searchRoot = "LDAP://CN=Certificate Templates,CN=Public Key Services,CN=Services,$($rootDSE.configurationNamingContext)"
            $searcher = [adsisearcher]"(&(objectClass=pKICertificateTemplate)(msPKI-Cert-Template-OID=$oid))"
            $searcher.SearchRoot = $searchRoot; $searcher.ClientTimeout = [TimeSpan]::FromSeconds(2)
            $res = $searcher.FindOne()
            if ($res) { 
                $TemplateName = "$($res.Properties['cn']), $($res.Properties['displayname'])" 
            }
        } catch { }
    }
    else {
        # Fallback for simple string formats
        $TemplateName = $fmt
    }
    
    return $TemplateName
}

Write-Host "--- VPN Diagnostic Tool for Global Protect ---" -ForegroundColor Cyan
Write-Host "Target Environment: $TargetEnvironment"

$GPServiceName = "PanGPS"
$Diagnostics = @{
    ServiceStatus  = "NOT CHECKED"
    DeviceCert     = "NOT CHECKED"
    UserCert       = "NOT CHECKED"
    TcpPortSuccess = "NOT CHECKED"
}

# 1. Service Check
Write-Host "[*] Checking Global Protect Service ($GPServiceName)..." -NoNewline
$GPService = Get-Service -Name $GPServiceName -ErrorAction SilentlyContinue
if ($GPService) {
    if ($GPService.Status -eq 'Running') {
        Write-Host " [OK]" -ForegroundColor Green
        $Diagnostics.ServiceStatus = "Running"
    } else {
        Write-Host " [FAIL] Status: $($GPService.Status)" -ForegroundColor Red
        $Diagnostics.ServiceStatus = $GPService.Status
    }
} else {
    Write-Host " [FAIL] Service not found." -ForegroundColor Red
    $Diagnostics.ServiceStatus = "NOT REGISTERED"
}

# 2. Certificate Check (Enhanced Logic)
$ClientAuthOID = "1.3.6.1.5.5.7.3.2"
$DeviceCertTemplate = "Enterprise Computer SHA2 - Wi-Fi"
$UserCertTemplate = "Enterprise User SHA2 - Wi-Fi"

Write-Host "[*] Checking Device Certificate..." -NoNewline
$DeviceCerts = Get-ChildItem Cert:\LocalMachine\My | Where-Object { 
    $_.Subject -match "$($env:COMPUTERNAME)" -and 
    $_.HasPrivateKey -and 
    ($_.EnhancedKeyUsageList.ObjectId -contains $ClientAuthOID) -and
    $_.NotBefore -le (Get-Date) -and 
    $_.NotAfter -ge (Get-Date) 
}

# Tighten Device Cert Validation: Require specific template
if ($DeviceCerts) {
    $DeviceCerts = $DeviceCerts | Where-Object {
        $ResolvedTemplate = Get-CertificateTemplate -Cert $_
        $ResolvedTemplate -match [regex]::Escape($DeviceCertTemplate)
    }
}

if ($DeviceCerts) {
    Write-Host " [OK] Found valid device certificate ($($DeviceCerts[0].Thumbprint))." -ForegroundColor Green
    $Diagnostics.DeviceCert = "VALID"
} else {
    Write-Host " [FAIL] Device certificate check failed!" -ForegroundColor Red
    Write-Host " [!] ALERT: No valid system-level cert with Template '$DeviceCertTemplate' found." -ForegroundColor Yellow
    $Diagnostics.DeviceCert = "MISSING/EXPIRED/WRONG-TEMPLATE"
}

Write-Host "[*] Checking User Certificate..." -NoNewline
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$CurrentUserSID = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value

# Identify Logged-on user (Console)
$LoggedOnUser = Get-CimInstance Win32_ComputerSystem | Select-Object -ExpandProperty UserName
$TargetSID = $CurrentUserSID
$ContextWarning = ""

if ($IsAdmin -and $LoggedOnUser) {
    try {
        $TargetSID = (New-Object System.Security.Principal.NTAccount($LoggedOnUser)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        if ($TargetSID -ne $CurrentUserSID) {
            $ContextWarning = " (Probing store for logged-on user: $LoggedOnUser)"
            if ($DebugMode) { Write-Host " [DEBUG] Current SID: $CurrentUserSID, Target SID: $TargetSID" -ForegroundColor Gray }
        }
    } catch {
        # Fallback to current process user if translation fails
    }
}

$UserCerts = @()
if ($TargetSID -eq $CurrentUserSID) {
    # Standard check for current process user
    $UserCerts = Get-ChildItem Cert:\CurrentUser\My | Where-Object { 
        $_.HasPrivateKey -and 
        ($_.EnhancedKeyUsageList.ObjectId -contains $ClientAuthOID) -and
        $_.NotBefore -le (Get-Date) -and 
        $_.NotAfter -ge (Get-Date)
    }

    # Tighten validation: Require specific User VPN template
    if ($UserCerts) {
        $UserCerts = $UserCerts | Where-Object {
            $ResolvedTemplate = Get-CertificateTemplate -Cert $_
            $ResolvedTemplate -match [regex]::Escape($UserCertTemplate)
        }
    }
    
    if ($DebugMode -and $UserCerts) {
        foreach ($cert in $UserCerts) {
            $TemplateName = Get-CertificateTemplate -Cert $cert
            Write-Host " [DEBUG] Provider Match found:" -ForegroundColor Gray
            Write-Host "         - Template: $TemplateName" -ForegroundColor Gray
            Write-Host "         - Subject: $($cert.Subject)" -ForegroundColor Gray
            Write-Host "         - Thumbprint: $($cert.Thumbprint)" -ForegroundColor Gray
            Write-Host "         - Expires: $($cert.NotAfter)" -ForegroundColor Gray
        }
    }
} else {
    # Running as Admin but target is a different user - Enhanced Probe
    # 1. Registry Probe (Standard for many environments)
    $BaseRegPath = "Registry::HKEY_USERS\$TargetSID\Software\Microsoft\SystemCertificates"
    $StoreNames = @("My", "MY")
    
    foreach ($StoreName in $StoreNames) {
        $RegPath = Join-Path $BaseRegPath "$StoreName\Certificates"
        if (Test-Path $RegPath) {
            $RegKeys = Get-ChildItem $RegPath
            foreach ($Key in $RegKeys) {
                $Blob = Get-ItemPropertyValue -Path $Key.PSPath -Name "Blob" -ErrorAction SilentlyContinue
                if ($Blob) {
                    $ParsedCert = Get-CertificateFromRegistryBlob -Blob $Blob
                    if ($ParsedCert) {
                        # Resolve Template Name
                        $TemplateName = Get-CertificateTemplate -Cert $ParsedCert

                        # Validation
                        $IsExpired = ($ParsedCert.NotBefore -gt (Get-Date) -or $ParsedCert.NotAfter -lt (Get-Date))
                        $HasClientAuth = $false
                        try {
                            if ($ParsedCert.EnhancedKeyUsageList.ObjectId -contains $ClientAuthOID) { $HasClientAuth = $true }
                        } catch {
                            foreach ($ext in $ParsedCert.Extensions) {
                                if ($ext.Oid.Value -eq "2.5.29.37" -and ($ext.Format(0) -match $ClientAuthOID -or $ext.Format(0) -match "Client Authentication")) {
                                    $HasClientAuth = $true; break
                                }
                            }
                        }
                        
                        $IsVpnTemplate = ($TemplateName -match [regex]::Escape($UserCertTemplate))

                        if ($IsVpnTemplate -and $HasClientAuth -and -not $IsExpired) {
                            $UserCerts += $ParsedCert
                            if ($DebugMode) { 
                                Write-Host " [DEBUG] Registry Match found:" -ForegroundColor Gray
                                Write-Host "         - Template: $TemplateName" -ForegroundColor Gray
                                Write-Host "         - Subject: $($ParsedCert.Subject)" -ForegroundColor Gray
                                Write-Host "         - Thumbprint: $($ParsedCert.Thumbprint)" -ForegroundColor Gray
                                Write-Host "         - Expires: $($ParsedCert.NotAfter)" -ForegroundColor Gray
                            }
                        }
                    }
                }
            }
            if ($DebugMode -and $UserCerts.Count -eq 0 -and $RegKeys.Count -gt 0) {
                Write-Host " [DEBUG] Registry Store '$StoreName' found but no certs matching '$UserCertTemplate' found." -ForegroundColor Gray
            }
        } elseif ($DebugMode) {
             Write-Host " [DEBUG] Registry path not found: $RegPath" -ForegroundColor Gray
        }
        if ($UserCerts.Count -gt 0) { break }
    }

    # 2. FileSystem Probe Fallback (Common for some user profiles/modern Windows)
    if ($UserCerts.Count -eq 0) {
        $UserAccount = New-Object System.Security.Principal.SecurityIdentifier($TargetSID)
        $UserNameOnly = $UserAccount.Translate([System.Security.Principal.NTAccount]).Value.Split('\')[-1]
        $UserProfilePath = "C:\Users\$UserNameOnly\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates"
        
        if (Test-Path $UserProfilePath) {
            $CertFiles = Get-ChildItem -Path $UserProfilePath -File
            foreach ($File in $CertFiles) {
                try {
                    $Blob = [System.IO.File]::ReadAllBytes($File.FullName)
                    $ParsedCert = Get-CertificateFromRegistryBlob -Blob $Blob
                    if ($ParsedCert) {
                        # Resolve Template Name
                        $TemplateName = Get-CertificateTemplate -Cert $ParsedCert

                        # Validation
                        $IsExpired = ($ParsedCert.NotBefore -gt (Get-Date) -or $ParsedCert.NotAfter -lt (Get-Date))
                        $HasClientAuth = $false
                        try {
                            if ($ParsedCert.EnhancedKeyUsageList.ObjectId -contains $ClientAuthOID) { $HasClientAuth = $true }
                        } catch {
                            foreach ($ext in $ParsedCert.Extensions) {
                                if ($ext.Oid.Value -eq "2.5.29.37" -and ($ext.Format(0) -match $ClientAuthOID -or $ext.Format(0) -match "Client Authentication")) {
                                    $HasClientAuth = $true; break
                                }
                            }
                        }

                        $IsVpnTemplate = ($TemplateName -match [regex]::Escape($UserCertTemplate))

                        if ($IsVpnTemplate -and $HasClientAuth -and -not $IsExpired) {
                            $UserCerts += $ParsedCert
                            if ($DebugMode) { 
                                Write-Host " [DEBUG] File Match found:" -ForegroundColor Gray
                                Write-Host "         - Template: $TemplateName" -ForegroundColor Gray
                                Write-Host "         - Subject: $($ParsedCert.Subject)" -ForegroundColor Gray
                                Write-Host "         - Thumbprint: $($ParsedCert.Thumbprint)" -ForegroundColor Gray
                                Write-Host "         - Expires: $($ParsedCert.NotAfter)" -ForegroundColor Gray
                            }
                        }
                    }
                } catch { }
            }
            if ($DebugMode -and $UserCerts.Count -eq 0 -and $CertFiles.Count -gt 0) {
                Write-Host " [DEBUG] File System folder found but no certs matching '$UserCertTemplate' found." -ForegroundColor Gray
            }
        } elseif ($DebugMode) {
            Write-Host " [DEBUG] FileSystem path not found: $UserProfilePath" -ForegroundColor Gray
        }
    }
}

if ($UserCerts) {
    Write-Host " [OK] Found $(@($UserCerts).Count) valid cert(s)$ContextWarning." -ForegroundColor Green
    $Diagnostics.UserCert = "VALID"
} else {
    Write-Host " [FAIL] User certificate check failed!$ContextWarning" -ForegroundColor Red
    Write-Host " [!] ALERT: No valid user-level certificates found for Template '$UserCertTemplate'." -ForegroundColor Yellow
    $Diagnostics.UserCert = "MISSING/EXPIRED/WRONG-TEMPLATE"
}

# 3. Connectivity Check (TCP Only)
Write-Host "[*] Testing TCP Port 443 reachability to $Portal..." -NoNewline
$NetTest = Test-NetConnection -ComputerName $Portal -Port 443 -WarningAction SilentlyContinue
if ($NetTest.TcpTestSucceeded) {
    Write-Host " [OK] TcpTestSucceeded: True" -ForegroundColor Green
    $Diagnostics.TcpPortSuccess = "True"
} else {
    Write-Host " [FAIL] TcpTestSucceeded: False" -ForegroundColor Red
    $Diagnostics.TcpPortSuccess = "False"
}

# 4. Targetted Repair Actions
if ($Repair) {
    Write-Host "`n--- Performing Targeted Repair Actions ---" -ForegroundColor Yellow
    
    # Repair Service if failed
    if ($Diagnostics.ServiceStatus -ne "Running" -and $Diagnostics.ServiceStatus -ne "NOT REGISTERED") {
        Write-Host "[!] Attempting to restart $GPServiceName..."
        try { Start-Service -Name $GPServiceName -ErrorAction Stop; Write-Host " [OK] Restarted." -ForegroundColor Green }
        catch { Write-Host " [FAIL] Could not start service." -ForegroundColor Red }
    }

    # Repair Connectivity/DNS if TCP failed
    if ($Diagnostics.TcpPortSuccess -ne "True") {
        Write-Host "[!] Connectivity failed. Flushing DNS and Resetting NetBT..."
        ipconfig /flushdns | Out-Null
        nbtstat -R | Out-Null
        Write-Host " [OK] Caches flushed." -ForegroundColor Green
    }

    # Handle Certificate Failures (Notification Only)
    if ($Diagnostics.DeviceCert -ne "VALID" -or $Diagnostics.UserCert -ne "VALID") {
        Write-Host "[!] Certificate issues detected. Cannot repair via script." -ForegroundColor Yellow
        Write-Host "    REQUIRED: Please enroll in GPO or contact IT to push missing certificates." -ForegroundColor Gray
    }
}

Write-Host "`nDiagnostic Summary:" -ForegroundColor Cyan
$Diagnostics | Format-List

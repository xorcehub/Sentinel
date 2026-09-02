# scripts/install-sysmon.ps1
# Ensures Sysmon64 is installed with a config that emits the EIDs the Sentinel
# rules need (Phase 0 acceptance, 07-BUILD-PHASES.md). Idempotent: detects an
# existing install and updates the config rather than reinstalling.
#
# Base config: SwiftOnSecurity/sysmon-config (chosen in 02-ARCHITECTURE.md §5 /
# 07 Phase 0). The adaptations below are applied on top.
#
# REQUIRES: run as Administrator.

param(
    [string]$SysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip",
    [string]$ConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml",
    [string]$InstallDir = "$env:ProgramData\Sysmon"
)

$ErrorActionPreference = "Stop"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as Administrator."
}

# --- 1. locate or install sysmon64.exe ---
$sysmonExe = Join-Path $InstallDir "sysmon64.exe"
if (-not (Test-Path $sysmonExe)) {
    Write-Host "Installing Sysmon to $InstallDir ..."
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $zip = Join-Path $env:TEMP "sysmon.zip"
    Invoke-WebRequest -Uri $SysmonUrl -OutFile $zip
    Expand-Archive -Path $zip -DestinationPath $InstallDir -Force
    Remove-Item $zip
}

# --- 2. fetch base config ---
$configPath = Join-Path $InstallDir "sentinel-sysmon.xml"
Invoke-WebRequest -Uri $ConfigUrl -OutFile $configPath

# PATCH: SwiftOnSecurity's NetworkConnect EXCLUDE list drops DestinationIp
# 127.0.0.1 at the SOURCE, so loopback EID 3 never reaches Sentinel and
# NET-005 (the loopback-C2 gap-closer) plus known_loopback_listeners can
# never work - verified live 2026-09-01 (NET-005: zero alerts ever; an ::1
# connect arrived but 127.0.0.1 connects do not). Strip that one exclusion.
# Loopback noise this re-admits is bounded by NET-005's known_loopback_listeners
# except + 5m dedup and allowed_destinations (127/8, ::1/128) in
# config/allowlist.json - but expect extra toasts until dev ports are seeded
# (both "127.0.0.1:P" and "::1:P" spellings; Sysmon sends the expanded
# 0:0:0:0:0:0:0:1 form, which the loader canonicalizes).
$cfg = Get-Content $configPath -Raw
$patched = $cfg -replace '(?m)^\s*<DestinationIp condition="is">127\.0\.0\.1</DestinationIp>.*\r?\n', ''
if ($patched -eq $cfg) {
    # FAIL the install: this exact blindness persisted for months silently.
    # Upstream drifted - inspect manually, then widen/replace the pattern.
    throw "loopback exclude not found in upstream config - refusing to install blind (NET-005 would lose all 127.0.0.1 visibility)"
}
Set-Content -Path $configPath -Value $patched -NoNewline
if (Select-String -Path $configPath -Pattern 'DestinationIp[^>]*>\s*127\.0\.0\.1' -Quiet) {
    throw "post-patch assert failed: a 127.0.0.1 DestinationIp exclusion is still present"
}
Write-Host "Patched + verified: 127.0.0.1 NetworkConnect exclusion removed (NET-005 needs loopback EID 3)"
Write-Host "Base config: $configPath"
Write-Host "NOTE: ensure the config has <HashAlgorithms>SHA256,IMPHASH</HashAlgorithms> and EID 7/8/10/11/12/13/19/20/21/22/23/25 enabled (see 04-TELEMETRY.md §1). SwiftOnSecurity covers most; verify ProcessAccess targets lsass."
Write-Warning "This base config does NOT include the EID 11/23 FileCreate/FileDelete telemetry (file_capture, PERSIST-004, CONFIG-001, CRED-001 depend on it). Run scripts/enable-filecreate-telemetry.ps1 IMMEDIATELY after this script - never deploy this base config alone."

# --- 3. install or update ---
$installed = (Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue)
if ($installed) {
    Write-Host "Sysmon already installed; updating config ..."
    & $sysmonExe -accepteula -c $configPath
} else {
    Write-Host "Installing Sysmon ..."
    & $sysmonExe -accepteula -i $configPath
}

# --- 4. verify flow (Phase 0 acceptance) ---
Write-Host "`nVerifying Sysmon event flow (expect a spread of EIDs, not just 1/3):"
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Group-Object Id | Sort-Object Count -Descending | Format-Table Count, Name -AutoSize

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
Write-Host "Base config: $configPath"
Write-Host "NOTE: ensure the config has <HashAlgorithms>SHA256,IMPHASH</HashAlgorithms> and EID 7/8/10/11/12/13/19/20/21/22/23/25 enabled (see 04-TELEMETRY.md §1). SwiftOnSecurity covers most; verify ProcessAccess targets lsass."

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

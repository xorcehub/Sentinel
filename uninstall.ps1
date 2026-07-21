# uninstall.ps1 - one-shot Sentinel teardown.
#
# Mirror of install.ps1: stops the task, unregisters it, and removes Sentinel's
# artifacts. Does NOT uninstall Sysmon itself (other tools may depend on it),
# and does NOT touch the Sysmon config (revert that manually if needed).
#
# REQUIRES: elevated (admin) PowerShell.
# Usage:    powershell -ExecutionPolicy Bypass -File uninstall.ps1
#
# Flags:
#   -KeepVault   keep the forensic vault (default: delete). The vault is
#                evidence; pass this if you want to preserve captures.
#   -RemoveLog   also delete sentinel.log + alerts/heartbeat logs (default: keep).

#Requires -Version 5.1

param(
    [switch]$KeepVault,
    [switch]$RemoveLog
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $p = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script from an ELEVATED (admin) PowerShell."
    }
}
function Step($n, $msg) { Write-Host "`n[$n] $msg" -ForegroundColor Cyan }
function Ok($msg)       { Write-Host "    OK: $msg" -ForegroundColor Green }
function Skip($msg)     { Write-Host "    skip: $msg" -ForegroundColor DarkGray }

Assert-Admin
$root   = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe    = Join-Path $root "sentinel.exe"
$task   = "Sentinel"
Write-Host "Sentinel uninstall (repo: $root)" -ForegroundColor White

# --- 1. stop the task + any running sentinel.exe ---
Step 1 "Stopping Sentinel"
$t = Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
if ($t) {
    Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
    Ok "Task stopped"
} else {
    Skip "task not registered"
}
# Kill any stray sentinel processes (interactive or orphaned SYSTEM ones).
# sentinel-tray is the user-session toast relay; kill it too.
$procs = Get-Process sentinel,sentinel-cli,sentinel-tray -ErrorAction SilentlyContinue
if ($procs) {
    $procs | Stop-Process -Force -ErrorAction SilentlyContinue
    Ok "Killed $($procs.Count) process(es)"
} else {
    Skip "no sentinel process running"
}

# --- 2. unregister the task ---
Step 2 "Removing Scheduled Task"
if ($t) {
    Unregister-ScheduledTask -TaskName $task -Confirm:$false
    Ok "Task unregistered"
} else {
    Skip "task not registered"
}

# --- 3. unregister the Windows Event Log source ---
Step 3 "Removing Event Log source"
$key = "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Application\Sentinel"
if (Test-Path $key) {
    Remove-Item $key -Recurse -Force -ErrorAction SilentlyContinue
    Ok "Event source 'Sentinel' removed"
} else {
    Skip "event source not registered"
}

# --- 4. vault (forensic evidence) ---
Step 4 "Forensic vault"
$vault = Join-Path $root "forensics\sentinel-vault"
if (Test-Path $vault) {
    if ($KeepVault) {
        Skip "kept (-KeepVault): $vault"
    } else {
        Remove-Item $vault -Recurse -Force
        Ok "Vault removed: $vault"
    }
} else {
    Skip "vault not found"
}

# --- 5. binary + toast relay ---
Step 5 "Binary + toast relay"
foreach ($b in @($exe, (Join-Path $root "sentinel-tray.exe"))) {
    if (Test-Path $b) { Remove-Item $b -Force; Ok "$([System.IO.Path]::GetFileName($b)) removed" }
    else { Skip "$([System.IO.Path]::GetFileName($b)) not found" }
}
# Remove the HKLM Run autostart entry for the toast relay.
$runKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
if (Get-ItemProperty -Path $runKey -Name "SentinelTray" -ErrorAction SilentlyContinue) {
    Remove-ItemProperty -Path $runKey -Name "SentinelTray" -ErrorAction SilentlyContinue
    Ok "SentinelTray Run entry removed"
} else {
    Skip "SentinelTray Run entry not present"
}

# --- 6. logs (optional) ---
Step 6 "Logs"
if ($RemoveLog) {
    foreach ($f in @("sentinel.log","ALERTS.log","heartbeat.log")) {
        $p = Join-Path $root $f
        if (Test-Path $p) { Remove-Item $p -Force; Ok "$f removed" }
    }
} else {
    Skip "logs kept (pass -RemoveLog to delete sentinel.log, ALERTS.log, heartbeat.log)"
}

Write-Host "`n=== DONE ===" -ForegroundColor Green
Write-Host "Sentinel stopped and removed. Sysmon itself was NOT uninstalled."
Write-Host ""
Write-Host "NOT removed (revert manually if desired):"
Write-Host "  - Sysmon service (sysmon64 -u to uninstall)"
Write-Host "  - Sysmon config telemetry patches (FileCreate/FileDelete/ArchiveDirectory)"
Write-Host "  - C:\SentinelArchive (Sysmon's FileDelete archive)"

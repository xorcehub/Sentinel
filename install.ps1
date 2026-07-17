# install.ps1 - one-shot Sentinel setup.
#
# Builds the binary, installs Sysmon + the FileCreate/FileDelete telemetry
# config (with ArchiveDirectory), registers the event source, and installs the
# Scheduled Task running as SYSTEM (so it can read Sysmon's SYSTEM-locked
# FileDelete archive). Starts the task at the end.
#
# Every step is idempotent - re-run safely to update.
#
# REQUIRES: elevated (admin) PowerShell + Go toolchain on PATH (to build).
# Usage:    powershell -ExecutionPolicy Bypass -File install.ps1

#Requires -Version 5.1
$ErrorActionPreference = "Stop"

function Assert-Admin {
    $p = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script from an ELEVATED (admin) PowerShell."
    }
}
function Step($n, $msg) { Write-Host "`n[$n] $msg" -ForegroundColor Cyan }
function Ok($msg)       { Write-Host "    OK: $msg" -ForegroundColor Green }

Assert-Admin
$root   = Split-Path -Parent $MyInvocation.MyCommand.Path
$exe    = Join-Path $root "sentinel.exe"
$scripts = Join-Path $root "scripts"
Write-Host "Sentinel one-shot install (repo: $root)" -ForegroundColor White

# --- 1. build ---
Step 1 "Building sentinel.exe (-H windowsgui: no console window under Task Scheduler)"
$go = Get-Command go.exe -ErrorAction SilentlyContinue
if (-not $go) { throw "Go toolchain not on PATH. Install Go, or build sentinel.exe manually first." }
Push-Location $root
& go build -ldflags "-H windowsgui" -o $exe ./cmd/sentinel
$code = $LASTEXITCODE
Pop-Location
if ($code -ne 0) { throw "go build failed (exit $code)." }
Ok "sentinel.exe built"

# --- 2. sysmon + base config ---
Step 2 "Installing Sysmon + SwiftOnSecurity base config"
& (Join-Path $scripts "install-sysmon.ps1")
Ok "Sysmon installed/updated"

# --- 3. FileCreate + FileDelete telemetry + ArchiveDirectory ---
Step 3 "Patching Sysmon config: FileCreate + FileDelete (archive) + ArchiveDirectory"
& (Join-Path $scripts "enable-filecreate-telemetry.ps1")
Ok "Telemetry config applied"

# --- 4. event source ---
Step 4 "Registering Sentinel Windows Event Log source"
& (Join-Path $scripts "register-eventsource.ps1") -ExePath $exe
Ok "Event source ready"

# --- 5. Scheduled Task (SYSTEM, so it can read C:\SentinelArchive) ---
Step 5 "Installing Scheduled Task as SYSTEM (at-logon, auto-restart)"
& (Join-Path $scripts "install-task.ps1") -ExePath $exe -AsSystem
Ok "Task registered"

# --- 6. start ---
Step 6 "Starting the task"
Start-ScheduledTask -TaskName "Sentinel"
Start-Sleep -Seconds 3
$info = Get-ScheduledTaskInfo -TaskName "Sentinel"
if ($info.LastTaskResult -eq 267009 -or $info.LastTaskResult -eq 0) {
    Ok "Task running (it holds a mutex if an old instance is still up - stop it first)."
} else {
    Write-Host "    WARN: task exited with code $($info.LastTaskResult). Check sentinel.log." -ForegroundColor Yellow
}

Write-Host "`n=== DONE ===" -ForegroundColor Green
Write-Host "Sentinel is installed and running as SYSTEM."
Write-Host "  log:     $root\sentinel.log"
Write-Host "  vault:   $root\forensics\sentinel-vault"
Write-Host "  archive: C:\SentinelArchive"
Write-Host ""
Write-Host "Verify (elevated):"
Write-Host "  Get-Content $root\sentinel.log -Tail 8 | Select-String 'archive capture enabled'"
Write-Host "  Get-ScheduledTaskInfo Sentinel | Select-Object LastRunTime, LastTaskResult, NumberOfMissedRuns"

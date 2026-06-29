# scripts/register-eventsource.ps1
# One-time (admin) registration of the "Sentinel" Windows Event Log source, so
# Phase 2's alert dispatcher can write to the Application log natively
# (05-ALERTING.md §6). If unregistered, the dispatcher falls back to
# eventcreate.exe (which auto-registers) so alerting never fails on a fresh box.

param(
    [string]$Source = "Sentinel",
    [string]$Log    = "Application",
    [string]$ExePath = (Join-Path $PSScriptRoot "..\cmd\sentinel\sentinel.exe")
)

$ErrorActionPreference = "Stop"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as Administrator."
}

$key = "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\$Log\$Source"
if (Test-Path $key) {
    Write-Host "Event source '$Source' already registered." -ForegroundColor Yellow
} else {
    # The simplest reliable registration uses eventcreate.exe once, which writes
    # the registry keys the EventLog API expects (EventMessageFile etc.). We use
    # the OS's own message file so ReportEvent doesn't need a custom MC file.
    $exe = if (Test-Path $ExePath) { (Resolve-Path $ExePath).Path } else { "" }
    & eventcreate.exe /ID 200 /T INFORMATION /L $Log /SO $Source /D "Sentinel event source registered." | Out-Null
    Write-Host "Registered event source '$Source' (log: $Log)." -ForegroundColor Green
}

Write-Host "Verify: Get-WinEvent -FilterHashtable @{LogName='$Log';ProviderName='$Source'} -MaxEvents 5"

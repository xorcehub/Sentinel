# scripts/install-task.ps1
# Creates the session-scoped scheduled task that launches sentinel.exe at logon
# and keeps it alive. Run once (as the user; no admin needed for a user task).
#
# Replaces the legacy BeaconHunt task once Sentinel Phase 2 passes.
#
# Session-0 constraint (02-ARCHITECTURE.md §1): the task MUST run only when the
# user is logged on (not "whether logged on or not") so the process lives in the
# interactive session and can show MessageBoxes.

param(
    [string]$ExePath = (Join-Path $PSScriptRoot "..\cmd\sentinel\sentinel.exe"),
    [string]$TaskName = "Sentinel",
    [string]$User     = $env:USERNAME
)

# Resolve to an absolute path (scheduled tasks need it).
$ExePath = (Resolve-Path $ExePath -ErrorAction Stop).Path

$action    = New-ScheduledTaskAction -Execute $ExePath
$trigger   = New-ScheduledTaskTrigger -AtLogOn -User $env:USERDOMAIN\$User

# Restart on failure (RestartCount 999 — the 3-try cliff was a security hole),
# plus a repeating supervised trigger every 5 min that no-ops if the mutex is held.
$settings  = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1)

$principal = New-ScheduledTaskPrincipal -UserId $env:USERDOMAIN\$User -LogonType Interactive -RunLevel Limited

# Cleanup if it already exists (idempotent).
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

Register-ScheduledTask `
    -TaskName  $TaskName `
    -Action    $action `
    -Trigger   $trigger `
    -Settings  $settings `
    -Principal $principal `
    -Description "Sentinel endpoint guard (session-scoped). Replaces BeaconHunt."

Write-Host "Registered task '$TaskName' -> $ExePath (at-logon, RestartCount=999)." -ForegroundColor Green
Write-Host "Verify: Start-ScheduledTask $TaskName ; Get-ScheduledTaskInfo $TaskName"

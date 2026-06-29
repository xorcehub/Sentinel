# scripts/install-task.ps1
# Creates the session-scoped scheduled task that launches sentinel.exe at logon
# and keeps it alive. Run once from an elevated (admin) PowerShell.
#
# Replaces the legacy BeaconHunt task once Sentinel Phase 2 passes.
#
# Session-0 constraint (02-ARCHITECTURE.md §1): the task MUST run only when the
# user is logged on (not "whether logged on or not") so the process lives in the
# interactive session and can show MessageBoxes.
#
# Elevation requirement (discovered Phase 1): the Sysmon Operational channel
# (Microsoft-Windows-Sysmon/Operational) requires an elevated token to read, so
# the task is registered with -RunLevel Highest. This is orthogonal to the
# Session-0 constraint above: an elevated process still runs on the interactive
# desktop in the user's session and CAN show MessageBoxes — elevation does not
# push the process into Session 0 (only a Windows Service lives there).
# Registering a Highest task requires admin rights, hence "run from elevated
# PowerShell". Thereafter the task silently re-elevates at each logon with no
# UAC prompt (same model as the operator's PowerPlan Switcher).

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

# -RunLevel Highest: silent elevation at logon so the process can read the
# Sysmon channel. Equivalent to <RunLevel>HighestAvailable</RunLevel> in task
# XML. -LogonType Interactive keeps the process in the user's desktop session
# (NOT Session 0) so MessageBox works.
$principal = New-ScheduledTaskPrincipal -UserId $env:USERDOMAIN\$User -LogonType Interactive -RunLevel Highest

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

Write-Host "Registered task '$TaskName' -> $ExePath (at-logon, RunLevel=Highest, RestartCount=999)." -ForegroundColor Green
Write-Host "Verify: Start-ScheduledTask $TaskName ; Get-ScheduledTaskInfo $TaskName"
Write-Host "Confirm elevation: (Get-ScheduledTask -TaskName $TaskName).Principal.RunLevel  # should be 'Highest'"

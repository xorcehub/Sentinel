# scripts/install-task.ps1
# Creates the session-scoped scheduled task that launches sentinel.exe at logon
# and keeps it alive. Run once from an elevated (admin) PowerShell.
#
# Prerequisite: build sentinel.exe as a WINDOWS-GUI-subsystem binary so Task
# Scheduler can launch it WITHOUT allocating a console window:
#
#     go build -ldflags "-H windowsgui" -o sentinel.exe ./cmd/sentinel
#
# A default `go build` produces a console-subsystem binary; launched with no
# parent console (Task Scheduler), Windows allocates a fresh one and sentinel.exe
# pops a console window. -H windowsgui (same approach as a tray app) makes the
# PE subsystem GUI so no console is auto-created. MessageBox/EventLog/Toast all
# work regardless of subsystem (they create their own windows via API).
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
    # Default to the repo-root sentinel.exe — this is where
    #   go build -o sentinel.exe ./cmd/sentinel
    # outputs the binary (the -o path is relative to CWD, i.e. the repo root).
    # It MUST live at repo root, not in cmd\sentinel\: resolveExeRelative() in
    # main.go makes rules.d/ + config/ + logs relative to the EXE directory, so
    # the exe needs rules.d/ as a sibling (true at repo root, false in cmd/sentinel).
    [string]$ExePath = (Join-Path $PSScriptRoot "..\sentinel.exe"),
    [string]$TaskName = "Sentinel",
    [string]$User     = $env:USERNAME,
    # -AsSystem: run the task as NT AUTHORITY\SYSTEM instead of the current
    # user. REQUIRED to read Sysmon's FileDelete archive (C:\SentinelArchive),
    # which Sysmon locks to SYSTEM-only so hard that even admins get access-
    # denied. Tradeoff: a SYSTEM task runs in Session 0 — toasts must relay via
    # sentinel-tray (pipe), popups are disabled (-popup=false, see below) and
    # criticals escalate to a loud looping toast. Use -AsSystem
    # when the snapshot vault (file capture) matters more than popups.
    [switch]$AsSystem,
    # Vault + archive dirs. Only used with -AsSystem (the archive is
    # SYSTEM-locked). The snapshot vault is where captured files are written.
    [string]$SnapshotDir = "",
    [string]$ArchiveDir  = "C:\SentinelArchive"
)

# Resolve to an absolute path (scheduled tasks need it).
$ExePath = (Resolve-Path $ExePath -ErrorAction Stop).Path

# Build the action. With -AsSystem, append the snapshot-vault + archive flags
# so the SYSTEM daemon can read the FileDelete archive and write the vault.
$actionArg = ""
if ($AsSystem) {
    if (-not $SnapshotDir) {
        $SnapshotDir = Join-Path (Split-Path $ExePath -Parent) "forensics\sentinel-vault"
    }
    # -popup=false: an unattended SYSTEM daemon shouldn't block on a MessageBox
    # waiting for a human click; disabling it escalates criticals to a loud
    # looping-alarm toast (relayed by sentinel-tray).
    $actionArg = "-popup=false -snapshot-dir `"$SnapshotDir`" -sysmon-archive-dir `"$ArchiveDir`""
}
$action    = New-ScheduledTaskAction -Execute $ExePath -Argument $actionArg -WorkingDirectory (Split-Path $ExePath -Parent)
$trigger   = New-ScheduledTaskTrigger -AtLogOn

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
if ($AsSystem) {
    # SYSTEM can read C:\SentinelArchive natively. Runs in Session 0, so no
    # desktop popups/toast — log + eventlog alerts only.
    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType Service -RunLevel Highest
} else {
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERDOMAIN\$User -LogonType Interactive -RunLevel Highest
}

# Cleanup if it already exists (idempotent).
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

# Out-Null: the returned task object otherwise prints its formatted table
# out of order amid the Write-Host steps (observed on-host).
Register-ScheduledTask `
    -TaskName  $TaskName `
    -Action    $action `
    -Trigger   $trigger `
    -Settings  $settings `
    -Principal $principal `
    -Description "Sentinel endpoint guard (session-scoped). Replaces BeaconHunt." |
    Out-Null

Write-Host "Registered task '$TaskName' -> $ExePath (at-logon, RunLevel=Highest, RestartCount=999)." -ForegroundColor Green
if ($AsSystem) {
    Write-Host "  Mode: SYSTEM (can read C:\SentinelArchive; no desktop popups)." -ForegroundColor Yellow
    Write-Host "  Args: $actionArg"
} else {
    Write-Host "  Mode: $User interactive (desktop popups work; CANNOT read archive)."
}
Write-Host "Verify: Start-ScheduledTask $TaskName ; Get-ScheduledTaskInfo $TaskName"
Write-Host "Confirm elevation: (Get-ScheduledTask -TaskName $TaskName).Principal.RunLevel  # should be 'Highest'"

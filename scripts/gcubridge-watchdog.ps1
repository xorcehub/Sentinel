# GCUBridge service-watchdog. Run at logon by the operator's scheduled task:
#   powershell -WindowStyle Hidden -ep bypass -File <repo>\scripts\gcubridge-watchdog.ps1
# The allowlist dev_scripts entry is anchored on THIS path
# (config/allowlist.json, 2026-09-02c redteam F10) — keep the task's -File
# target in sync. The old inline form (`-Command "Get-Service -Name
# 'GCUBridge'; ..."` ) matched ANY cmdline containing the marker string, so a
# piggybacked payload after it suppressed EXEC-001 for the whole launch.

$s = Get-Service -Name 'GCUBridge'
if ($s.Status -ne 'Running') {
    Start-Service -Name 'GCUBridge'
}

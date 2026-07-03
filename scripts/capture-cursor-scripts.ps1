# scripts/capture-cursor-scripts.ps1
#
# Capture the contents of the ps-script-<GUID>.ps1 files Cursor spawns and
# deletes immediately in %TEMP% (the scripts behind the EXEC-001/PERSIST-001
# alerts). Lets you read what they actually do before they vanish.
#
# Why this exists: Cursor launches
#   powershell.exe -ExecutionPolicy Bypass -NonInteractive -File <TEMP>\ps-script-<GUID>.ps1
# and deletes the script right after. Copying by hand never wins the race.
#
# Approach: tight poll of %TEMP% (every ~15ms, Windows timer granularity) with
# a robust retry read that survives a concurrent write lock. If the file is
# already gone by the time we read, the attempt is logged as FAILED and the
# script prints the bulletproof Sysmon-archive fallback (no race possible).
#
# USAGE:  pwsh -File .\capture-cursor-scripts.ps1            (PowerShell 7)
#         powershell -ExecutionPolicy Bypass -File .\capture-cursor-scripts.ps1   (5.1)
# Then open a NEW Cursor window while it watches. No admin rights needed.

#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$TempDir    = $env:TEMP,
    [string]$CaptureDir = "C:\forensics\cursor-scripts",
    [int]   $WatchSeconds = 120
)

$ErrorActionPreference = "Stop"

function Write-Section([string]$t) { Write-Host "`n==== $t ====" -ForegroundColor Cyan }

Write-Section "Cursor ps-script capture"

# ---- sanity: TempDir exists ----
if (-not (Test-Path $TempDir -PathType Container)) {
    throw "TempDir not found: $TempDir (pass -TempDir <path>)"
}
Write-Host "Temp       : $TempDir"
Write-Host "Capture    : $CaptureDir"
Write-Host "Watch (s)  : $WatchSeconds"

# ---- Phase 1: did Sysmon already archive any? (free win, no race) ----
Write-Section "Phase 1: checking Sysmon FileDelete (EID 23) archives"
$sysmonHit = $false
try {
    $e23 = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; Id = 23 } `
        -MaxEvents 2000 -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match 'ps-script' }
    if ($e23) {
        $sysmonHit = $true
        Write-Host "Sysmon already saw $($e23.Count) FileDelete(s) for ps-script:" -ForegroundColor Green
        $e23 | Select-Object -First 3 TimeCreated | Format-Table -AutoSize
        $archived = $e23 | Where-Object { $_.Message -match '(?im)^\s*Archived:\s*true' }
        if ($archived) {
            Write-Host "==> At least one was ARCHIVED. Copies (no extension) are in the Sysmon" -ForegroundColor Green
            Write-Host "    ArchiveDirectory. Default location:" -ForegroundColor Green
            Write-Host "      C:\ProgramData\Sysmon\"
            Write-Host "    Newest archived files:"
            Get-ChildItem 'C:\ProgramData\Sysmon\' -File -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending | Select-Object -First 10 |
                Format-Table LastWriteTime, Length, FullName -AutoSize
        } else {
            Write-Host "Sysmon saw the deletes but did NOT archive (no <FileDelete> include rule)." -ForegroundColor Yellow
            Write-Host "Continuing to live capture below; see the fallback block if it loses the race."
        }
    } else {
        Write-Host "No Sysmon EID 23 events for ps-script in the last 2000. Continuing to live capture." -ForegroundColor Yellow
    }
} catch {
    Write-Host "Sysmon log query failed ($($_.Exception.Message)). Continuing to live capture." -ForegroundColor Yellow
}

# ---- Phase 2: prepare capture dir + log ----
if (-not (Test-Path $CaptureDir)) { New-Item -ItemType Directory -Force -Path $CaptureDir | Out-Null }
$logFile = Join-Path $CaptureDir "capture.log"
$sessionStart = Get-Date
$sessionStamp = $sessionStart.ToString('yyyy-MM-ddTHH:mm:ss')
"=== capture session $sessionStamp  TempDir=$TempDir ===" | Out-File -FilePath $logFile -Append -Encoding utf8

# quick warm scan: are any sitting there right now?
$warm = @([System.IO.Directory]::GetFiles($TempDir, 'ps-script-*.ps1'))
if ($warm.Count -gt 0) {
    Write-Host "Warm hit: $($warm.Count) ps-script file(s) present right now." -ForegroundColor Green
}

# ---- Phase 3: live poll + robust copy ----
Write-Section "Phase 2: watching - open a NEW Cursor window NOW"
Write-Host "Polling every ~15ms. Launch/refresh Cursor in another window." -ForegroundColor White
Write-Host "Press Ctrl+C to stop early (results still print)." -ForegroundColor DarkGray

$deadline = (Get-Date).AddSeconds($WatchSeconds)
$seen   = New-Object System.Collections.Generic.HashSet[string]
$dests  = New-Object System.Collections.Generic.List[string]
$checks = 0
$lastHeartbeat = [datetime]::MinValue

function Read-Captured {
    # Robust read that survives a concurrent write lock. Returns bytes or throws.
    param([string]$Path)
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $ms = New-Object System.IO.MemoryStream
        $fs.CopyTo($ms)
        return ,$ms.ToArray()
    } finally { $fs.Close() }
}

try {
    while ((Get-Date) -lt $deadline) {
        $checks++
        # heartbeat so the user can see it's alive
        if ((Get-Date) - $lastHeartbeat -ge [timespan]'00:00:05') {
            $remain = [int]([math]::Ceiling(($deadline - (Get-Date)).TotalSeconds))
            Write-Host "  ...still watching (${remain}s left, $checks polls, $($dests.Count) captured)" -ForegroundColor DarkGray
            $lastHeartbeat = Get-Date
        }

        try {
            $hits = [System.IO.Directory]::GetFiles($TempDir, 'ps-script-*.ps1')
            foreach ($f in $hits) {
                if ($seen.Contains($f)) { continue }
                [void]$seen.Add($f)

                $stamp = Get-Date -Format 'HHmmss.fff'
                $dest  = Join-Path $CaptureDir ("$stamp " + (Split-Path $f -Leaf))

                $ok = $false
                $reason = ''
                # up to ~600ms of retries: covers a held write lock or a slow flush.
                for ($i = 1; $i -le 60; $i++) {
                    try {
                        $bytes = Read-Captured -Path $f
                        [System.IO.File]::WriteAllBytes($dest, $bytes)
                        $ok = $true
                        break
                    } catch {
                        $reason = $_.Exception.GetType().Name + ': ' + $_.Exception.Message
                        Start-Sleep -Milliseconds 10
                    }
                }

                $ts  = Get-Date -Format 'HH:mm:ss.fff'
                $sz  = if ($ok) { " ($([System.IO.File]::ReadAllBytes($dest).Length) bytes)" } else { '' }
                $msg = if ($ok) { "CAPTURED -> $dest$sz" } else { "FAILED ($reason)" }
                $clr = if ($ok) { 'Green' } else { 'Red' }
                Write-Host "[$ts] $f" -ForegroundColor $clr
                Write-Host "       $msg" -ForegroundColor $clr
                "$ts  $f  $msg" | Add-Content -Path $logFile -Encoding utf8
                if ($ok) { [void]$dests.Add($dest) }
            }
        } catch {
            # transient enumeration error (e.g. handle churn) - keep polling
        }

        Start-Sleep -Milliseconds 10
    }
} finally {
    Write-Host "`nWatch window ended. Poll iterations: $checks" -ForegroundColor DarkGray
}

# ---- Phase 4: report + dump contents ----
Write-Section "Phase 3: results"
$files = Get-ChildItem -Path $CaptureDir -Filter '*.ps1' -File -ErrorAction SilentlyContinue |
         Where-Object { $_.LastWriteTime -ge $sessionStart } |
         Sort-Object Name

if (-not $files -and $dests.Count -eq 0) {
    Write-Host "Nothing captured this session." -ForegroundColor Yellow
    Write-Host "Either no new Cursor window was launched, or Cursor deletes faster than the poll." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "BULLETPROOF FALLBACK - Sysmon FileDelete archiving (no race possible)." -ForegroundColor Cyan
    Write-Host "Sysmon archives the file at the moment of deletion, so it can never be missed."
    Write-Host "Add to your Sysmon config inside <EventFiltering>:"
    Write-Host @"

    <RuleGroup name="Capture-Cursor-Spawned-Scripts" groupRelation="or">
      <FileDelete onmatch="include">
        <TargetFilename condition="contains">\Temp\ps-script-</TargetFilename>
      </FileDelete>
    </RuleGroup>

"@ -ForegroundColor White
    Write-Host "Then reload it:"
    Write-Host "    & 'C:\ProgramData\Sysmon\sysmon64.exe' -accepteula -c <your-config>.xml"
    Write-Host "Archived copies (no extension) land in: C:\ProgramData\Sysmon\"
    Write-Host "Log of this session: $logFile"
    return
}

Write-Host "Captured $($files.Count) script(s):" -ForegroundColor Green
foreach ($f in $files) {
    Write-Host ("  {0,-45} {1,8} bytes" -f $f.Name, $f.Length)
}

Write-Section "Contents"
foreach ($f in $files) {
    Write-Host "`n----- $($f.Name) -----" -ForegroundColor Cyan
    try {
        Get-Content -Raw -Path $f.FullName
    } catch {
        Write-Host "(unreadable: $($_.Exception.Message))" -ForegroundColor Red
    }
}

Write-Host "`nFull log: $logFile" -ForegroundColor DarkGray
Write-Host "Re-run anytime; older captures are kept." -ForegroundColor DarkGray

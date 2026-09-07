# Round-5 live fire (2026-09-03b). Benign payloads only; everything stays in
# this dir. Each vector has a distinct marker; controls must fire so silence
# is attributed to the filter, not lost telemetry. Run WITHOUT bypass flags:
#   powershell -NoProfile -File run.ps1
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$proof = Join-Path $root 'r5proof.txt'
Remove-Item $proof -ErrorAction SilentlyContinue

Write-Output ("round5 live fire start " + (Get-Date -Format o))

# ---- F17 vector: double-space between flag and value ----
& cmd /c "powershell -NoProfile -ep  bypass -w  h -c `"Write-Host r5f17-marker`" >> `"$proof`" 2>&1"

# ---- F17 control: identical shape, single spaces (MUST fire EXEC-001) ----
& cmd /c "powershell -NoProfile -ep bypass -w h -c `"Write-Host r5f17ctl-marker`" >> `"$proof`" 2>&1"

# ---- F18 vector: full-name non-Bypass policy value ----
& cmd /c "powershell -NoProfile -ExecutionPolicy Unrestricted -c `"Write-Host r5f18-marker`" >> `"$proof`" 2>&1"

# ---- F18 control: abbreviated form '-ep u' (token covered; MUST fire) ----
& cmd /c "powershell -NoProfile -ep u -c `"Write-Host r5f18ctl-marker`" >> `"$proof`" 2>&1"

# ---- F19 vector: headless conhost running cmd (not powershell) ----
& cmd /c "conhost --headless cmd /c `"echo r5f19-marker >> $proof`""

# ---- F19 control: headless conhost running powershell (MUST fire EXEC-002) ----
& cmd /c "conhost --headless powershell -NoProfile -c `"Write-Host r5f19ctl-marker`" >> `"$proof`" 2>&1"

# ---- F20 vector: AiStone unanchored dev_scripts substring, repo-tree mimic ----
$mim = Join-Path $root 'aistoneservice\mycontrolcenter\command'
New-Item -ItemType Directory -Force -Path $mim | Out-Null
Set-Content -Path (Join-Path $mim 'logonusername.ps1') -Value `
  "Add-Content -Path '$proof' -Value 'r5f20-marker'" -Encoding ASCII
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $mim 'logonusername.ps1')

# ---- F20 control: same flags, no AiStone substring (MUST fire EXEC-001) ----
Set-Content -Path (Join-Path $root 'ctl_r5f20.ps1') -Value `
  "Add-Content -Path '$proof' -Value 'r5f20ctl-marker'" -Encoding ASCII
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'ctl_r5f20.ps1')

Write-Output ("round5 live fire end " + (Get-Date -Format o))
Write-Output "---- proof file (execution evidence) ----"
Get-Content $proof

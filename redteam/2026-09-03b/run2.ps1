# Round-5b post-fix live re-fire (2026-09-03). Verifies against the LIVE
# daemon (rebuilt 15:56) + LIVE Sysmon config (headless-aware conhost
# exclude deployed): F17/F20 should now FIRE; F18/F19 expected still quiet
# (open findings). Benign payloads; everything stays in this dir.
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$proof = Join-Path $root 'r5bproof.txt'
Remove-Item $proof -ErrorAction SilentlyContinue

Write-Output ("round5b live fire start " + (Get-Date -Format o))

# F17 vector: double-space (FIXED -> must FIRE now)
& cmd /c "powershell -NoProfile -ep  bypass -w  h -c `"Write-Host r5b-f17vec`" >> `"$proof`" 2>&1"
# F17 control: single space (must FIRE, pipeline proof)
& cmd /c "powershell -NoProfile -ep bypass -w h -c `"Write-Host r5b-f17ctl`" >> `"$proof`" 2>&1"

# F18 vector: full-name Unrestricted (OPEN -> expected QUIET)
& cmd /c "powershell -NoProfile -ExecutionPolicy Unrestricted -c `"Write-Host r5b-f18vec`" >> `"$proof`" 2>&1"

# F19 vector: headless conhost + cmd child (OPEN -> expected QUIET)
Start-Process -FilePath "$env:WINDIR\System32\conhost.exe" -ArgumentList '--headless','cmd','/c',"echo r5b-f19vec > $root\r5b-f19.txt" -Wait -WindowStyle Hidden
# F19 control: headless conhost + powershell child (F21 deployed -> must FIRE EXEC-002, first ever)
Start-Process -FilePath "$env:WINDIR\System32\conhost.exe" -ArgumentList '--headless','powershell','-NoProfile','-c','Write-Host r5b-f19ctl' -Wait -WindowStyle Hidden

# F20 vector: AiStone repo-tree mimic (FIXED -> must FIRE now)
$mim = Join-Path $root 'aistoneservice\mycontrolcenter\command'
New-Item -ItemType Directory -Force -Path $mim | Out-Null
Set-Content -Path (Join-Path $mim 'logonusername.ps1') -Value "Add-Content -Path '$proof' -Value 'r5b-f20vec'" -Encoding ASCII
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $mim 'logonusername.ps1')

Write-Output ("round5b live fire end " + (Get-Date -Format o))
Write-Output "---- proof file ----"
Get-Content $proof -ErrorAction SilentlyContinue
Get-Content (Join-Path $root 'r5b-f19.txt') -ErrorAction SilentlyContinue

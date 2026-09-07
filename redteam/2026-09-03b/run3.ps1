# Round-5c final verification (2026-09-03). After redeploying the daemon
# with the F18/F19 rule fixes: both remaining vectors must now FIRE.
# Benign payloads; everything stays in this dir.
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$proof = Join-Path $root 'r5cproof.txt'
Remove-Item $proof -ErrorAction SilentlyContinue

Write-Output ("round5c live fire start " + (Get-Date -Format o))

# F18 vector: full-name Unrestricted (FIXED -> must FIRE EXEC-001)
& cmd /c "powershell -NoProfile -ExecutionPolicy Unrestricted -c `"Write-Host r5c-f18vec`" >> `"$proof`" 2>&1"
# F18 control: -ep bypass single-space (must FIRE, pipeline proof)
& cmd /c "powershell -NoProfile -ep bypass -c `"Write-Host r5c-f18ctl`" >> `"$proof`" 2>&1"

# F19 vector: headless conhost + cmd child (FIXED -> must FIRE EXEC-002)
Start-Process -FilePath "$env:WINDIR\System32\conhost.exe" -ArgumentList '--headless','cmd','/c',"echo r5c-f19vec > $root\r5c-f19.txt" -Wait -WindowStyle Hidden
# F19 control: headless conhost + powershell child (must FIRE EXEC-002)
Start-Process -FilePath "$env:WINDIR\System32\conhost.exe" -ArgumentList '--headless','powershell','-NoProfile','-c','Write-Host r5c-f19ctl' -Wait -WindowStyle Hidden

Write-Output ("round5c live fire end " + (Get-Date -Format o))
Write-Output "---- proof ----"
Get-Content $proof -ErrorAction SilentlyContinue
Get-Content (Join-Path $root 'r5c-f19.txt') -ErrorAction SilentlyContinue

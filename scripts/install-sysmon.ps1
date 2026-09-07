# scripts/install-sysmon.ps1
# Ensures Sysmon64 is installed with a config that emits the EIDs the Sentinel
# rules need (Phase 0 acceptance, 07-BUILD-PHASES.md). Idempotent: detects an
# existing install and updates the config rather than reinstalling.
#
# Base config: SwiftOnSecurity/sysmon-config (chosen in 02-ARCHITECTURE.md §5 /
# 07 Phase 0). The adaptations below are applied on top.
#
# REQUIRES: run as Administrator.

param(
    [string]$SysmonUrl = "https://download.sysinternals.com/files/Sysmon.zip",
    [string]$ConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml",
    [string]$InstallDir = "$env:ProgramData\Sysmon"
)

$ErrorActionPreference = "Stop"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as Administrator."
}

# --- 1. locate or install sysmon64.exe ---
$sysmonExe = Join-Path $InstallDir "sysmon64.exe"
if (-not (Test-Path $sysmonExe)) {
    Write-Host "Installing Sysmon to $InstallDir ..."
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $zip = Join-Path $env:TEMP "sysmon.zip"
    Invoke-WebRequest -Uri $SysmonUrl -OutFile $zip
    Expand-Archive -Path $zip -DestinationPath $InstallDir -Force
    Remove-Item $zip
}

# --- 2. fetch base config ---
$configPath = Join-Path $InstallDir "sentinel-sysmon.xml"
Invoke-WebRequest -Uri $ConfigUrl -OutFile $configPath

# PATCH: SwiftOnSecurity's NetworkConnect EXCLUDE list drops DestinationIp
# 127.0.0.1 at the SOURCE, so loopback EID 3 never reaches Sentinel and
# NET-005 (the loopback-C2 gap-closer) plus known_loopback_listeners can
# never work - verified live 2026-09-01 (NET-005: zero alerts ever; an ::1
# connect arrived but 127.0.0.1 connects do not). Strip that one exclusion.
# Loopback noise this re-admits is bounded by NET-005's known_loopback_listeners
# except + 5m dedup and allowed_destinations (127/8, ::1/128) in
# config/allowlist.json - but expect extra toasts until dev ports are seeded
# (both "127.0.0.1:P" and "::1:P" spellings; Sysmon sends the expanded
# 0:0:0:0:0:0:0:1 form, which the loader canonicalizes).
$cfg = Get-Content $configPath -Raw
$patched = $cfg -replace '(?m)^\s*<DestinationIp condition="is">127\.0\.0\.1</DestinationIp>.*\r?\n', ''
if ($patched -eq $cfg) {
    # FAIL the install: this exact blindness persisted for months silently.
    # Upstream drifted - inspect manually, then widen/replace the pattern.
    throw "loopback exclude not found in upstream config - refusing to install blind (NET-005 would lose all 127.0.0.1 visibility)"
}
Set-Content -Path $configPath -Value $patched -NoNewline
if (Select-String -Path $configPath -Pattern 'DestinationIp[^>]*>\s*127\.0\.0\.1' -Quiet) {
    throw "post-patch assert failed: a 127.0.0.1 DestinationIp exclusion is still present"
}
Write-Host "Patched + verified: 127.0.0.1 NetworkConnect exclusion removed (NET-005 needs loopback EID 3)"

# PATCH 2: SwiftOnSecurity's ProcessCreate EXCLUDE list drops
# C:\Windows\system32\conhost.exe at the SOURCE, so conhost EID 1 never
# reaches Sentinel and EXEC-002 (conhost --headless, the incident vector)
# has been inert its whole life - zero alerts ever, live-verified 2026-09-03
# redteam round 5 F21 (both the '--headless powershell' control AND the
# '--headless cmd' vector were silent; engine-level rule passes). Replace
# the blanket exclude with a Rule that keeps ordinary conhost churn
# excluded but lets --headless launches through. Sysmon semantics, learned
# the hard way (live 2026-09-03 16:0x, twice):
#   1. direct condition children of an event tag are OR-combined (that is
#      how this exclude union works) - a bare sibling <CommandLine> would
#      exclude nearly EVERY process-create.
#   2. a <Rule> element WITHOUT its own groupRelation ALSO combines its
#      conditions with OR (inherited) - deploying patch 2 that way silently
#      starved the box of ALL EID1 (FileCreate kept flowing, so the daemon
#      looked alive; a textbook -ep bypass control went quiet). The AND must
#      be EXPLICIT: <Rule groupRelation="and">.
# CONDITION SPELLING MATTERS: the negative contains is `excludes`, NOT
# `not contains` - the deployed Sysmon64 15.21 has no such condition (its
# embedded DTD/usage strings list is/is not/contains/contains any/contains
# all/excludes/excludes any/excludes all/begin with/end with/...), and an
# unknown condition crashes the config apply with 0xC0000409 instead of
# erroring cleanly. First attempt used `not contains` from memory and was
# caught exactly that way (by enable-filecreate's exit-code check - install
# step 3 used to swallow the same crash; it now checks too).
# Idempotent: skips if the Rule is already present.
if (Select-String -Path $configPath -Pattern 'conhost except headless' -Quiet) {
    Write-Host "conhost ProcessCreate exclude already headless-aware - skipping patch 2"
} else {
    $before = Get-Content $configPath -Raw
    $after = $before -replace '(?m)^(\s*)(<Image condition="is">C:\\Windows\\system32\\conhost\.exe</Image>)(\s*<!--.*-->)?\s*$',
        ('$1<Rule name="Sentinel F21: conhost except headless" groupRelation="and">' + '$2' + '$3' + "`r`n" +
         '$1  <CommandLine condition="excludes">--headless</CommandLine>' + "`r`n" + '$1</Rule>')
    if ($after -eq $before) {
        # FAIL the install, same doctrine as patch 1: this exact blindness
        # (EXEC-002 starved of conhost EID 1) persisted silently for months.
        throw "conhost ProcessCreate exclude not found in upstream config - refusing to install blind (EXEC-002 would stay dead telemetry)"
    }
    # the replacement must yield well-formed XML (Rule wrapper inside the
    # ProcessCreate exclude group) - parse before writing anything.
    try { [void][xml]$after } catch { throw "patch 2 produced malformed XML: $_" }
    Set-Content -Path $configPath -Value $after -NoNewline
    if (-not (Select-String -Path $configPath -Pattern 'conhost except headless' -Quiet)) {
        throw "post-patch assert failed: conhost exclude is not headless-aware"
    }
    if (Select-String -Path $configPath -Pattern 'condition="not contains"' -Quiet) {
        throw "post-patch assert failed: a 'not contains' condition survived - this Sysmon build rejects it (0xC0000409)"
    }
    Write-Host "Patched + verified: conhost ProcessCreate exclude is now headless-aware (EXEC-002 needs conhost EID 1)"
}
Write-Host "Base config: $configPath"
Write-Host "NOTE: ensure the config has <HashAlgorithms>SHA256,IMPHASH</HashAlgorithms> and EID 7/8/10/11/12/13/19/20/21/22/23/25 enabled (see 04-TELEMETRY.md §1). SwiftOnSecurity covers most; verify ProcessAccess targets lsass."
Write-Warning "This base config does NOT include the EID 11/23 FileCreate/FileDelete telemetry (file_capture, PERSIST-004, CONFIG-001, CRED-001 depend on it). Run scripts/enable-filecreate-telemetry.ps1 IMMEDIATELY after this script - never deploy this base config alone."

# --- 3. install or update ---
# Exit codes are CHECKED: sysmon64 crashes (e.g. 0xC0000409 on a condition
# spelling it doesn't know) rather than erroring cleanly, and the 2026-09-03
# F21 patch initially shipped one script downstream because this step used
# to ignore $LASTEXITCODE. A failed apply must stop the install HERE.
$installed = (Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue)
if ($installed) {
    Write-Host "Sysmon already installed; updating config ..."
    & $sysmonExe -accepteula -c $configPath
} else {
    Write-Host "Installing Sysmon ..."
    & $sysmonExe -accepteula -i $configPath
}
if ($LASTEXITCODE -ne 0) {
    throw "sysmon64 rejected the config (exit $LASTEXITCODE) - config NOT applied; inspect $configPath"
}

# --- 3b. EID1 flow guard ---
# The over-exclusion incident (2026-09-03): a syntactically-accepted config
# can still starve ProcessCreate (FileCreate keeps flowing, so everything
# looks alive). sysmon64 accepting the config proves NOTHING about semantics.
# Fail the install if Sysmon's operational log shows no EID 1 in the last
# 200 Sysmon events - a live Windows session always has process creates.
Start-Sleep -Seconds 2
$recent = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 200 -ErrorAction SilentlyContinue
$eid1 = @($recent | Where-Object { $_.Id -eq 1 }).Count
if ($eid1 -eq 0) {
    throw "EID1 FLOW GUARD: no ProcessCreate in the last 200 Sysmon events - config is over-excluding (see F21 postmortem, redteam/2026-09-03b). NOT leaving the box blind."
}
Write-Host "EID1 flow guard OK ($eid1 ProcessCreate in last 200 Sysmon events)"

# --- 4. verify flow (Phase 0 acceptance) ---
Write-Host "`nVerifying Sysmon event flow (expect a spread of EIDs, not just 1/3):"
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'} -MaxEvents 200 -ErrorAction SilentlyContinue |
    Group-Object Id | Sort-Object Count -Descending | Format-Table Count, Name -AutoSize

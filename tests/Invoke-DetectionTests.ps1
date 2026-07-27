#requires -Version 5.1
<#
.SYNOPSIS
    Sentinel detection-rule self-test harness (operator's own box).

.DESCRIPTION
    Runs benign scenarios that make Sysmon emit the exact events the Sentinel
    rules key on, so you can confirm each rule fires. Every payload is inert
    (echo / marker file / one-byte loopback connect / LoadLibrary of a stub).

    DRY-RUN BY DEFAULT. Prints the rule(s) each step would fire and the exact
    command it WOULD run. Pass -Execute to actually run them. Pass -Cleanup to
    remove everything a prior -Execute created.

    Nothing here is real malware. It exists only to exercise your own rules.

.PARAMETER Category
    Which scenario groups to run: exec, dropper, persistence, cred, evade, net,
    inject, config. Default: all except inject (inject needs -IncludeDangerous).

.PARAMETER Execute
    Actually perform the actions. Without it, only the plan is printed.

.PARAMETER IncludeDangerous
    Also run inject (CreateRemoteThread) and lsass (CRED-002). These need an
    ELEVATED shell and may trip Defender independently of Sentinel.

.PARAMETER Cleanup
    Remove artifacts created by -Execute (scheduled task, reg keys, Startup
    file, rules.d probe, Temp copies, built binaries). Idempotent.

.PARAMETER SkipBuild
    Don't rebuild the Go probes; reuse tests/bin/detection.exe + payload.dll.

.EXAMPLE
    # See the full plan without touching anything:
    powershell -ExecutionPolicy Bypass -File tests/Invoke-DetectionTests.ps1
.EXAMPLE
    # Actually run the safe scenarios:
    powershell -ExecutionPolicy Bypass -File tests/Invoke-DetectionTests.ps1 -Execute
.EXAMPLE
    # Tear it all back down:
    powershell -ExecutionPolicy Bypass -File tests/Invoke-DetectionTests.ps1 -Cleanup
#>
[CmdletBinding()]
param(
    [ValidateSet('exec','dropper','persistence','cred','evade','net','inject','config','all')]
    [string[]]$Category = @('all'),
    [switch]$Execute,
    [switch]$IncludeDangerous,
    [switch]$Cleanup,
    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$binDir   = Join-Path $PSScriptRoot 'bin'
$exe      = Join-Path $binDir 'detection.exe'
$dll      = Join-Path $binDir 'payload.dll'
$temp     = $env:TEMP
$taskName = 'SentinelSelfTestTask'
$svcName  = 'SentinelSelfTestSvc'
$runKey   = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$svcKey   = "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName"
$startup  = Join-Path ([Environment]::GetFolderPath('Startup')) 'sentinel-selftest.ps1'

function Want([string]$cat) {
    return ($Category -contains 'all') -or ($Category -contains $cat)
}

# Print a step header: the rule(s) it targets + the command, then run only if -Execute.
# Each step runs in its own try/catch: a single failing scenario reports and
# continues instead of aborting the whole run (one bad step must not blind the
# rest of the catalog). $ErrorActionPreference='Stop' makes cmdlet errors
# terminating, so without this any one failure would kill all later categories.
function Step([string]$rules, [string]$desc, [scriptblock]$action) {
    Write-Host ""
    if ($Execute) {
        Write-Host "==> [$rules] $desc" -ForegroundColor Cyan
        try {
            & $action
        } catch {
            Write-Host "    STEP FAILED (later steps still run): $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "PLAN==> [$rules] $desc" -ForegroundColor DarkGray
        Write-Host "        $($action.ToString().Trim())" -ForegroundColor DarkGray
    }
}

function Build-Probes {
    Write-Host "Building Go probes -> $binDir" -ForegroundColor Green
    New-Item -ItemType Directory -Force -Path $binDir | Out-Null
    & go build -o $exe  (Join-Path $PSScriptRoot 'detection-bin.go')
    if ($LASTEXITCODE -ne 0) { throw "go build detection-bin.go failed" }
    & go build -buildmode=c-shared -o $dll (Join-Path $PSScriptRoot 'payload-dll.go')
    if ($LASTEXITCODE -ne 0) { throw "go build payload-dll.go failed" }
}

# ---------- CLEANUP ----------
# Cleanup must NEVER abort partway: it is the safety net that removes the REAL
# persistence artifacts (Run-key value, Startup .ps1) created by -Execute. So
# the whole block runs under SilentlyContinue -- a missing task / locked file /
# native-command stderr cannot throw and stop it. Without this, schtasks /Delete
# on a non-existent task (e.g. when PERSIST-001 was skipped for no admin)
# wrote to stderr and, under the script's global Stop, aborted cleanup before
# reaching the Run-key removal -- leaving real persistence on disk.
if ($Cleanup) {
    Write-Host "Removing Sentinel self-test artifacts..." -ForegroundColor Yellow
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    try {
        & schtasks /Delete /TN $taskName /F 2>&1 | Out-Null
        # Run-key: delete ONLY our value, never the shared Run key (other apps
        # autostart from it). Create side used New-ItemProperty -Name
        # SentinelSelfTest, so cleanup mirrors it with Remove-ItemProperty.
        Remove-ItemProperty -Path $runKey -Name 'SentinelSelfTest'
        Remove-Item $svcKey -Recurse
        Remove-Item $startup
        Remove-Item (Join-Path (Join-Path $repoRoot 'rules.d') 'zz-selftest-probe.tmp')
        Remove-Item (Join-Path $temp 'sentinel-test.marker')
        Remove-Item (Join-Path $temp 'deadbeef.exe')
        Remove-Item (Join-Path $temp 'loader.exe')
        Remove-Item (Join-Path $temp 'logins.json')
        Remove-Item (Join-Path $temp 'logins-copy.json')
        Remove-Item (Join-Path $temp 'test.vbs')
        Remove-Item (Join-Path $temp 'selftest-payload.ps1')
        Remove-Item (Join-Path $temp 'payload.dll')
        # Built probes (tests/bin): detection.exe, payload.dll, AND payload.h
        # (the .h is an automatic byproduct of go build -buildmode=c-shared).
        # Remove the whole dir so -Cleanup returns to a truly clean tree; a next
        # -Execute rebuilds in ~2s, and -SkipBuild without a prior build errors
        # loudly instead of silently using stale probes.
        Remove-Item $binDir -Recurse
    } finally {
        $ErrorActionPreference = $prevEAP
    }
    Write-Host "Cleanup done." -ForegroundColor Green
    return
}

# ---------- BUILD ----------
# -SkipBuild reuses the probes when present; if absent (e.g. after -Cleanup
# wiped tests/bin/), build anyway — a flag must never produce a broken run.
if ((-not $SkipBuild) -or (-not (Test-Path $exe)) -or (-not (Test-Path $dll))) { Build-Probes }

if (-not $Execute) {
    Write-Host "DRY-RUN (no actions taken). Re-run with -Execute to fire these." -ForegroundColor Yellow
}

# ---------- EXEC / LOLBins ----------
if (Want 'exec') {
    Step 'EXEC-001 EXEC-002 PERSIST-001' "conhost --headless powershell -ep bypass from a user-writable path (the incident shape)" {
        $payload = Join-Path $temp 'selftest-payload.ps1'
        'Write-Host sentinel-selftest' | Set-Content $payload
        & conhost.exe --headless powershell.exe -ExecutionPolicy Bypass -File $payload
    }
    Step 'EXEC-001' "powershell -ep bypass + Reflection.Emit/WriteProcessMemory tokens (no real injection)" {
        & powershell.exe -ExecutionPolicy Bypass -Command "Write-Host ('Reflection.Emit WriteProcessMemory' | Out-String)"
    }
    Step 'EXEC-003' "cscript running a .vbs under Temp (LOLBin + script token); not Docker's regList path, so dev_scripts does NOT except" {
        $vbs = Join-Path $temp 'test.vbs'
        'WScript.Echo "sentinel-selftest"' | Set-Content $vbs
        & cscript.exe //nologo $vbs
    }
}

# ---------- DROPPER (random/hex exe from Temp + credential-copy shape) ----------
if (Want 'dropper') {
    Step 'EXEC-004' "hex-named exe launched from Temp" {
        Copy-Item $exe (Join-Path $temp 'deadbeef.exe') -Force
        & (Join-Path $temp 'deadbeef.exe') dropper
    }
    Step 'CRED-001' "non-browser process copies a browser-vault-named file (fake, empty)" {
        '' | Set-Content (Join-Path $temp 'logins.json')
        Copy-Item (Join-Path $temp 'logins.json') (Join-Path $temp 'logins-copy.json')
    }
}

# ---------- PERSISTENCE ----------
if (Want 'persistence') {
    Step 'PERSIST-001' "schtasks /create with -ep bypass + ProgramData path (needs admin)" {
        if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')) {
            Write-Warning "PERSIST-001 skipped: schtasks /create needs an elevated shell."
        } else {
            & schtasks.exe /Create /TN $taskName /SC ONLOGON /RL LIMITED `
                /TR "powershell.exe -ExecutionPolicy Bypass -File C:\ProgramData\sentinel-selftest.ps1" /F
        }
    }
    Step 'PERSIST-003' "Run-key write (HKCU\...\Run)" {
        if (-not (Test-Path $runKey)) { New-Item $runKey -Force | Out-Null }
        New-ItemProperty -Path $runKey -Name 'SentinelSelfTest' -Value 'cmd /c echo sentinel-selftest' `
            -PropertyType String -Force | Out-Null
    }
    Step 'PERSIST-004' ".ps1 dropped in Startup folder" {
        'Write-Host sentinel-selftest-startup' | Set-Content $startup
    }
    Step 'PERSIST-005' "bogus service subkey write under HKLM\...\Services (needs admin; ImagePath-resolver helper not in engine, so this is a raw EID 13 check)" {
        if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')) {
            Write-Warning "PERSIST-005 skipped: needs an elevated shell."
        } else {
            New-Item $svcKey -Force | Out-Null
            New-ItemProperty -Path $svcKey -Name 'ImagePath' -Value "C:\ProgramData\$svcName.exe" -PropertyType String -Force | Out-Null
        }
    }
}

# ---------- CONFIG TAMPER ----------
if (Want 'config') {
    Step 'CONFIG' "write a probe file into rules.d (real install dir, NOT Temp -> not filtered by filter_temp)" {
        'sentinel-selftest-probe' | Set-Content (Join-Path (Join-Path $repoRoot 'rules.d') 'zz-selftest-probe.tmp')
    }
}

# ---------- DEFENSE EVASION (AMSI tokens) ----------
if (Want 'evade') {
    # EVADE-001's selection_cli matches CommandLine containing any of
    # amsi/AmsiUtils/GetAssemblies/System.dll/GlobalAssemblyCache. We use
    # 'System.dll' (a benign echo), NOT the AmsiUtils reflection payload: that
    # signature is the textbook AMSI bypass, and Defender ASR blocks it at the
    # process-creation layer (the launch returns 'Access is denied' and no
    # process is created -> no Sysmon EID 1 -> EVADE-001 can't fire). Echoing
    # 'System.dll' satisfies the rule's cmdline token without tripping ASR.
    Step 'EVADE-001' "powershell cmdline carrying a rule-matching token (System.dll echo; not a bypass, so ASR won't block it)" {
        & powershell.exe -Command "Write-Host System.dll"
    }
}

# ---------- NETWORK ----------
# Sysmon EID 3 fires on an ESTABLISHED connection. Pointing the probe at a port
# with nothing listening (e.g. discard :9) gets a refused connection and produces
# no EID 3, so neither NET rule can fire. Instead spin up a throwaway loopback
# listener on an OS-assigned high port, connect to it, then stop it. The
# handshake completes at the kernel level before Accept() is called, so EID 3
# fires even though we never read. NET-005's known_loopback_listeners except
# only lists 127.0.0.1:9080, so an ephemeral port is NOT excepted -> fires.
if (Want 'net') {
    Step 'NET-004 NET-005' "Temp-resident exe connects to a live loopback listener on an ephemeral port" {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
        try {
            & (Join-Path $temp 'deadbeef.exe') connect 127.0.0.1 $port
            Start-Sleep -Milliseconds 300   # let Sysmon flush the EID 3
        } finally {
            $listener.Stop()
        }
    }
}

# ---------- INJECTION (dangerous) ----------
if (Want 'inject') {
    if (-not $IncludeDangerous) {
        Write-Host ""
        Write-Host "inject scenarios skipped (need -IncludeDangerous AND elevation)." -ForegroundColor DarkGray
    } else {
        if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')) {
            Write-Warning "inject scenarios need an ELEVATED shell; skipping."
        } else {
            $tempDll = Join-Path $temp 'payload.dll'
            Step 'INJECT-002' "Temp-resident loader LoadLibrary's an unsigned Temp DLL (EID 7)" {
                Copy-Item $dll $tempDll -Force
                Copy-Item $exe (Join-Path $temp 'loader.exe') -Force
                & (Join-Path $temp 'loader.exe') loader $tempDll
            }
            Step 'INJECT-001' "CreateRemoteThread into a sacrificial notepad (ExitThread start addr)" {
                $np = Start-Process notepad.exe -PassThru
                Start-Sleep -Milliseconds 400
                & $exe inject $np.Id
                Stop-Process -Id $np.Id -Force -ErrorAction SilentlyContinue
            }
            Step 'CRED-002' "OpenProcess(lsass, VM_READ) then close immediately (reads nothing; may trip Defender)" {
                & $exe lsass
            }
        }
    }
}

if (-not $Execute) {
    Write-Host ""
    Write-Host "Done planning. Verify each [RULE-XXX] in Sentinel's alerts/log, then:" -ForegroundColor Yellow
    Write-Host "    powershell -ExecutionPolicy Bypass -File tests/Invoke-DetectionTests.ps1 -Execute" -ForegroundColor Yellow
    Write-Host "When finished:" -ForegroundColor Yellow
    Write-Host "    powershell -ExecutionPolicy Bypass -File tests/Invoke-DetectionTests.ps1 -Cleanup" -ForegroundColor Yellow
} else {
    Write-Host ""
    Write-Host "Scenarios executed. Check Sentinel alerts + sentinel.log, then run -Cleanup." -ForegroundColor Green
}

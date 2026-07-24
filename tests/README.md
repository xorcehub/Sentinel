# Sentinel detection self-test harness

Benign scenarios that make Sysmon emit the exact events the Sentinel rules key
on, so you can confirm each rule fires end-to-end (event → engine → alert).

**This tests your own tool on your own box.** Every payload is inert: an echo,
a marker file, a one-byte loopback connect, or a `LoadLibrary` of a stub DLL.
Nothing beacons, exfiltrates, or persists anything real.

## Files

| file | role |
|---|---|
| `detection-bin.go` | one multi-mode probe: `dropper`, `connect`, `loader`, `inject`, `lsass`. `//go:build ignore` so CI's `go build ./...` skips it. |
| `payload-dll.go` | unsigned stub DLL for the INJECT-002 EID 7 case. c-shared. |
| `Invoke-DetectionTests.ps1` | driver. Builds the probes, runs scenarios, maps each to the rule(s) it fires, cleans up. **Dry-run by default.** |

## Quick start

```powershell
# 1. See the full plan (no actions taken):
powershell -ExecutionPolicy Bypass -File tests/Invoke-DetectionTests.ps1

# 2. Actually run the safe scenarios:
powershell -ExecutionPolicy Bypass -File tests/Invoke-DetectionTests.ps1 -Execute

# 3. Confirm each [RULE-XXX] fired in Sentinel's alerts + sentinel.log,
#    then tear everything back down:
powershell -ExecutionPolicy Bypass -File tests/Invoke-DetectionTests.ps1 -Cleanup
```

## Scenario → rule matrix

| Category | Scenario | Fires |
|---|---|---|
| exec | `conhost --headless powershell -ep bypass` from Temp (the incident shape) | **EXEC-001, EXEC-002, PERSIST-001** |
| exec | `powershell -ep bypass` + `Reflection.Emit`/`WriteProcessMemory` cmdline tokens | **EXEC-001** |
| exec | `cscript` running a `.vbs` under Temp (not Docker's `regedit\vbs\regList.wsf`, so dev_scripts does NOT except) | **EXEC-003** |
| dropper | hex-named `deadbeef.exe` run from `%TEMP%` | **EXEC-004** |
| dropper | non-browser process copies a vault-named file (`logins.json`, fake/empty) | **CRED-001** |
| persistence | `schtasks /create` + `-ep bypass` + `ProgramData` path | **PERSIST-001** |
| persistence | write to `HKCU\...\Run` | **PERSIST-003** |
| persistence | `.ps1` dropped in Startup folder | **PERSIST-004** |
| persistence | bogus service subkey under `HKLM\...\Services` (elevated) | **PERSIST-005** |
| config | probe file written into `rules.d\` (real dir, not Temp → not filtered by `filter_temp`) | **CONFIG (tamper)** |
| evade | cmdline carrying the `System.dll` token (a benign echo — the AmsiUtils reflection payload is ASR-blocked at process creation, so it never spawns a process to detect) | **EVADE-001** |
| net | Temp-resident exe connects to a throwaway loopback listener on an OS-assigned ephemeral port | **NET-004, NET-005** |
| inject | Temp loader `LoadLibrary`s unsigned Temp DLL (EID 7) | **INJECT-002** ⚠ |
| inject | `CreateRemoteThread(ExitThread)` into sacrificial notepad (EID 8) | **INJECT-001** ⚠ |
| inject | `OpenProcess(lsass, VM_READ)` then close — reads nothing | **CRED-002** ⚠ |

⚠ = behind `-IncludeDangerous` AND requires an elevated shell. The lsass open may
trip Windows Defender independently of Sentinel; run on a box where that's OK.

## Notes on the matrix

- **Scenario ordering:** the `net` step reuses `%TEMP%\deadbeef.exe`, which is
  created by the `dropper` step. Running `-Category net` alone silently no-ops
  (the connect is wrapped in try/catch, so it reports `STEP FAILED` and moves on).
  Use `-Category dropper,net` or the default (`all`).
- **Telemetry-feed dependence:** CRED-001 (`.json` FileCreate), INJECT-002
  (EID 7 from Temp), and NET-005 (loopback EID 3) only fire if the **Sysmon
  config** actually captures those event IDs / paths. If a scenario runs but no
  alert appears, confirm the config subscribes to that EID before assuming the
  rule is broken — the harness can't control Sysmon's event subscription.

## What is deliberately NOT covered

- **NET-002 / NET-003** (public outbound): would need real egress. The net
  scenario proves the loopback path (NET-004/005); pointing a Temp exe at a
  public host is left to the operator.
- **PERSIST-002** (WMI event subscription): creation is heavyweight and very
  detectable by Defender; skipped to keep the harness non-destructive.
- **CRED-003** (SAM/SYSTEM/SECURITY/ntds.dit): faithful triggering needs raw
  disk / shadow copy; out of scope for a benign harness.
- **BASE-001**: emitted by the daily baseline-diff job, not by a Sysmon event;
  exercise it by running the baseline scan after any PERSIST-* scenario.

## Why Go and not C

`golang.org/x/sys` is already a dependency and the operator builds `sentinel.exe`
with Go, so the probes build with `go build` — no compiler roulette. The
`inject`/`lsass` modes use `x/sys/windows` (`OpenProcess`, `CreateRemoteThread`,
toolhelp snapshot) directly. `payload-dll.go` uses `-buildmode=c-shared`.

## Safety / cleanup

Every artifact created by `-Execute` is removed by `-Cleanup`:

- scheduled task `SentinelSelfTestTask`
- `HKCU\...\Run\SentinelSelfTest` value
- service key `HKLM\...\Services\SentinelSelfTestSvc`
- `%STARTUP%\sentinel-selftest.ps1`
- `rules.d\zz-selftest-probe.tmp`
- `%TEMP%\sentinel-test.marker`, `deadbeef.exe`, `logins.json*`, `test.vbs`,
  `payload.dll`, `loader.exe`
- built binaries under `tests\bin\`

`-Cleanup` is idempotent — run it any number of times.

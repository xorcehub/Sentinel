# Sentinel (working name)

> **Not affiliated with Microsoft Sentinel or SentinelOne.**

[![CI](https://github.com/xorcehub/sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/xorcehub/sentinel/actions/workflows/ci.yml)

> A behavior-based endpoint guard for a single Windows power-user workstation.
> Evaluates Sigma-style rules against live Sysmon events, alerts the user
> on the workstation, and **forensically captures files that match create-and-delete
> patterns before they vanish**.

*Concrete case: an editor (Cursor) drops a `<Temp>\ps-script-<guid>.ps1`, runs
it as `powershell -ep bypass`, and deletes it the instant it exits. Its
contents are gone before you can open them. Sentinel snapshots that file into
a vault before the delete lands — and back-links the alert that names it.*

Not an EDR. Not a SIEM. Not a fleet tool. Not a Defender replacement.
Deliberately scoped to one operator, one box — see [Boundaries](#boundaries).

---

## Quick facts

| | |
|---|---|
| **Role** | Single-host behavior detector + forensic capture |
| **Language** | Go (module `sentinel`, Go 1.26) — ~8.0k LOC core + ~8.2k tests, 82 files, 40 test files, 3 fuzz targets |
| **Platform** | Windows 10 1607+ / Windows 11 (latest Sysmon from Sysinternals; installer pulls the current release, no version is pinned) |
| **Telemetry source** | Sysmon (real-time, 1s poll) + Sysinternals Autoruns (daily persistence diff) |
| **Detection paradigms** | Catch-by-act behavior rules + catch-by-result baseline diff |
| **Coverage** | **26 hand-curated rules** across 9 categories, mapping to ~20 MITRE ATT&CK techniques |
| **License** | MIT — [`LICENSE`](LICENSE); deps MIT/BSD/Apache only — [`THIRDPARTY.md`](THIRDPARTY.md) |
| **Threat model** | Self-assessed — [`THREAT-MODEL.md`](THREAT-MODEL.md). Read before deploying. |

Two binaries, both built by `install.ps1`: `sentinel.exe` (the daemon, runs as
SYSTEM) and `sentinel-tray.exe` (a user-session toast relay).

---

## What it does

- Reads `Microsoft-Windows-Sysmon/Operational` in real time (1s poll; a native
  `EvtSubscribe` path exists but is broken — see `-sysmon-native`).
- Evaluates **26 Sigma-style rules** (in-house evaluator, no external Sigma
  library) across persistence, execution, network, credential, injection,
  evasion, baseline, config-tamper, and telemetry-integrity. Rules live in [`rules.d/`](rules.d)
  as Sigma YAML with an `x-sentinel:` extension block for routing/severity.
- **Watches its own telemetry.** If no Sysmon event arrives for 10 minutes
  (default), the daemon fires one critical `HEALTH-001` hit per stale episode
  and flags `sysmon=STALE` in the heartbeat — a dead feed can no longer look
  like a quiet machine. Sysmon config changes (EID 16) raise `TELEMETRY-001`.
- On a hit, fans out to four alert channels: **popup, toast, Windows Event
  Log, and `ALERTS.log`**. Every severity toasts (suspicious silently, no
  banner sound). With popup on, criticals also toast silently alongside the
  MessageBox; the installed task's `-popup=false` (an unattended daemon
  shouldn't block on a click) instead makes the critical hit's toast the loud
  looping-alarm variant — same channel, louder tier. Every hit gets a per-hit correlation ID (`hid`)
  stamped across the popup, EventLog, and ALERTS.log channels (toast omits it
  — too little room).
- Forensically captures files matching `file_capture.patterns` in
  [`config/allowlist.json`](config/allowlist.json) into a vault before they
  can be deleted. Content files are written **without an extension** (can't be
  double-clicked into execution); a `manifest.json` sidecar carries sha256,
  parent process, and status (`ok` / `truncated` / `lost-race`).
- **Detection is never blinded by suppression.** The noise filter and capture
  hook run *after* rule evaluation — never before. Regression tests in
  `internal/rules/catalog_blindspot_test.go` and
  `internal/app/noise_blinds_test.go` pin this invariant.

---

## Persistence baseline diffing

The real-time rules catch the *act* of persistence — a Run key being written,
a service being created. They can't catch what landed while the daemon was
down, while the Sysmon log rolled, or via a quiet installer that triggered no
LOLBin and no network connection. The baseline diff catches the *result*.

Once a day (default 04:00 local), Sentinel shells out to Sysinternals
`autorunsc64.exe -a * -c -s -t` — all ~262 persistence locations, CSV output,
signature-verified, UTC-normalized timestamps — and diffs it against a clean
baseline. The baseline is captured once on a verified machine via
`sentinel -baseline-snapshot`, operator-reviewed, and committed as
`baseline_clean.csv`; it is **not** auto-trusted on first run (a classic
false-anchor bug).

- **Diff key is `Location + Entry`.** A Discord update (new version/signer/
  time) keeps the same key and does *not* fire. Only genuinely new
  persistence surfaces alert. Removed entries are ignored — uninstallers
  remove things constantly, so removals would be pure noise.
- **New entries flow through the same engine as Sysmon events**, emitted as
  synthetic events (`Source=baseline`, `EID=0`). `BASE-001` is just another
  rule, routed through the same alert channels and dedup as the rest. No
  second pipeline.
- **Alert-once per entry**, persisted in `state.db`. A new entry surfaces on
  the first scan that sees it and is silenced on subsequent scans until the
  baseline is re-captured — so a daily scan doesn't re-alert yesterday's
  finding.

```powershell
# Capture the clean reference on a verified machine, review + commit it:
sentinel -baseline-snapshot          # writes baseline_clean.csv (gitignored)

# Manually diff current state vs the committed baseline (prints new entries):
sentinel -baseline-now
```

Degrades silently when `autorunsc64.exe` isn't installed (one startup warning,
no daily failures; `install.ps1` step 8 also warns at install time). The daily scan additionally no-ops if no clean baseline
exists yet.

---

## Design decisions

1. **Detection is never blinded by suppression.** The obvious place to filter
   noise is before the engine. That's also the place where a wrong allowlist
   entry silently disables a detection. Sentinel filters *after* eval, and two
   regression tests assert that every rule can still fire against an
   allowlist of every actor it targets. Suppression is a logging concern, not a
   detection concern.

2. **The allowlist refuses to trust the LOLBins.** The naive "trust
   `\windows\system32\.*\.exe`" glob also trusts every Living-Off-the-Land
   binary the rules hunt (`powershell`, `certutil`, `mshta`, `regsvr32`, …) —
   so it silently disarms every rule that uses `except: image_in_allowlist`.
   Instead, only specific, named session/service binaries are trusted, by
   exact filename. Comments in `config/allowlist.json` spell out the reasoning.

3. **Layered capture for create-and-delete droppers.** Best-effort EID 11
   snapshot races the delete; Sysmon's EID 23 `ArchiveDirectory` is the
   guaranteed backstop. Misses produce a `lost-race` manifest so the operator
   knows the create was *seen*; the alert's `hid` is back-linked into the
   matching capture's manifest.

4. **Session-0 crossing.** A SYSTEM Scheduled Task lives in
   Session 0, where MessageBoxes render to a ghost desktop and WinRT toasts
   get "Access is denied." Popups cross via `WTSSendMessageW`; toasts hand off
   to a user-session relay over a named pipe (`\\.\pipe\sentinel-toast`,
   4 instances, bursts beyond four drop best-effort). The pipe is
   **unauthenticated** — documented as a known boundary in the threat model,
   not a hidden one.

5. **Degrade-silently contracts.** If the engine, allowlist, snapshot vault,
   or ALERTS.log can't initialize, the daemon keeps running in a reduced mode
   rather than refusing to start. A capture flood can't stall ingestion (the
   snapshotter is non-blocking, default-drop on a full buffer). A malformed
   Sysmon event triggers a per-event `recover()` and skips *one* event — never
   crashes the daemon.

6. **Self-assessed threat model.** What it stops, what it doesn't,
   where the trust boundary is (an attacker with SYSTEM can kill it), and why
   that's the same line every host-based detector shares. See
   [`THREAT-MODEL.md`](THREAT-MODEL.md).

---

## MITRE ATT&CK coverage

| Tactic | Technique | Rules |
|--------|-----------|-------|
| **Persistence** | T1053.005 Scheduled Task | PERSIST-001 |
| | T1546.003 WMI Event Subscription | PERSIST-002 |
| | T1546.015 COM Hijack | PERSIST-006 |
| | T1547.001 Registry Run Keys / Startup Folder | PERSIST-003, PERSIST-004 |
| | T1543.003 Windows Service | PERSIST-005 |
| **Execution** | T1059.001 PowerShell | EXEC-001, EXEC-002 |
| | T1218 System Binary Proxy Execution (LOLBins) | EXEC-003 |
| | T1027 Obfuscated/Random-name Executable | EXEC-004 |
| | T1204 / T1566 User Execution via Office/Doc parent | EXEC-005 |
| **Defense Evasion** | T1562.002 Disable Tools: AMSI | EVADE-001 |
| | T1562.001 Impair Defenses (config tamper) | CONFIG-001, TELEMETRY-001 |
| | T1055 Process Injection / Hollowing (INJECT-003) | INJECT-003 |
| **Credential Access** | T1555 Credentials from Password Store (browser vault) | CRED-001 |
| | T1003.001 LSASS Memory | CRED-002 |
| | T1003.002 Security Account Manager | CRED-003 |
| **Discovery / C2** | T1071 Application Layer Protocol | NET-002, NET-003 |
| | T1571 Non-Standard Port (loopback broker) | NET-001, NET-005 |
| | Outbound from user-writable path | NET-004 |
| **Priv. Escalation** | T1055 / T1055.001 Process/DLL Injection | INJECT-001, INJECT-002 |
| **Baseline** | New persistence entry vs clean baseline | BASE-001 |

---

## Testing & fuzzing

- **Three parsers fuzzed** — `sysmonxml`, `sigmaeval`, `allowlist` — each for
  5 minutes on the host (no crashes). The tray and snapshot parsers are pure
  stdlib `json.Unmarshal` with no in-house surface.
- **Per-event `recover()`** contains any unfound panic so a malformed event
  skips one event instead of crashing the daemon.
- **Invariant tests** pin the load-bearing security properties:
  `catalog_blindspot_test.go` (detections survive a hostile allowlist),
  `noise_blinds_test.go` (the noise filter can't suppress a real hit).
- **`sentinel -self-test`** runs an incident-coverage regression of 12
  representative vectors (core rules' motivating incidents), then exits. The
  **full** per-rule regression — every catalog rule must fire on its vector
  against the real shipped config — is
  `internal/rules/catalog_vector_test.go` (`go test ./internal/rules`).
- **`sentinel -self-test` is portable** — pure engine check, no mutex,
  ingestion, or alerters. It builds and runs on non-Windows too (the Windows
  alerters compile to no-op stubs behind build tags), so a reviewer on Linux
  or macOS can clone and run the catalog regression without Sysmon.
- *Caveat:* continuous fuzzing is not wired into CI, and binary releases are
  not signed. Both are named as known limitations in the threat model.

---

## How it works

```
   untrusted ──▶  Sysmon kernel driver (Microsoft, trusted)
                       │  Microsoft-Windows-Sysmon/Operational
                       ▼
                 sentinel.exe  (SYSTEM, Session 0)
                   parses XML, evaluates rules,
                   reads C:\SentinelArchive, writes vault + logs
                       │  \\.\pipe\sentinel-toast  (named pipe, local)
                       ▼
                 sentinel-tray.exe  (user, Session 1+)
                   reads pipe, fires WinRT toast via beeep
```

The daemon runs as SYSTEM in Session 0. Session 0 cannot show MessageBoxes or
fire toasts on the interactive desktop, so:

- **Popup:** crosses to the active console session via `WTSSendMessageW`.
- **Toast:** the daemon writes one-line JSON to a named pipe; the user-session
  `sentinel-tray.exe` relay reads it and calls `beeep.Notify`. **Best-effort:**
  no AUMID/Start-Menu shortcut is registered, so toasts may not persist in
  Action Center; treat the log/eventlog/popup channels as authoritative.
- **EventLog / file log:** work directly from SYSTEM (no session dependency).

Pipe protocol: one connection = one toast. Client writes `{title, body, severity}` JSON
and closes; server reads until EOF, parses, toasts. Four concurrent pipe
instances; bursts beyond four drop silently (best-effort contract). The pipe
is **unauthenticated** in the current build — a user-session process could
squat it to suppress or spoof toasts (not RCE, not detection bypass — popup,
log, and eventlog channels are unaffected). Acceptable on a single-user box;
the pipe ACL would need hardening before use on a multi-user host.

---

## Try it

```powershell
# 1. Clone + build (needs the Go toolchain + Windows)
go build -o sentinel.exe ./cmd/sentinel

# 2. Run the incident-coverage regression (portable, no Sysmon needed)
./sentinel.exe -self-test
#    -> prints ✓/✗ per rule against its motivating vector; writes self-test.txt

# 3. Full install (elevated PowerShell) — installs Sysmon, registers the task
powershell -ExecutionPolicy Bypass -File install.ps1
```

`-self-test` is the fastest way to see the detector work without a live attack.

---

## Requirements

- Windows 10 1607+ or Windows 11
- **Go toolchain on PATH** (only needed for `install.ps1`, which builds from
  source; not needed to run an already-built binary)
- **Elevated (Administrator) PowerShell** for install and uninstall
- No prior Sysmon install required — `install.ps1` installs Sysmon with the
  SwiftOnSecurity base config and patches in the FileCreate/FileDelete
  telemetry it needs. If Sysmon is already installed, **its config is replaced
  with SwiftOnSecurity** (FileCreate/FileDelete/`ArchiveDirectory` are then
  merged on top). Back up any hand-tuned config first.

## Install

From an elevated PowerShell in the repo root:

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1
```

`install.ps1` runs eight idempotent steps:

1. Build `sentinel.exe` + `sentinel-tray.exe` (with `-H windowsgui`)
2. Install Sysmon + SwiftOnSecurity base config (re-applies SwiftOnSecurity if already installed)
3. Patch Sysmon config: FileCreate (EID 11) + FileDelete (EID 23) + `<ArchiveDirectory>`
4. Register the `Sentinel` Windows Event Log source
5. Register the Scheduled Task as **SYSTEM** (at-logon, auto-restart) — required
   to read Sysmon's SYSTEM-locked FileDelete archive at `C:\SentinelArchive`
6. Start the task
7. Install the toast relay (`HKLM\...\Run\SentinelTray`, started now and at
   every future logon)
8. Check for `autorunsc64.exe` (exe dir, `C:\Tools\Autoruns`, Sysinternals
   dir, PATH). Missing = the daily baseline diff silently disabled — the
   installer warns with download instructions; never fails the install.

Safe to re-run. Output paths (relative to the repo root):

| What | Path |
|------|------|
| Structured log | `sentinel.log` |
| Alerts log | `ALERTS.log` |
| Heartbeat | `heartbeat.log` |
| bbolt dedup state | `state.db` |
| Forensic vault | `forensics\sentinel-vault\` |
| Sysmon FileDelete archive | `C:\SentinelArchive\` (SYSTEM-only) |

### Verify

```powershell
Get-Content .\sentinel.log -Tail 8 | Select-String 'snapshot vault active','archive capture enabled','rules loaded'
Get-ScheduledTaskInfo Sentinel | Select-Object LastRunTime, LastTaskResult, NumberOfMissedRuns
```

## Uninstall

```powershell
powershell -ExecutionPolicy Bypass -File uninstall.ps1
```

Stops the task, unregisters it, kills the tray, removes the `HKLM\...\Run`
entry, unregisters the Event Log source, and deletes the binary + vault.

Flags:

- `-KeepVault` — keep the forensic vault (default: delete). The vault is
  evidence; pass this to preserve captures.
- `-RemoveLog` — also delete `sentinel.log`, `ALERTS.log`, `heartbeat.log`
  (default: keep).

**Does not uninstall Sysmon itself** (other tools may depend on it) and does
not touch the Sysmon config. Revert those manually if needed.

---

## Configuration

Three knobs, all file-based (loaded at daemon startup — restart the task to
apply changes):

| File | Purpose |
|------|---------|
| `rules.d/*.yml` | Sigma rules + `x-sentinel:` extension. Edit to add/tune detection. |
| `config/allowlist.json` | Trusted binaries (incl. Tier-2 hash-gated signature trust, `hash_gated_path`), allowed destinations, dev-tool paths, event-log noise filter, `file_capture.patterns`. JSONC (comments allowed). |
| `config/sentinel.conf.example` | Documents the runtime knobs and defaults. The daemon currently reads CLI flags (see `sentinel -h`); this file is the spec for the Phase 2 config-file loader. |

### Adding a rule

Rules are [Sigma](https://github.com/SigmaHQ/sigma) YAML, one per document
(separated by `---`), dropped into `rules.d/`. Each rule carries the standard
Sigma fields (`title`, `id`, `logsource`, `detection`, `condition`, `level`,
`tags`) plus an `x-sentinel:` extension block that controls engine behavior.

**Required `x-sentinel:` fields:**

| Field | Values | Purpose |
|-------|--------|--------|
| `id` | mnemonic like `PERSIST-004`, `EXEC-001` | Stable ID stamped in logs, dedup, EventLog, alerts. `EXEC-001` style is conventional. |
| `severity` | `critical` / `suspicious` / `info` | Routes the alert. `critical` surfaces a blocking popup (or, with `-popup=false`, the loud looping-alarm toast) and carries the severity in the toast text. |
| `alert` | subset of `[popup, toast, log, eventlog]` | Which channels fire on hit. `log` should always be present. |

**Optional `x-sentinel:` fields:**

| Field | Purpose |
|-------|--------|
| `except` | Suppress hits matching an allowlist operator (see below). |
| `note` | Free-text rationale; shown in some alert contexts. |
| `target_key` | Override the dedup grouping key (default: rule + image). |
| `dedup` | Dedup window override (e.g. `{window: 15m}`). |

**`except` operators** (each takes an `allowlist.json` section name):

| Operator | Suppresses when |
|----------|----------------|
| `image_in_allowlist: trusted_binaries` | The hit process image is trusted. |
| `image_in_dev_tools: dev_tool_paths` | The hit process is a known dev tool. |
| `cmdline_in_dev_scripts: dev_scripts` | The command line matches a known dev script. |

Minimal working example (drop into `rules.d/mine.yml`, restart the task) — uses
a fresh prefix/number so it doesn't collide with shipped rules:

```yaml
title: Executable written to Startup folder
id: 7b3c1d2e-1234-5678-9abc-def012345678
status: experimental
logsource: { product: windows, service: sysmon }
detection:
  selection:
    EventID: 11
    TargetFilename|contains: '\Start Menu\Programs\Startup'
  condition: selection
level: high
tags: [attack.persistence, attack.t1547.001]
x-sentinel:
  id: MINE-001
  severity: critical
  alert: [popup, toast, log, eventlog]
  except:
    image_in_allowlist: trusted_binaries
```

Mnemonic IDs are stable across logs, dedup state, and the self-test regression
(`sentinel -self-test`). When you add a rule, pick a category prefix that
matches an existing one (`EXEC-`, `PERSIST-`, `NET-`, `CRED-`, `INJECT-`,
`EVADE-`, `BASE-`, `CONFIG-`, `TELEMETRY-`) and the next free number, or mint
a new prefix.

### All CLI flags

```powershell
sentinel -h
```

Notable: `-debug` (default **on** — DEBUG output is useful while tuning; flip
to `info` in production with `-debug=false`, no recompile), `-trace-events`
(per-event raw dump, default off — firehose, for rule-tuning only), `-raw`
(log events without running the engine), `-self-test` (incident-coverage
regression against the catalog, then exit), `-snapshot-dir` (empty = capture
disabled).

---

## Updating

- **Rule or allowlist update:** edit the files, restart the task. No rebuild.
- **Binary update:** stop the task, swap `sentinel.exe` / `sentinel-tray.exe`
  at their install path, restart the task. No re-registration, no re-install.

```powershell
Stop-ScheduledTask Sentinel
# (swap the binaries)
Start-ScheduledTask Sentinel
```

`install.ps1` is not required for updates — steps 2-7 (Sysmon, telemetry, event
source, task registration, tray) are one-time. Re-running it is safe but does
more work than an update needs.

## Roadmap

- **YARA retro-hunting of vault captures** — scan the forensic vault's captured
  droppers against YARA rules (they're stored with sha256 + full content).
- **Continuous fuzzing in CI** — the three parser fuzzers exist
  (`internal/*/fuzz_test.go`); wiring them into CI is the remaining step.
- **Native `EvtSubscribe` ingestion** — replace the 1s poller once the
  subscription bug is fixed.

---

## Boundaries

This project is **a single power-user's workstation guard, not a product.** The
scope below is deliberate, not accidental — each is a scoping decision, with
the boundary documented in [`THREAT-MODEL.md`](THREAT-MODEL.md):

- **Not a Defender replacement.** Run alongside it. Defender does signatures;
  this does behavior. Complementary, not redundant.
- **No defense against an adversary who already has SYSTEM/Administrator.** At
  that trust level the attacker can kill the daemon, edit logs, delete the
  vault, plant false captures, or uninstall the whole thing. Same boundary
  every host-based detector shares.
- **Not a fleet / enterprise tool.** No central console, no agent-server comms,
  no remote management, no remote update channel.
- **Not a kernel/rootkit hunter.** Sysmon reports what it sees from kernel; a
  rootkit below Sysmon is invisible to us.
- **Binaries are not signed.** A determined attacker with write access to the
  install directory can swap them.
- **The Sysmon archive at `C:\SentinelArchive` grows forever.** No post-capture
  cleanup or periodic sweep yet. Plan for it.
- **The toast relay pipe is not ACL-hardened** and **fuzzing is not in CI.**
  Both named in the threat model.

**Parser hardening is partial.** The three in-house parsers (`sysmonxml`,
`allowlist`, `sigmaeval`) are each fuzzed for 5 minutes on the host (no
crashes) and a per-event `recover()` contains any unfound panic. Continuous
fuzzing in CI is not wired; binary releases are not signed. See
[`THREAT-MODEL.md`](THREAT-MODEL.md).

---

## License

MIT — see [`LICENSE`](LICENSE). Third-party attributions in
[`THIRDPARTY.md`](THIRDPARTY.md).

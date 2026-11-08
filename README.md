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
| **Language** | Go (module `sentinel`, Go 1.26) — ~8.0k LOC core + ~8.8k tests, 82 files, 40 test files, 3 fuzz targets |
| **Platform** | Windows 10 1607+ / Windows 11 (latest Sysmon from Sysinternals; installer pulls the current release, no version is pinned) |
| **Telemetry source** | Sysmon (real-time, 1s poll) + Sysinternals Autoruns (daily persistence diff) |
| **Detection paradigms** | Catch-by-act behavior rules + catch-by-result baseline diff |
| **Coverage** | **27 hand-curated rules** across 9 categories, mapping to ~20 MITRE ATT&CK techniques |
| **License** | MIT — [`LICENSE`](LICENSE); deps MIT/BSD/Apache only — [`THIRDPARTY.md`](THIRDPARTY.md) |
| **Threat model** | Self-assessed — [`THREAT-MODEL.md`](THREAT-MODEL.md). Read before deploying. |

Two binaries, both built by `install.ps1`: `sentinel.exe` (the daemon, runs as
SYSTEM) and `sentinel-tray.exe` (a user-session toast relay).

---

## What it does

- Reads `Microsoft-Windows-Sysmon/Operational` in real time (1s poll; a native
  `EvtSubscribe` path exists but is broken — see `-sysmon-native`).
- Evaluates **27 Sigma-style rules** (in-house evaluator, no external Sigma
  library) across persistence, execution, network, credential, injection,
  evasion, baseline, config-tamper, and telemetry-integrity. Rules live in [`rules.d/`](rules.d)
  as Sigma YAML with an `x-sentinel:` extension block for routing/severity.
- **Watches its own telemetry.** If no Sysmon event arrives for 10 minutes
  (hard-coded for now — no flag or config knob yet), the daemon fires one
  critical `HEALTH-001` hit per stale episode
  and flags `sysmon=STALE` in the heartbeat — a dead feed can no longer look
  like a quiet machine. Sysmon config changes (EID 16) raise `TELEMETRY-001`;
  clearing the Sysmon log raises critical `TELEMETRY-002` (from System log
  EID 104, which names the channel, the account and the backup path; read
  with a 24h look-back, so a clear made while Sentinel was stopped alerts at
  the next start). A recreated channel whose RecordIds go backwards raises
  it too, and the poller resets its high-water and keeps ingesting.
- On a hit, fans out to four alert channels: **popup, toast, Windows Event
  Log, and `ALERTS.log`**. Every severity toasts except `info` (log-only by
  default) — suspicious silently, no banner sound. A rule's own `alert:` list
  *replaces* that default channel set instead of merging with it
  (`NET-003` ships log-only). With popup on, criticals also toast silently
  alongside the MessageBox; the installed task's `-popup=false` (an
  unattended daemon shouldn't block on a click) instead makes the critical
  hit's toast the loud looping-alarm variant — same channel, louder tier.
  Every hit gets a per-hit correlation ID (`hid`) stamped across the popup,
  EventLog, and ALERTS.log channels (toast omits it — too little room).
- Forensically captures files matching `file_capture.patterns` in your live
  allowlist (start from [`config/allowlist.json.example`](config/allowlist.json.example)) into a vault before they
  can be deleted. Content files are written **without an extension** (can't be
  double-clicked into execution); a `manifest.json` sidecar carries sha256,
  parent process, and status (`ok` / `truncated` / `lost-race`).
- **Detection is never blinded by suppression.** The noise filter runs *after*
  rule evaluation; the capture hook runs in the forensics band *before* it, but
  is non-blocking and reads no rule input — neither can delay, drop or alter a
  hit. Regression tests in `internal/rules/catalog_blindspot_test.go` and
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
sentinel -baseline-snapshot          # writes baseline_clean.csv

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
   exact filename. Comments in `config/allowlist.json.example` spell out the reasoning.

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
| | T1070.001 Clear Windows Event Logs (Sysmon channel) | TELEMETRY-002 |
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
  against the worked example config — is
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
                   reads pipe, fires WinRT toast (go-toast, COM only)
```

The daemon runs as SYSTEM in Session 0. Session 0 cannot show MessageBoxes or
fire toasts on the interactive desktop, so:

- **Popup:** crosses to the active console session via `WTSSendMessageW`.
- **Toast:** the daemon writes one-line JSON to a named pipe; the user-session
  `sentinel-tray.exe` relay reads it and fires it via WinRT COM (no PowerShell fallback). **Best-effort:**
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

Before step 3: `copy config\allowlist.json.example config\allowlist.json.local`
and prune it for your box. The example is the tuning manual for the somewhat
unusual syntax — a real allowlist where every entry says which noise it kills
and why the regex looks like that — so copy from it rather than writing entries
from scratch. The daemon uses that file automatically whenever it exists and no
`-allowlist` flag is given (an explicit flag always wins), so manual runs and
re-installs never revert your tuning.

Rule tuning works the same way. The shipped rules in `rules.d/*.yml` carry no
filters for any particular machine's software; the tuning of the box they were
developed on (Cursor IDE, Claude Code CLI, a python helper, the Nahimic audio
stack) lives in `rules.d/local.example/` as suppress-only overlays. To use it:
`mkdir rules.d\local` and `copy rules.d\local.example\tuning.yml rules.d\local\`,
then delete the overlays for software you don't run. The daemon loads
`rules.d/local/` (gitignored) automatically.

Skip both steps and Sentinel runs with the plain defaults: every rule armed,
nothing trusted — expect noise until you tune (the heartbeat's `allowlist=ok`
just means the empty policy loaded fine), forensic file-capture stays off (no
patterns set) and DEBUG logging runs unfiltered.

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

All file-based (loaded at daemon startup — restart the task to
apply changes):

| File | Purpose |
|------|---------|
| `rules.d/*.yml` | Sigma rules + `x-sentinel:` extension, as shipped: generic, no filters for any particular machine's software, so a fresh clone runs every rule fully armed. Edit to add detection; put per-box noise filters in `rules.d/local/` instead. |
| `rules.d/local.example/` | **Your rule-tuning reference.** Overlays from the development box, each documenting the noise it quiets and the mimics that must still fire. Never loaded by the daemon. |
| `rules.d/local/` | **Your live rule overlays** (gitignored, optional). Each document names one rule (`x-sentinel-overlay: {rule: EXEC-001}`) plus its own `detection` block; that rule then fires only when its condition matches and the overlay's does not. Overlays can only suppress: they cannot add rules, widen selections, or change severity, alerting or `except`, and one naming an unknown rule fails the load. Startup logs `rules loaded … overlays=N`. Stays under `rules.d\`, so the config-tamper rule watches it. |
| `config/allowlist.json` | What Sentinel runs with out of the box: empty — every rule armed, nothing trusted, so expect noise until you tune. This file stays empty on purpose; make your tuning in `allowlist.json.local` (below) instead of editing it. |
| `config/allowlist.json.example` | **Your tuning reference.** A real allowlist, annotated by the tuning that went into it: every entry documents which noise class it kills and why its regex is shaped that way (the syntax is unusual — JSONC comments, `\`-escaped path regexes, patterns anchored to the drive root). Copy it to `allowlist.json.local` as your starting point. |
| `config/allowlist.json.local` | **Your live allowlist** — the file Sentinel actually runs with once you create it. Keep the name (the config-tamper alarm watches for `allowlist.json` in it). Gitignored; picked up by presence, like `rules.d/local/`: the daemon prefers it over `allowlist.json` whenever no `-allowlist` flag is given (an explicit flag always wins). Startup logs `allowlist loaded … local=true`. JSONC (comments allowed). |
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
| `alert` | subset of `[popup, toast, log, eventlog]` | Which channels fire on hit — **replaces** the severity's default channel set (no merge with it). `log` should always be present. |

**Optional `x-sentinel:` fields:**

| Field | Purpose |
|-------|--------|
| `except` | Suppress hits matching an allowlist operator (see below). |
| `note` | Free-text rationale; shown in some alert contexts. |
| `target_key` | What counts as "the same thing" for the cool-down below — default: same rule + same image + same command line. Example: add the destination IP:port so each remote host triggers its own alert. |
| `dedup` | Cool-down: once it has alerted, stay quiet about the same thing for this long (default 15 minutes). Write it as a single value — `dedup: 30m`. |

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

### Audit the shipped rules first

The catalog in [`rules.d/`](rules.d) and [`config/allowlist.json.example`](config/allowlist.json.example)
is a worked example from **one incident on one workstation**. Read it as
*"how to write rules for your own situation"*, not as a drop-in baseline:

- **Every `except:` operator and allowlist entry is a trust decision, not a
  tuning knob.** If the process or path it names doesn't belong on your
  machine, delete it rather than inherit it.
- **Prune the personal entries.** `dev_scripts` / `dev_tool_paths` name one
  operator's own tools and repo paths; `trusted_binaries` path patterns grant
  trust to whoever can write to those paths.
- **Capture `baseline_clean.csv` on the machine you deploy to** — it is not
  shipped (each machine's baseline is its own), so a fresh clone has none and
  the daily diff stays off until you run `sentinel -baseline-snapshot` there. If you did carry one over from
  another box, re-capture it: it measures against *that* box's idea of
  "clean", not yours.
- **Re-tune the noise settings** against your own `ALERTS.log` — per-rule
  `dedup` windows and `file_capture.patterns` (`HEALTH-001` staleness is
  hard-coded at 10 min for now). Then run
  `go test ./...` and `sentinel -self-test` so every rule still fires on its
  vector after your edits.

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
- **The rules and the example allowlist (`config/allowlist.json.example`) are
  a worked example, tuned to one machine.**
  Audit every `except:` and allowlist entry before deploying elsewhere — see
  [Audit the shipped rules first](#audit-the-shipped-rules-first).

**Parser hardening is partial.** The three in-house parsers (`sysmonxml`,
`allowlist`, `sigmaeval`) are each fuzzed for 5 minutes on the host (no
crashes) and a per-event `recover()` contains any unfound panic. Continuous
fuzzing in CI is not wired; binary releases are not signed. See
[`THREAT-MODEL.md`](THREAT-MODEL.md).

---

## License

MIT — see [`LICENSE`](LICENSE). Third-party attributions in
[`THIRDPARTY.md`](THIRDPARTY.md).

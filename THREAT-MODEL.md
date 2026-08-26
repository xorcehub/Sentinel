# Threat model

## What this project is

A two-binary, no-server Sysmon-driven detection framework for a Windows
workstation. It evaluates detection rules against Sysmon events in real time,
alerts the user locally (popup, toast, Windows Event Log, file log), and
forensically captures files that match suspicious create-and-delete patterns
before they vanish. One-shot install/uninstall. Runs as a SYSTEM Scheduled
Task. Targets Windows 10/11.

**What it is not:** an enterprise EDR, a SIEM, a fleet management tool, a
replacement for Defender, or a defense against a sophisticated adversary who
already has SYSTEM on the workstation. If you need any of those, use Wazuh, osquery,
Velociraptor, or a commercial EDR.

## Assets (what we protect)

1. **The user's awareness of suspicious activity on their own workstation.**
   The primary asset is timely, accurate notification — not prevention.
2. **Forensic evidence of transient files** (create-and-delete scripts) that
   would otherwise be unrecoverable after execution.
3. **The integrity of the audit trail** (logs, vault, manifests) — to the
   extent that integrity is achievable on-host (see non-goals).

## Adversaries

**In scope:**
- Malware or unauthorized tooling that runs in the user's session or as a
  user-mode child of a legitimate process (e.g., a malicious macro spawning
  PowerShell with `-enc`, a hijacked dev tool dropping a persistence entry).
- "Living off the land" techniques that abuse signed binaries.
- File-based artifacts (droppers, scripts) that execute and self-delete.

**Explicitly out of scope:**
- An adversary who already has **SYSTEM or Administrator** on this host. At
  that trust level the attacker can kill the daemon, edit logs, delete the
  vault, plant false captures, or uninstall the whole thing. We make no claim
  against a privileged local adversary. (This is the same boundary every
  host-based detector shares; it is fundamental, not a bug.)
- A physically present attacker with the ability to boot from external media,
  bypass Secure Boot, or modify the disk offline.
- Kernel-mode rootkits. Sysmon itself runs in kernel and reports what it sees;
  a rootkit below Sysmon is invisible to us.
- Supply-chain compromise of Microsoft, the Go toolchain, SwiftOnSecurity's
  sysmon-config, or our Go module dependencies.

## Trust boundaries

```
                  ┌─────────────────────────────────────────────┐
   untrusted ──▶     Sysmon kernel driver (Microsoft, trusted)  
                  └─────────────────────┬───────────────────────┘
                                        │ ETW channel (trusted)
                                        ▼
                 ┌─────────────────────────────────────────────┐
                 │  sentinel.exe (SYSTEM, Session 0)           │
                 │   - parses Sysmon XML                       │
                 │   - evaluates rules                         │
                 │   - reads C:\SentinelArchive                │
                 │   - writes vault (as SYSTEM)                │
                 │   - writes logs                             │
                 └─────────────────────┬───────────────────────┘
                                       │ named pipe (local)
                                       ▼
                 ┌─────────────────────────────────────────────┐
   user session  │  sentinel-tray.exe (user, Session 1+)       │
                 │   - reads pipe, fires WinRT toast           │
                 └─────────────────────────────────────────────┘
```

Two trust crossings matter:
- **Sysmon channel → sentinel.exe.** Events are treated as data. The XML
  parser and rule engine run on attacker-influenced input (an attacker who can
  trigger Sysmon events can shape the field values we parse). Go's memory
  safety contains the memory-corruption class of bugs; logic bugs (path
  traversal, regex DoS, rule-evaluation bypass) are still possible.
- **sentinel.exe → sentinel-tray.exe (named pipe).** See "Known limitations"
  below; this crossing is unauthenticated in the current build.

## Security properties we do provide

- **Detection is never blinded by logging decisions.** The noise filter and
  forensic-capture layer are purely additive — they run after rule evaluation,
  not instead of it. Regression tests (`catalog_blindspot_test.go`,
  `noise_blinds_test.go`) assert this invariant.
- **Detection survives a malformed event.** Each event is wrapped in a
  `recover()` at the ingest and dispatch boundaries, so a panic in any parser
  or rule handler (on attacker-shaped input) skips ONE event and logs WARN —
  the drain loop continues. A malformed event cannot crash the daemon or blind
  detection. The `panics_contained` heartbeat counter surfaces a spike.
  Regression test in `panic_containment_test.go`.
- **Allowlist suppression is config-driven and audited.** Nothing is silently
  dropped. Dedup-window suppressions are logged per-event at INFO; allowlist
  suppressions are accumulated and emitted as a DEBUG summary (rule, image,
  count, first/last hid) — visible under the default DEBUG config, silent at
  INFO. The running total is always in the heartbeat's `suppressed_total`.
- **Per-hit correlation ID (`hid`).** Every rule match gets a unique ID
  stamped across all alert channels and any forensic capture, so an alert can
  be traced back to the exact event and any captured artifact.
- **Vault files are written without an extension.** Captured scripts cannot
  be accidentally executed from the vault by double-click.
- **Lost-race captures are recorded, not hidden.** If a create-and-delete
  file is gone before we copy it, the vault still records that we saw the
  create (with `status=lost-race`); the Sysmon FileDelete archive (EID 23)
  backstops the actual content capture.

## Known limitations

These are not bugs in the "we'll fix them next sprint" sense — they are
properties of the current design that a reviewer should know about.

1. **Runs as SYSTEM.** Required to read `C:\SentinelArchive` (Sysmon locks
   it SYSTEM-only). Consequence: any logic bug in code that handles untrusted
   input (XML, JSON, pipe data, captured file contents) executes at the
   highest Windows privilege level. Go's memory safety mitigates the
   memory-corruption class but does not eliminate logic bugs. **Audit the
   vault path construction in `internal/snapshot/snapshot.go` and the XML
   parser in `internal/sysmonxml/sysmonxml.go` before deploying beyond a
   single trusted workstation.**

   *Containment:* the per-event paths in `internal/ingest/sysmon_rt_windows.go`
   and `internal/app/app.go` wrap each event in a `recover()`, so a panic in
   any parser or rule handler skips ONE event and logs WARN instead of
   crashing the SYSTEM daemon. A panic can no longer blind detection. The
   `panics_contained` counter in the heartbeat surfaces a spike. `sysmonxml.Parse`
   is also covered by a `testing.F` fuzzer (5m runs on each of `sysmonxml`,
   `allowlist`, `sigmaeval`; no crashes; see `internal/*/fuzz_test.go`); the tray and snapshot parsers are pure stdlib
   `json.Unmarshal` with no in-house surface.

2. **Pipe relay is unauthenticated.** `\\.\pipe\sentinel-toast` can be
   squatted by any user-session process that creates the pipe before the real
   relay starts. Impact: an attacker can suppress or spoof toasts — *not* RCE,
   *not* privilege escalation, *not* detection bypass (the popup, log, and
   eventlog channels are unaffected). Single-user threat model makes this
   acceptable; on a multi-user host, add a restrictive SDDL on pipe creation.

3. **Forensic vault has no integrity protection.** Manifests and content are
   plain files writable by SYSTEM. A privileged attacker can delete, modify,
   or plant captures. This is inherent to on-host forensics — the real
   mitigation is off-host log/vault shipping (syslog, Event Log forwarding,
   S3 with object-lock), which this project does not do.

4. **Logs are append-only text files.** Same problem as #3, lower stakes.
   A privileged attacker can edit `sentinel.log` and `ALERTS.log`.

5. **No remote update channel.** All updates are local file operations:
   - Rule/allowlist updates: edit `rules.d/*.yml` or `config/allowlist.json`, then
     restart the task (rules load at startup; no rebuild, no Sysmon touch).
   - Binary updates: stop the task, swap `sentinel.exe` / `sentinel-tray.exe` at
     their install path, restart the task. The Scheduled Task points at a fixed
     path, so no re-registration, no re-install.

   `install.ps1` exists for first-time setup and is safe to re-run, but it is not
   required for updates — steps 2-7 (Sysmon, telemetry, event source, task
   registration, tray) are one-time. This is a feature (no supply-chain
   auto-update to subvert) and a limitation (no central management, no hot-reload).

6. **Detection coverage is whatever you put in `rules.d/`.** This is a rule
   engine, not a curated detection library. The default rules are a starting
   point, not a complete posture.

7. **`install.ps1` trusts the repo directory.** If an attacker can write to
   the directory containing `install.ps1`, they can Trojan the install. Anyone
   who can write there already has user-level code execution; treat the repo
   directory as trusted.

   *Decision (owner-approved, 2026-08):* sentinel is a single-workstation
   sensor; the SYSTEM privilege exists to read `C:\SentinelArchive`, not to
   defend against the user whose workstation it is. Consequence accepted:
   same-user malware can edit `rules.d/`, `config/allowlist.json`, or
   `baseline_clean.csv` in the user-writable install tree and thereby blind
   or poison detection (CONFIG-001 is the tripwire for the rules path). If
   this ever deploys beyond a personal box, move the install to an
   admin-only directory (Program Files + ACLs) — see "What would need to
   change" below.

8. **Single-instance mutex can be pre-squatted.** `Global\Sentinel-Running-*`
   is created with the creator's default DACL and no owner/creator check
   (`internal/proc/mutex_windows.go`),
   so any local process — including a lower-privilege account — can create the
   name first and sentinel will exit 1 at every start: a silent local DoS of
   the monitor. Accepted alongside #7: while the install dir is user-writable,
   an attacker with user-level code execution has strictly better options
   (edit the rules, swap the binary), so hardening the mutex alone buys
   nothing. Revisit together with #7 — verify the existing mutex's owner SID
   before bowing out, or alert via EventLog before exiting — when (and only
   when) the install location is locked down.

9. **Queued alerts may be dropped on interrupt-time shutdown.** On Ctrl+C
   (manual runs only — the scheduled task is hard-terminated by Windows with
   no drain opportunity at all), `Dispatcher.Run`/`Snapshotter.Run` select on
   ctx.Done vs their buffered channel, so queued work MAY be discarded.
   *Decision (owner-approved, 2026-08):* accepted, with sentinel.log as the
   backstop — every hit is written there (HIT line) before dispatch, so the
   alert is always on record even when its popup/toast/EventLog delivery is
   lost. Restart replay (see `sysmon_rt_windows.go` highWater seed) recovers
   only part of it: rules with a fresh dedup entry replay as suppressed
   (15 min window, persisted, stamped before dispatch), and a baseline hit
   accepted-then-dropped still latches alert-once marking. See the
   shutdown-ordering comment in `cmd/sentinel/main.go` for the full window
   analysis.

## Operational assumptions

- **Single-user workstation.** Multi-user hosts need at minimum the pipe ACL
  fix and a review of the `AtLogon` task semantics.
- **Attacker is not yet on the workstation at install time.** If it is already
  compromised when sentinel is installed, the attacker can interfere with
  installation.
- **The user is local admin of their own workstation.** Install requires
  elevation; the SYSTEM Scheduled Task requires admin to register.
- **Go-built binary is trusted.** We do not sign the binary. A determined
  attacker with write access to the install directory can swap it. (Signing is
  an operational hardening step the user can add; it is out of scope here.)

## What would need to change for broader deployment

In order of what actually matters:
- **Install dir out of user-writable space** — Program Files-style location
  with admin-only write ACLs, plus the mutex owner check from limitation #8.
  Without this, running as SYSTEM defends the door while the walls are
  cardboard (limitations #7/#8).
- **Pipe ACL hardening** — required for multi-user hosts.
- **Off-host log/vault shipping** — required for any
  post-incident forensic value against a privileged adversary. Local logs are
  only useful if the attacker doesn't get SYSTEM.
- **Continuous fuzzing in CI** — all three in-house parsing paths are covered by
  native `testing.F` fuzzers, each run for 5 minutes on the host with zero
  crashes: `sysmonxml.Parse` (~176M execs), `allowlist.Compile` (~190M execs,
  exercises the hand-written `stripJSONC` byte parser), and `sigmaeval.Load`
  (~29M execs, exercises Sigma rule type-assertion paths). The tray and
  snapshot manifest parsers are pure `json.Unmarshal` on fixed structs (stdlib,
  no in-house surface) and are not separately fuzzed. Continuous fuzzing in CI
  is the remaining operational step.
- **Threat-model review by a second engineer** — this document is
  self-assessed. Independent review is how you find the thing this document
  missed.
- **Signed binary releases** — defends against repo-directory Trojaning on
  machines you don't personally control.

## Responsible disclosure

If you find a security issue, please open a private advisory via GitHub's
Security tab, or email the maintainer directly. Do not open a public issue for
security vulnerabilities.

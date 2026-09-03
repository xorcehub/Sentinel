# Red-team round 5 — spelling class round 3 + a dead-telemetry find (2026-09-03b)

Round 4 closed the Unicode-dash spelling (F16, engine-side dash fold). This
round attacks the next spellings of the same class and re-attacks EXEC-002's
telemetry. Everything (scripts, mimic trees, proof files) stayed inside
`redteam/2026-09-03b/`; payloads are `Write-Host`/`echo`/`Add-Content` only.

**Post-round fixes applied (same session):** F17/F17b (foldCmdLine whitespace
collapse in Engine.normalize), F20 (AiStone dev_scripts anchored to
-File + OEM tree), F21 (install-sysmon.ps1 patch 2 — headless-aware conhost
exclude). F18/F19 remain open, pinned below. EXEC-002 stays inert on the
LIVE daemon until the operator re-runs install-sysmon.ps1 as admin.

## Findings

| ID | Vector | Live verdict | Status |
|----|--------|--------------|--------|
| **F17** | **Whitespace-run token split.** `powershell -ep  bypass -w  h -c <payload>` (double-spaced) — PS/CommandLineToArgvW treat a space RUN as one separator, so the launch executes with full Bypass+Hidden semantics while every space-form token pair (`-ep bypass`, `-w h`, `-ExecutionPolicy B`, …) is a plain substring and misses. | **QUIET live** 15:10:51: payload marker in proof file; zero ALERTS lines; sibling control (single-spaced, same parent, same second) fired EXEC-001 CRITICAL ×2 (powershell child rec=2244424 + cmd broker rec=2244423) | **FIXED** — foldCmdLine collapses whitespace runs in Engine.normalize (one choke point: rules, dev_scripts, dedup); pinned C17b/C17c |
| **F17b** | Same split on the full-name form `-ExecutionPolicy  Bypass`. | **QUIET live** (engine-pinned) | **FIXED** — same collapse; pinned C17c |
| **F18** | **Full-name non-Bypass policy value.** F1's fix added `-ep u`/`-ep:U`/`-ExecutionPolicy:U` but not the full-name space form: `-ExecutionPolicy Unrestricted -c <payload>` is quiet. | **QUIET live** 15:10:52; control `-ep u` fired EXEC-001 CRITICAL (ALERTS rec row r5f18ctl) | **OPEN** (pinned) — whack-a-mole class; durable fix is the PS-argv-parser helper already noted in exec.yml |
| **F19** | **EXEC-002 headless-broker gap.** Rule requires `['--headless','powershell']`; a headless conhost running `cmd` (or pwsh/wscript/…) matches neither EXEC-002 nor EXEC-001 (broker arm needs a CLI token). Hidden execution via the incident's exact broker. | **QUIET live** 15:10:52 + re-fire 15:13: headless `cmd` wrote `r5f19.txt`; zero ALERTS lines for either conhost EID1 | **OPEN** (engine-pinned; live silence conflated with F21) — widen token2 to a contains-any over `powershell\|pwsh\|cmd\|wscript\|cscript\|mshta` or key on `--headless` alone |
| **F20** | **AiStone dev_scripts unanchored** (known-limitations #1, documented 2026-07-29; the allowlist comment falsely claimed "path-anchored"). Repo-tree mimic `…\redteam\2026-09-03b\aistoneservice\mycontrolcenter\command\logonusername.ps1` run with `-ExecutionPolicy Bypass -File`. | **QUIET live, mechanism proven**: 15:11:31 the vector's EID1 matched EXEC-001 and was swallowed — `suppressed (allowlist) summary rule=EXEC-001 count=1 last_seen=15:11:31` — sandwiched between the control's EXEC-001 CRITICAL HITs (ctl_r5f20.ps1, same second, same parent) | **FIXED** — entry anchored to `-file\s+"?[c]:\\program[ -]files\\oem…` (R2–R4 pattern); repo mimic pinned C20b, real OEM task pinned quiet in TestRound5LegitStaysQuiet |
| **F21** | **EXEC-002 is dead telemetry on this deployment.** The deployed Sysmon config (SwiftOnSecurity base, `C:\ProgramData\Sysmon\sentinel-sysmon.xml` line 104) **excludes `conhost.exe` from ProcessCreate at the source** — conhost EID1 never reaches the daemon. EXEC-002 has **0 alerts ever** in ALERTS.log (grep-verified). My C19 live control (`conhost --headless powershell`) was silent for this reason, while the engine-level control passes. Same failure class as the 127.0.0.1 NetworkConnect source-blindness `install-sysmon.ps1` already patches — this one was missed. | live + config | **FIXED (installer)** — patch 2 converts the blanket exclude into a `<Rule>` (Image AND CommandLine not-contains --headless; direct children of an event tag are OR-combined, so the wrapper is required). Validated read-only against the deployed config bytes: match + well-formed XML + idempotent guard. **OPERATOR STEP: re-run scripts/install-sysmon.ps1 as admin to deploy** |

## Bounded impact (as of this round)

- F17/F18 quiet only the EXEC-shape rules for THAT launch; follow-on NET /
  PERSIST / CRED behavior stays armed (round-1 doctrine).
- F19+F21 compound: headless conhost + non-PS child + no CLI tokens = fully
  silent hidden execution today. The child's own behavior still trips
  behavioral rules, and `cmd`-brokered bypass launches still fire EXEC-001's
  broker arm when tokens are present.
- F20 gags EXEC-001/EXEC-003 for one launch shape; bounded per
  known-limitations #1.

## Run

```
go test ./redteam/2026-09-03b/ -v          # engine pins (open rows quiet, fixed rows + controls fire)
powershell -NoProfile -File run.ps1        # live fire (expects ~4 CRITICAL toasts; pre-fix run)
```

## Attempt log (live-fire 2026-09-03 15:10:49–15:13, transient artifacts deleted after)

| probe | shape | verdict |
|-------|-------|---------|
| F17 vec | `powershell -ep  bypass -w  h -c "Write-Host r5f17-marker"` (double spaces) | payload RAN (proof file); no ALERTS line |
| F17 ctl | same, single spaces | EXEC-001 CRITICAL ×2 (child + cmd broker) |
| F18 vec | `powershell -ExecutionPolicy Unrestricted -c "Write-Host r5f18-marker"` | payload RAN; no ALERTS line |
| F18 ctl | `-ep u -c …` | EXEC-001 CRITICAL |
| F19 vec | `conhost --headless cmd /c "echo r5f19-marker > …\r5f19.txt"` | payload RAN (file written); no ALERTS line |
| F19 ctl | `conhost --headless powershell -NoProfile -c …` | **also silent** → F21 (conhost EID1 source-excluded); engine control passes |
| F20 vec | `-ExecutionPolicy Bypass -File …\aistoneservice\mycontrolcenter\command\logonusername.ps1` (repo tree) | payload RAN; EID1 matched EXEC-001, suppressed (allowlist/dev_scripts) — summary line 15:15:59 |
| F20 ctl | same flags, `-File …\ctl_r5f20.ps1` | EXEC-001 CRITICAL rec=2244424/23 |

Attribution: every quiet vector has a same-parent, same-second control that
fired (F17/F18/F20), an execution proof artifact, and — for F20 — the
suppressed-hit summary proving the event reached rule evaluation. F19's
live silence is fully explained by F21 (source-level exclusion), pinned
separately at engine level.

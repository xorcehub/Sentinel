# Fix plan — redteam round 3 (2026-09-02c)

ONE branch: `fix/redteam-round3` (cut from `fix/redteam-round2`). The round-3
findings land there as the baseline commit, then ONE COMMIT PER FIX, in the
order below (highest value first). Every commit: rule/allowlist change + the
corresponding test-row flip (quiet row → controls) + green
`go test ./tests/redteam-2026-09-02c/ -count=1` and `go test ./...`.

Per-round doctrine: when a fix lands, its quiet row in
`TestCustomBinVectorsAreQuiet` starts failing → move that row into
`TestCustomBinControls` (it must now FIRE), and add a "legit usage stays
quiet" case wherever the fix could over-tighten (TestCustomBinLegitStaysQuiet).

Deploy note (once, after the branch merges): restart the Sentinel scheduled
task — rules + allowlist load at daemon start.

## Commit order

1. `test(redteam): round-3 custom-binary evasion vectors (F9-F15)` — the dir
   as-is (readme, custombin_vector_test.go, probe-bin.go, this plan).
2. F11 — CONFIG-001 filter_sentinel anchored to the deployed repo path.
3. F9 — known_loopback_listeners image gate anchored to install roots.
4. F13 — EXEC-004 + INJECT-002 cover C:\Users\Public.
5. F15 — Tier-1 trusted_binaries pinned to the system drive (headline).
6. F10 — dev_scripts anchored to -File script paths (+ watchdog script).
7. F12 — NET-005 recognizes ::ffff:127.x spelling (hardening).
8. docs — readme statuses OPEN → FIXED, plan marked done.

## Per-commit detail

### 2. F11 — CONFIG-001 trusts the NAME `sentinel.exe` anywhere

- `rules.d/config.yml`: filter_sentinel →
  `Image|re: '(?i)^[a-z]:\\[^\\]+\\documents\\github\\leave-my-shit-alone\\sentinel\.exe$'`
  (`|re` supported — INJECT-002 already uses it; `[^\\]+` = username wildcard;
  scripts/install-task.ps1 launches `<repo>\sentinel.exe`).
- Flip: F11 bypass row → control `C11b` (renamed sentinel.exe in Downloads
  writing the real allowlist.json now FIRES CONFIG-001). Keep `C11`.

### 3. F9 — the `nahimic` image gate is an unanchored substring

- `config/allowlist.json`: entry image →
  `^[a-z]:\\(windows\\system32\\nahimic|users\\[^\\]+\\appdata\\local\\nhnotifsys\\nahimic)`
  (JSONC: 4 backslashes per separator). Compiled `(?i)`, anchored at START
  only: `system32\nahimic` prefix still matches `NahimicService.exe`, and the
  AppData alternative still matches `...\nhnotifsys\nahimic\*.exe` — both
  pinned by `internal/allowlist/allowlist_test.go:143`. Update the entry
  comment: future entries default to anchored paths, not name fragments.
- Flip: F9 bypass row → control `C9c` (nahimic-named binary in Downloads on
  :9080 now FIRES NET-005). Keep `C9`/`C9b`. Legit-quiet: real
  nhnotifsys AppData path on :9080 stays suppressed(allowlist).

### 4. F13 — EXEC-004 / INJECT-002 dir lists miss `C:\Users\Public`

- `rules.d/exec.yml` EXEC-004: `(Temp|AppData|ProgramData)` →
  `(Temp|AppData|ProgramData|Users\\Public)`.
- `rules.d/inject.yml` INJECT-002: append `|Users\\Public` to the dir list.
  (Same one-token change F8a made to NET-004. Optional, separate decision:
  Downloads for EXEC-004.)
- Flip: both F13 rows → controls `C13c`/`C13d`. Keep `C13a`/`C13b`.

### 5. F15 — Tier-1 trust is drive-agnostic (headline)

Chosen posture: option (a) — anchor Tier-1 to the system drive (`^[a-z]:` →
`^[c]:`, still (?i)). Volume helper (option b) is the upgrade path if a
trusted tool ever legitimately lands on a data volume; until then
hash_gated_path is the ONLY route to behavioral trust off C:.

- `config/allowlist.json` `trusted_binaries.path`: ALL patterns `^[a-z]:` →
  `^[c]:` — includes `windows\...` and `programdata\windows defender\...`
  (same class: `D:\Windows`, `D:\ProgramData\...` are user-creatable on a
  data volume). Update the section comment: "Program Files is admin-owned"
  only holds on the system drive.
- Rider (same hole, same commit): `dev_tool_paths` docker + adoptium entries
  also start `^[a-z]:\\program files\\` → anchor to `^[c]:` (NET-only quiet,
  smaller blast radius, identical hole).
- Flip: both F15 rows → controls `C15c` (D:\ plant beacon → NET-002) and
  `C15d` (D:\ plant Run-key → PERSIST-003). Keep `C15a`/`C15b`. Legit-quiet:
  `C:\Program Files\Mozilla Firefox\firefox.exe` beaconing a public IP stays
  suppressed(allowlist).

### 6. F10 — dev_scripts entries match ANYWHERE in the cmdline

- Add `scripts/gcubridge-watchdog.ps1` (the exact watchdog payload as a file).
- `config/allowlist.json` dev_scripts:
  - GCUBridge bare marker `"Get-Service -Name 'GCUBridge'"` → path anchor
    `leave-my-shit-alone[\\\\/]+scripts[\\\\/]+gcubridge-watchdog\\.ps1`
    (F2 doctrine; mention-as-string no longer suffices).
  - pe-triage entry prefixed with the `-File` context so
    `IEX(gc C:\pe_triage\...)` stops matching:
    `-file\\s+[a-z]:\\\\pe_triage[\\\\/]+scripts[\\\\/]+pe-triage-docker\\.ps1`.
    Do NOT prefix the cscript/AiStone entries — they don't use `-File`.
- OPERATOR STEP (outside repo; documented in commit body): re-register the
  logon task to
  `powershell -WindowStyle Hidden -ep bypass -File <repo>\scripts\gcubridge-watchdog.ps1`.
  Until then the task (safely) alerts EXEC-001 at each logon.
- Flip: F10 row 1 (GCUBridge piggyback) and row 2 (IEX mention) → controls
  `C10b`/`C10c` (both now FIRE EXEC-001). Legit-quiet: `-File` invocations of
  both scripts stay suppressed(allowlist).

### 7. F12 — `::ffff:127.0.0.1` spelling (engine-only today, hardening)

- `rules.d/net.yml` NET-005: `^(127\.|::ffff:127\.|::1|0:0:0:0:0:0:0:1)`.
- Flip: F12 bypass row → control `C12c` (mapped-loopback dst now FIRES
  NET-005, critical). NET-002/003 stay dst-suppressed — fine: NET-005 is the
  loopback-C2 tripwire. Keep `C12a`/`C12b`. Keep the row comment: unreachable
  on current Winsock (v4-mapped connect → WSAEADDRNOTAVAIL); closes the
  spelling class if a future Windows/driver path ever delivers it.

### 8. docs

- `tests/redteam-2026-09-02c/readme.md`: findings table statuses OPEN →
  FIXED (branch commit), live-fire log annotated.
- This plan: mark commits done.

## After merge

- Restart the Sentinel scheduled task.
- Optional live-fire spot check (probe constraints): `gcupiggy` should alert
  EXEC-001 until the task is re-registered to `-File`;
  `nahimic-probe.exe nahloop 9080` should alert NET-005.

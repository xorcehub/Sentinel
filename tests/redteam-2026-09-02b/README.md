# Red-team round 2 — rule/allowlist evasion vectors (2026-09-02b)

Round 1 (`docs/redteam-plan-2026-09-02.md`) found and fixed the suffix-trust
hole in `filter_cursor_agent`. This round probes **new** holes in the shipped
rules (`rules.d/`) and allowlist (`config/allowlist.json`), found by reading
the engine semantics (`internal/sigmaeval`, `internal/rules`,
`internal/allowlist`, `internal/pathnorm`) and confirmed against the **real
catalog + real allowlist + real engine** in `evasion_vector_test.go`.

**Constraint compliance:** everything here runs IN-PROCESS inside this
directory. No registry writes, no `%TEMP%` drops, no scheduled tasks, no
external network. The "attacks" are event shapes fed straight to the engine
the daemon runs. The optional live probe (`probe-bin.go`) only runs a
powershell echo and loops one byte over 127.0.0.1.

## Run

```
go test ./tests/redteam-2026-09-02b/ -v
```

`TestBypassVectorsAreQuiet` — every finding row asserts **silence** (current,
broken behavior). `TestBypassControls` — same shapes minus the hole, **must
fire** (proves quiet = the hole, not lost telemetry). When you fix a finding,
its quiet row starts failing: flip it into the controls table, like round 1 did.

## Findings in plain words

The rules are mostly "if the command line / path *contains this text*, alert."
That works until someone spells the same thing slightly differently. Seven
spots where a slightly-different spelling makes Sentinel see **nothing**:

- **F1 — abbreviated PowerShell flags.** PowerShell accepts `-ep b` and fills
  in "bypass" from the first letter. Your rule searches for `-ep bypass`, which
  is *longer* — so the short form never matches. Full bypass policy, boring-looking
  event. Fix: add the short forms as search texts.
- **F2 — trusted script names are portable.** EXEC-001 ignores any command
  mentioning `pe-triage-docker.ps1`, from any folder. Malware names its script
  exactly that, drops it anywhere, runs with full bypass flags — the exception
  swallows it. Fix: anchor the entry to the repo folder (like install.ps1).
- **F3 — scheduled tasks without paths.** Writing the path as `%TEMP%\x.exe`
  shows the rule the literal text `%TEMP%`, not a path; `/xml task.xml` keeps
  the path out of the command line entirely. Fix: add `%temp%`/`%appdata%`
  tokens. The daily baseline catches this anyway, one day late.
- **F4 — autostart spots you don't watch.** `Windows NT\CurrentVersion\Windows\Load`
  and Active Setup `StubPath` are user-writable login autostarts outside the
  Run-key family. Fix: add both key names to PERSIST-003.
- **F5 — Startup file types.** Windows executes `.hta`/`.jse`/`.vbe`/`.wsf`/`.scr`
  from Startup at login, not just exe/ps1/bat/cmd/vbs/js/lnk. Fix: extend the list.
- **F7 — DLL loads outside Temp.** An unsigned DLL loaded from Desktop,
  Documents, or this repo is invisible — INJECT-002 only knows
  Temp/AppData/ProgramData/Downloads. Fix: add `Desktop` at minimum.
- **F8a — the magic IP (worst finding).** Connections to 1.1.1.1 are allowlisted
  (Cloudflare DNS), and NET-004 only flags images under Temp/AppData/ProgramData.
  A program in `C:\Users\Public\` (world-writable, in neither list) beaconing
  to 1.1.1.1:443 is invisible to the entire catalog — and DoH over that IP is a
  known exfil channel. Fix: add `\users\public\` to NET-004; reconsider the DoH
  CIDRs.
- **F8b — the magic port.** `127.0.0.1:9080` is excepted from NET-005, so two
  programs chatting over that port (the exact broker-C2 shape the rule exists
  for) are silent; :9081 fires CRITICAL. Fix: drop the entry if unused, or
  scope exceptions to an expected image.

None of these fixes have been applied — rules.d/config edits are the operator's
call. Total fix is ~15 lines of rule/allowlist text, then restart the Sentinel
task (rules load at startup); CU1/CU2 + the existing suite confirm no breakage.

## Findings (all live-verified quiet, engine-level)

| ID | Rule | Bypass | Fix direction |
|----|------|--------|---------------|
| F1 | EXEC-001 | `powershell -ep b` / `-ExecutionPolicy B` / `-w h` — PS resolves abbreviated param names AND abbreviated enum values, so Bypass policy with zero keyword matches (`'-ep bypass'` is longer than `'-ep b'`, contains() can't catch any prefix form). Conhost broker variant too (EXEC-002 needs `--headless`). | **FIXED** (branch `fix/redteam-round2`): first-letter + colon-prefix tokens added to selection_cli (`-ep b`, `-ep u`, `-ep:B`, `-ExecutionPolicy B`, `-w h`, ...). Rows flipped to controls. Residual: token list is whack-a-mole vs PS prefix matching — durable fix is an engine helper that parses PS argv. |
| F2 | EXEC-001 | `dev_scripts` except matches the bare filename `pe-triage-docker\.ps1` ANYWHERE in the cmdline: full `-ExecutionPolicy Bypass -File C:\<anywhere>\pe-triage-docker.ps1` = allowlist-suppressed, zero hits. (Evasion note in `internal/allowlist` documents the class; this pins the impact.) | Path-anchor the pe-triage entry to the repo dir like the install.ps1 entries. |
| F3 | PERSIST-001 | `schtasks /create /tr "%TEMP%\upd.exe"` (env-var: no literal path token) and `schtasks /create /xml <Documents task.xml>` (action lives in the XML, not the cmdline) both skip `selection_path`. | Add `%temp%`/`%appdata%` env-var tokens to selection_path (FP-cheap); `/xml` needs an engine helper resolving the XML. Backstop: BASE-001 daily autoruns diff (task appears in Logon category, ≤24h delay). |
| F4 | PERSIST-003 | User-writable autostart values outside the Run/RunOnce/Winlogon/AppInit/Userinit family: `...\Windows NT\CurrentVersion\Windows\Load`, `HKCU\...\Active Setup\Installed Components\{guid}\StubPath`. | Add `'\CurrentVersion\Windows\'` and `'StubPath'` tokens. Backstop: BASE-001 daily (both are autoruns surfaces). |
| F5 | PERSIST-004 | Startup extension list `exe|ps1|bat|cmd|vbs|js|lnk` misses executable-on-logon handlers: `.hta` (mshta), `.jse`, `.vbe`, `.wsf`, `.scr`. | Extend the alternation: `(exe|ps1|bat|cmd|vbs|js|jse|vbe|wsf|hta|scr|lnk)$`. Backstop: BASE-001. |
| F7 | INJECT-002 | `ImageLoaded` scoped to `(Temp|AppData|ProgramData|Downloads)` substrings — unsigned DLL loads from **Desktop**, **Documents**, or this repo tree are invisible. Desktop is a top staging dir per CRED-001's own note. | Add `Desktop` at minimum; the durable shape is "unsigned AND user-writable" (needs a user-writable-path helper). Also confirm the Sysmon config actually subscribes EID 7 for those paths. |
| F8a | NET-002/003/004 | **Fully silent public beacon**: dst `1.1.1.1`/`1.0.0.1` is in `allowed_destinations` (DoH entries) AND image at `C:\Users\Public\` misses NET-004's `Temp|AppData|ProgramData` list → zero rules see it. DoH over 443 gives DNS-tunnel exfil. | Decide: do the DoH CIDRs earn their keep (they exist for the system resolver)? If kept, add `\users\public\` to NET-004's image list; a DoH-from-non-resolver-image helper would be the precise fix. |
| F8b | NET-005 | **Fully silent loopback C2** on `127.0.0.1:9080` (the `known_loopback_listeners` entry) from any non-Temp/AppData/ProgramData image. Control :9081 fires CRITICAL. | The except has no image constraint. Either delete the :9080 entry if nothing uses it, or scope exceptions with an expected image (needs engine support for per-entry image matching). |

Documented-accepted (confirmed, pinned, not a new finding): `%USERPROFILE%\go\bin\evil.exe`
beacons a public IP with **zero hits** — dev_tool_paths path-trust (Bypass-B),
accepted in the allowlist comments. Row `F0-accepted` goes red if that posture
ever changes.

## Refuted hypotheses (honest log — these FIRE, kept as controls)

- `HKCU\Environment\UserInitMprLogonScript` (T1547.11): **caught** by
  PERSIST-003 — the unanchored `'\Userinit'` token substring-matches any value
  named `Userinit*`. Accidental but real coverage; pinned as control CU1 (if
  the token is ever tightened, CU1 catches the coverage loss).
- COM hijack via `LocalServer32` / `TreatAs` in the user hive: **caught** by
  PERSIST-006 — a value list under one Sigma field is OR, not AND, so
  `Classes\CLSID` alone satisfies the selection. Pinned as control CU2.
  (Machine-hive + admin-owned payload stays quiet, but that needs an admin
  writer = out of scope per THREAT-MODEL.)

## Coverage notes (no event shape exists; not vector-testable)

- INJECT-001 only sees EID 8 (CreateRemoteThread): APC / thread-hijack /
  SetWindowsLongPtr injection emits no EID 8/25 → silent.
- CRED-001 keys FileCreate filenames: in-memory vault reads + direct upload
  never write a staging copy (documented blind spot).
- EVADE-001 keys cmdline tokens: any AMSI patch without those tokens on the
  cmdline (any compiled language, any PS obfuscation) is silent.
- EXEC-005 parent list misses Chromium forks (Brave/Vivaldi/Opera) and
  non-Adobe PDF readers.

## Daemon-level confirmation (optional, benign, toasts expected)

The vector tests run the same engine+allowlist the daemon runs; live-fire only
re-proves ingestion. If wanted:

```powershell
go build -o tests/redteam-2026-09-02b/bin/probe.exe tests/redteam-2026-09-02b/probe-bin.go
tests\redteam-2026-09-02b\bin\probe.exe bypassps        # expect QUIET (F1)
tests\redteam-2026-09-02b\bin\probe.exe bypassps-full   # expect EXEC-001 CRITICAL toast (C1)
tests\redteam-2026-09-02b\bin\probe.exe loopctl 9080    # expect QUIET (F8b)
tests\redteam-2026-09-02b\bin\probe.exe loopctl 9081    # expect NET-005 CRITICAL toast (C8)
```

Then grep `sentinel.log` for the probe paths. Remember: rules load at daemon
start — after applying any fix, restart the Sentinel scheduled task, and flip
the now-failing quiet rows into `TestBypassControls`.

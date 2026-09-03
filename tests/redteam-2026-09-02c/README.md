# Red-team round 3 — custom-binary evasion vectors (2026-09-02c)

Rounds 1-2 probed event *spelling* (cmdline tokens, path anchors). This round
asks what an attacker who ships **their own binary** gains: a self-chosen
NAME, a self-chosen PATH, and socket spellings only custom code can produce.
Every finding was found by reading the compiled regexes in
`internal/allowlist/allowlist.go` (known_loopback_listeners image gates and
dev_scripts entries compile as **unanchored** `(?i)` substrings), the Sigma
filter selections in `rules.d/` (CONFIG-001 name-trust, EXEC-004 /
INJECT-002 dir lists), and the `^[a-z]:` drive-wildcard prefixes in
`trusted_binaries` Tier-1 — then confirmed against the **real catalog +
real allowlist + real engine** in `custombin_vector_test.go`.

**Constraint compliance:** all tests run IN-PROCESS in this directory. The
live probe (`probe-bin.go`) only runs a powershell `Write-Host`, 1-byte
loopback round trips, and a file write in `bin/` that it deletes again. The
one vector whose live plant would land outside the repo (F15, a data-drive
`D:\Program Files\...` mimic) was **not** executed — engine-pinned only.

## Run

```
go test ./tests/redteam-2026-09-02c/ -v
```

`TestCustomBinVectorsAreQuiet` — every finding row asserts **silence**
(current, broken behavior). `TestCustomBinControls` — same shapes minus the
hole, **must fire** (proves quiet = the hole, not lost telemetry).
`TestTier2GateBlocksCustomBinary` — pins that the Tier-2
(path + vendor-signature) gate **blocks** an unsigned custom binary, i.e.
fail-closed, the intended design. When a finding is fixed, its quiet row
starts failing: flip it into the controls table, like rounds 1-2 did.

## Findings in plain words

- **F9 — the `nahimic` name gate is a substring.** The F8b fix scoped the
  `127.0.0.1:9080` loopback exception to `{"image": "nahimic"}` — compiled
  UNANCHORED (`(?i)` + contains), so any binary whose full path contains
  "nahimic" anywhere inherits the exception. `Downloads\evil-nahimic-updater.exe`
  chatting on :9080 (the exact broker-C2 shape NET-005 exists for) is
  allowlist-suppressed. **Live-confirmed**: the daemon logged the connect and
  suppressed NET-002/003/005(allowlist) for a benign `nahimic-probe.exe`.
  Fix: anchor to the two legit install roots, e.g.
  `"image": "^[a-z]:\\\\(windows\\\\system32\\\\nahimic|users\\\\[^\\\\]+\\\\appdata\\\\local\\\\nhnotifsys\\\\nahimic)"` —
  and decide whether future entries default to anchored.
- **F10 — dev_scripts anchors are substrings.** `Get-Service -Name 'GCUBridge'`
  was written for a task whose `-Command` payload is EXACTLY that probe, but
  the compiled regex matches ANYWHERE in any cmdline: 
  `powershell -ep bypass -w h -c "Get-Service -Name 'GCUBridge'; <anything>"`
  suppresses EXEC-001 for the whole launch. Same class: mentioning the
  pe-triage path as a plain string. **Live-confirmed**: `gcupiggy` produced a
  `suppressed (allowlist)` EXEC-001 summary, control `gcuctl` fired CRITICAL.
  Fix: anchor payload-bearing entries to `-File <path>` context or convert the
  GCUBridge task to a path-anchored `-File` script (same doctrine as F2).
- **F11 — CONFIG-001 trusts the NAME `sentinel.exe` anywhere.**
  `filter_sentinel` is `Image|endswith '\sentinel.exe'` with no prefix anchor
  (the round-1 cursor-suffix class), and the selection keys on
  TargetFilename `contains 'allowlist.json'` etc. anywhere on disk. A custom
  binary RENAMED sentinel.exe can write the real config silently — and
  because this is a Sigma filter (not an except), not even a SUPPRESSED line
  is logged. **Live-confirmed with perfect attribution**: the same write from
  `bin\sentinel.exe` produced no CONFIG-001 line at all; the identical write
  from `bin\probe.exe` fired CRITICAL (rec 2156203 vs 2156221).
  Fix: anchor the filter to the real install path, e.g.
  `Image|re: '(?i)^[a-z]:\\[^\\]+\\documents\\github\\leave-my-shit-alone\\sentinel\.exe$'`
  (or whatever the deployed path is; install.ps1 knows it).
- **F12 — `::ffff:127.0.0.1` spelling.** NET-005's regex anchors on
  `^(127\.|::1|0:0:0:0:0:0:0:1)` — the IPv4-mapped spelling misses it, while
  allowed_destinations still excepts it from NET-002/003 (Go's
  `IPNet.Contains` sees it as 127.0.0.1). Engine row: such an event is fully
  silent. **However, the live probe REFUTED reachability**: Winsock refuses
  `connect()` to a v4-mapped destination on an AF_INET6 socket
  (WSAEADDRNOTAVAIL — Windows, unlike Linux, does not translate mapped
  addresses for connect), while raw-v4 and native-::1 connects work — so NO
  user-mode Windows TCP connection can carry that dst spelling, and Sysmon
  can never log it. Kept as a hardening note: add `::ffff:` to NET-005's
  regex anyway (one token, closes the spelling class if a future Windows or
  driver path ever delivers it).
- **F13 — the F8a fix only touched NET-004.** `C:\Users\Public` (and
  Downloads / repo trees) are still absent from the sibling dir-list rules:
  EXEC-004 (hex/GUID-named exe from `(Temp|AppData|ProgramData)`) and
  INJECT-002 (unsigned DLL from
  `(...|Downloads|Desktop|Documents)`). A hex-named exe or an unsigned
  sideloaded DLL from Public is invisible to both. Fix: add `Users\Public`
  to EXEC-004's regex and INJECT-002's (and consider `Downloads` for
  EXEC-004) — the same one-token change F8a made to NET-004.
- **F15 — Tier-1 trust is drive-agnostic (headline).** Every
  `trusted_binaries.path` pattern starts `^[a-z]:\\program files\\...` — the
  drive letter is a wildcard. The tier's premise ("Program Files is
  admin-owned") only holds on the system drive. On any user-writable data
  volume (this box has D:), a USER creates
  `D:\Program Files\Mozilla Firefox\ffupdate.exe`, plants a custom binary,
  and inherits FULL behavioral trust: NET-002/003/004, EXEC-001/004,
  INJECT-001/002, CRED-001/002/003, PERSIST-002/003/006, EVADE-001 all
  suppress(allowlist) for that image. Same class:
  `D:\ProgramData\Microsoft\Windows Defender\...\msmpeng.exe` on a data
  volume is a user-created tree matching the Defender pattern.
  Impact bound: NET-005 (loopback), PERSIST-004/005, CONFIG-001 and the
  EXEC-002/003/005 broker rules have no image_in_allowlist except and stay
  armed; BASE-001 backstops daily. NOT live-fired (plant would land outside
  this repo per operator constraint; the engine rows pin it).
  Fix options: (a) anchor Tier-1 to `^[a-z]:` → explicit `c:` for the system
  volume AND rely on hash_gated_path for any non-system volume, or (b) an
  engine helper that checks the volume is the system drive, or (c) accept and
  document (current comments claim admin-owned — that claim is false on
  multi-drive boxes).

## Findings table (verified against the real engine at authoring time)

| ID | Rule/entry | Bypass | Status |
|----|------------|--------|--------|
| F9 | allowlist `known_loopback_listeners` (NET-005 except) | `*nahimic*.exe` anywhere on the unanchored image regex → loopback C2 on :9080 quiet | **FIXED** (2026-09-03, fix/redteam-round3): image gate anchored to install roots |
| F10 | allowlist `dev_scripts` (EXEC-001 except) | piggyback payload after the unanchored `GCUBridge` / pe-triage cmdline markers | **FIXED** (2026-09-03): entries anchored to `-File` script paths; task re-registration to `-File` = operator step |
| F11 | rules.d/config.yml CONFIG-001 `filter_sentinel` | renamed `sentinel.exe` writes any `allowlist.json`/`state.db`/… anywhere → silent (no suppressed line) | **FIXED** (2026-09-03): filter anchored to deployed repo path |
| F12 | NET-005 regex + allowed_destinations | `::ffff:127.0.0.1` loopback fully silent at engine level | **ENGINE-ONLY — not reachable live** (Winsock refuses v4-mapped connect; probe verdict reproduced). **FIXED** (2026-09-03, hardening): `::ffff:` token added to NET-005 |
| F13 | EXEC-004, INJECT-002 | dir lists miss `C:\Users\Public` (EXEC-004 also misses Downloads/repo trees) | **FIXED** (2026-09-03): Users\Public added to both dir lists |
| F15 | allowlist `trusted_binaries.path` Tier-1 | `^[a-z]:\\program files\\…` matches user-creatable trees on non-system drives → full behavioral trust for a custom binary | **FIXED** (2026-09-03): Tier-1 anchored to ^[c]: (system drive); D:-drive installs now attacker cases |
| — | Tier-2 hash_gated_path + sigverify | custom binary planted at a Tier-2 path, unsigned | **CLOSED (pinned)**: fail-closed without vendor signature; WinVerifyTrustEx chain validation rejects spoofed-subject self-signed certs before subject match. TestTier2GateBlocksCustomBinary |

Documented-accepted, unchanged: the F0-accepted round-2 posture
(`go\bin\evil.exe` → NET-002/003/004 quiet) already covers custom binaries
self-named into dev_tool_paths; not re-pinned here.

## Live-fire log (2026-09-02 18:43, all artifacts deleted; daemon on fix/redteam-round2)

| Mode | Shape | Expectation | Daemon verdict |
|------|-------|-------------|----------------|
| `gcupiggy` | PS `-ep bypass -w h -c "Get-Service -Name 'GCUBridge'; Write-Host"` | QUIET (F10) | `suppressed (allowlist)` EXEC-001 summary — **confirmed** |
| `gcuctl` | same minus marker | EXEC-001 CRITICAL | **FIRED** ✓ |
| `nahimic-probe.exe nahloop 9080` | 1-byte loopback (connect-only; real Nahimic owns :9080) | QUIET (F9) | NET-002/003/005 `suppressed (allowlist)` — **confirmed** |
| `probe.exe nahloop 9081` | 1-byte loopback, other port | NET-005 CRITICAL | **FIRED** ✓ |
| `sentinel.exe sentname` | writes `allowlist.json.probe` in `bin/` (deleted) | QUIET (F11) | EID 11 logged, **no CONFIG-001 line** — **confirmed** |
| `probe.exe sentname` | identical write, other name | CONFIG-001 CRITICAL | **FIRED** ✓ (same rec window as quiet twin) |
| `loop6 7798/7799` | raw AF_INET6 v4-mapped connect | unknown | **REFUTED live**: Winsock WSAEADDRNOTAVAIL; raw-v4 baseline connected and fired NET-005 ✓ (telemetry path proven) |

Attribution: every quiet mode has a same-second sibling event proving the
event family reached the daemon; daemon latency ~10-90 s; distinct
ports/cmdlines avoided the 5-min dedup.

## Suggested fix order (operator decision; NOT auto-applied)

1. F11 (self-protection of the config itself — smallest, highest value)
2. F9 (one regex change in allowlist.json)
3. F13 (two one-token rule changes)
4. F15 (decide posture: `c:`-anchor vs volume helper vs documented-accept)
5. F10 (convert GCUBridge task to `-File` + path-anchored entry)
6. F12 (add `::ffff:` to NET-005 — optional, unreachable today)

After merging fixes: restart the Sentinel scheduled task (rules + allowlist
load at daemon start), then flip each fixed quiet row into
`TestCustomBinControls`, like rounds 1-2 did.

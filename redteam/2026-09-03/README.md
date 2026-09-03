# Red-team round 4 — spelling class, round 2 (2026-09-03)

Round 3.1 re-attacked the round-3 fixes. This round re-attacks the *event
spelling* class with a live-fire pass: benign custom binaries built in
`redteam/lab/` (gitignored, repo-only) against the post-3.1 daemon. One NEW
bypass, two documented residuals live-confirmed, and the R1 fix verified.

## Findings

| ID | Vector | Evidence | Status |
|----|--------|----------|--------|
| **F16** | **Unicode-dash EXEC-001 bypass.** PowerShell's console host normalizes en/em dashes (U+2013/2014, also U+2015/2212/FE63/FF0D) to ASCII `-` in argv: `–ep bypass –w h –c <payload>` runs with full Bypass/Hidden semantics while every EXEC-001 token (all ASCII-prefixed) misses. **LIVE-CONFIRMED** 13:00:57: payload printed; daemon logged NOTHING for the EID1 (sibling ASCII control fired CRITICAL rec=2220107; the dash spawn's own file event rec=2220097 proves telemetry). Same whack-a-mole class as F1 — durable fix: fold Unicode dashes to `-` in `Engine.normalize`, one choke point covering rule eval AND dev_scripts matching. | live + engine rows | **FIXED** (engine folding) |
| — | **DoH-dst beacon** (F8a residual, live-confirmed): custom repo binary → `1.1.1.1:443` fully silent (NET-002/003 dst-except via allowed_destinations; NET-004 dir list misses repo trees). Control `8.8.8.8` fires NET-002/003 (rec=2220228). Durable fix stays the round-2 note: DoH-from-non-resolver-image helper. | live + engine row | documented-accept (pinned) |
| — | **EXEC-004 dir-list gap** (F13 note): hex-named exe outside `Temp\|AppData\|ProgramData\|Users\Public` (repo trees, Downloads) invisible. Control (%TEMP%) fires (C13a). | live + engine row | documented-accept (pinned) |
| — | R1 fix verification: renamed `sentinel.exe` in `redteam\lab\` writing `allowlist.json.probe` → **CONFIG-001 CRITICAL** (rec=2220137). Extra path segment no longer trusted. | live | fix verified ✓ |
| — | NET-005 stays armed for repo images: lab binary → `127.0.0.1:7794` → **CRITICAL** (rec=2220243/44). | live | control ✓ |

## Run

```
go test ./redteam/2026-09-03/ -v
```

## Attempt log (live-fire 2026-09-03 13:00:57–13:01:33, artifacts deleted)

| probe | shape | verdict |
|-------|-------|---------|
| dash-PS | `–ep bypass –w h –c "Write-Host r4dash-marker"` | payload RAN; daemon silent (rec 2220097 = its file event) |
| ctl-PS | ASCII `-ep bypass -w h -c …` | EXEC-001 CRITICAL rec=2220107 |
| labctl 1.1.1.1:443 | connect-only | silent (no line at all) |
| labctl 8.8.8.8:53 | connect-only | NET-002/003 HIT rec=2220228 |
| cafe123456.exe touch | hex-named, repo tree | silent (no line at all) |
| sentinel.exe (lab copy) touch allowlist.json.probe | renamed config writer | CONFIG-001 CRITICAL rec=2220137 |
| labctl 127.0.0.1:7794 | loopback connect | NET-005 CRITICAL rec=2220243/44 |

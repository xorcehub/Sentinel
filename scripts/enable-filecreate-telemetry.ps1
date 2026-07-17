# scripts/enable-filecreate-telemetry.ps1
#
# SwiftOnSecurity's sysmon-config (deployed by install-sysmon.ps1) does NOT
# include a FileCreate (EID 11) rule group, so EID 11 never fires. This blinds:
#   - the snapshot capture vault (needs EID 11 for \Temp\ps-script-)
#   - PERSIST-004 (executable/script written to Startup folder)
#   - CONFIG-001 (sentinel config/state files written by non-sentinel.exe)
#
# This script merges a surgical FileCreate include rule group (from the
# companion sysmon-filecreate.xml) into the active Sysmon config and reloads it.
# IDEMPOTENT: if the sentinel marker is already present, it exits without change.
#
# The include set is deliberately narrow (only the paths the rules need) so it
# adds negligible noise, unlike a broad FileCreate which would flood.
#
# REQUIRES: run as Administrator.

# Save + restore ErrorActionPreference so this script never leaks "Stop"
# into the caller's session (which would turn every native command's stderr
# into a terminating NativeCommandError — e.g. sentinel-cli.exe's slog logs).
$script:prevEAP = $ErrorActionPreference
$ErrorActionPreference = "Stop"
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $ErrorActionPreference = $script:prevEAP
    throw "Run this script as Administrator."
}

# Marker used for idempotency; snippet lives in a sibling XML file so no XML
# appears inline in this script (avoids PowerShell here-string / '<' pitfalls).
$FileCreateMarker = "Sentinel-FileCreate-Telemetry"
$FileDeleteMarker = "Sentinel-FileDelete-Telemetry"
$Marker       = $FileCreateMarker  # backward-compat for idempotency text
$ArchiveDirName = "SentinelArchive"
$SnippetFile     = Join-Path $PSScriptRoot "sysmon-filecreate.xml"
$FileDeleteSnippet = Join-Path $PSScriptRoot "sysmon-filedelete.xml"

# Invoke-Native: run a console program with separate stdout/stderr capture.
# sysmon64 writes its banner to stderr even on success, and PowerShell's
# $ErrorActionPreference="Stop" turns that into a terminating error that aborts
# before the exit-code check. The .NET Process API sidesteps the PowerShell
# error stream entirely — stdout and stderr are read independently, never
# interleaved, never surfaced as errors. Returns @{ExitCode; StdOut; StdErr}.
function Invoke-Native {
    param([string]$Binary, [string]$ArgString)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Binary
    $psi.Arguments = $ArgString
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    [void]$p.Start()
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    $code = $p.ExitCode
    return @{ ExitCode = $code; StdOut = $stdout; StdErr = $stderr }
}

# Merge-SysmonRules: generic XML DOM merge for FileCreate/FileDelete include
# rules. Merges snippet entries into an existing include element or creates a
# new RuleGroup. XPath sees only real elements (never comments), which is the
# fix for the comment-merge bug that left ps-script rules dead.
function Merge-SysmonRules {
    param($Doc, [string]$ElementName, [string]$MarkerName, [string]$SnippetPath)
    $rawEntries = Get-Content $SnippetPath -Raw
    $fragDoc = New-Object System.Xml.XmlDocument
    $fragDoc.LoadXml('<Root>' + $rawEntries + '</Root>')

    $xpathInc = '//' + $ElementName + "[@onmatch='include']"
    $existing = $Doc.SelectSingleNode($xpathInc)

    if ($existing) {
        foreach ($child in $fragDoc.DocumentElement.ChildNodes) {
            $imported = $Doc.ImportNode($child, $true)
            $null = $existing.AppendChild($imported)
        }
        Write-Host ("Merged entries into existing " + $ElementName + "(include) via XML DOM.")
    } else {
        $xpathExc = '//' + $ElementName + "[@onmatch='exclude']"
        if ($Doc.SelectSingleNode($xpathExc)) {
            throw ($ElementName + " present as exclude-only; manual edit required.")
        }
        $rg = $Doc.CreateElement("RuleGroup")
        $rg.SetAttribute("name", $MarkerName)
        # groupRelation="or" is REQUIRED: sysmon 15.21 crashes (0xC0000409)
        # on a RuleGroup that lacks it. SwiftOnSecurity's groups all carry it.
        $rg.SetAttribute("groupRelation", "or")
        $el = $Doc.CreateElement($ElementName)
        $el.SetAttribute("onmatch", "include")
        foreach ($child in $fragDoc.DocumentElement.ChildNodes) {
            $imported = $Doc.ImportNode($child, $true)
            $null = $el.AppendChild($imported)
        }
        $null = $rg.AppendChild($el)
        # CRITICAL: new RuleGroups must go INSIDE <EventFiltering>, not as a
        # direct child of <Sysmon>. Appending to DocumentElement places the
        # group after </EventFiltering>, which crashes sysmon (0xC0000409).
        $eventFiltering = $Doc.SelectSingleNode("//EventFiltering")
        if ($eventFiltering) {
            $null = $eventFiltering.AppendChild($rg)
        } else {
            $null = $Doc.DocumentElement.AppendChild($rg)
        }
        Write-Host ("No " + $ElementName + " element found; added new RuleGroup inside EventFiltering via XML DOM.")
    }
}

# --- 1. locate sysmon64 ---
# Sysmon installs to different paths depending on how it was deployed:
#   - default `sysmon64 -i`           -> C:\Windows\sysmon64.exe
#   - install-sysmon.ps1 (this repo)  -> C:\ProgramData\Sysmon\sysmon64.exe
#   - custom location                  -> resolve via Get-Command (PATH)
$candidates = @()
$cmd = Get-Command sysmon64.exe -ErrorAction SilentlyContinue
if ($cmd) { $candidates += $cmd.Source }
$candidates += "$(Join-Path $env:ProgramData 'Sysmon\sysmon64.exe')"
if ($env:WINDIR) { $candidates += "$(Join-Path $env:WINDIR 'sysmon64.exe')" }

$sysmon = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $sysmon) {
    Write-Host "Searched: $($candidates -join ', ')"
    throw "sysmon64.exe not found. Install Sysmon first (scripts/install-sysmon.ps1), or add it to PATH."
}
Write-Host "Using sysmon: $sysmon"

# --- 2. load the FileCreate snippet ---
if (-not (Test-Path $SnippetFile)) {
    throw "Snippet not found: $SnippetFile"
}
$snippet = Get-Content $SnippetFile -Raw

# --- 3. acquire the base config XML ---
# Source priority:
#   1. Local copy left by install-sysmon.ps1 ($env:ProgramData\Sysmon\...)
#   2. Fresh download of SwiftOnSecurity/sysmon-config (same source
#      install-sysmon.ps1 uses)
# We do NOT use 'sysmon -c' to dump the running config — that prints a
# human-readable SUMMARY, not XML, so there's no '</Sysmon>' to merge into.
# Sysmon 4.91 loads schema-4.50 configs fine (backward compatible); the only
# hard rule is ONE FileCreate group (handled by the merge below).
$workDir = Join-Path $env:TEMP "sentinel-sysmon-patch"
New-Item -ItemType Directory -Force -Path $workDir | Out-Null
$baseConfig = Join-Path $workDir "base-sysmon.xml"

$localPaths = @(
    (Join-Path $env:ProgramData "Sysmon\sentinel-sysmon.xml"),
    (Join-Path $env:ProgramData "Sysmon\sysmonconfig.xml")
)
$local = $localPaths | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if ($local) {
    Write-Host "Using local config: $local"
    Copy-Item $local $baseConfig -Force
} else {
    Write-Host "No local config found; downloading SwiftOnSecurity config ..."
    $url = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"
    Invoke-WebRequest -Uri $url -OutFile $baseConfig
    Write-Host "Downloaded to: $baseConfig"
}
# --- 4. load config as XML DOM + idempotency ---
# Parse with XmlDocument, NOT string manipulation. SwiftOnSecurity's config is
# heavily commented and contains literal '</FileCreate>' / '<FileCreate ...>'
# strings inside comment blocks. The old string-based merge used
# LastIndexOf('</FileCreate>') which matched those COMMENT occurrences, silently
# inserting our rules INTO a comment (valid XML, validation passed, but the
# rules were dead — root cause of ps-script files never generating EID 11).
# XPath on the DOM sees ONLY real elements, so the merge is bulletproof.
$xml = New-Object System.Xml.XmlDocument
$xml.PreserveWhitespace = $true
try {
    $xml.Load($baseConfig)
} catch {
    $msg = "Base config is not valid XML: $($_.Exception.Message). Inspect: $baseConfig"
    throw $msg
}

# Sanity: confirm Sysmon root element.
if (-not $xml.DocumentElement -or $xml.DocumentElement.Name -ne 'Sysmon') {
    $msg = "Acquired config has no <Sysmon> root. Inspect: $baseConfig"
    throw $msg
}

# --- 4. idempotency: check BOTH FileCreate and FileDelete markers ---
$hasFC = $xml.OuterXml -match [regex]::Escape($FileCreateMarker)
$hasFD = $xml.OuterXml -match [regex]::Escape($FileDeleteMarker)
$hasAD = $null -ne $xml.SelectSingleNode("//ArchiveDirectory")
# Do NOT early-return even if both markers exist: the ArchiveDirectory may
# still be missing or misplaced (out of schema order). We must always proceed
# to the ArchiveDirectory step below.
if ($hasFC -and $hasFD -and $hasAD) {
    Write-Host "FileCreate, FileDelete, and ArchiveDirectory all present - nothing to do."
    return
}

# --- 5. merge FileCreate rules (if not already present) ---
if (-not $hasFC) {
    Merge-SysmonRules -Doc $xml -ElementName "FileCreate" -MarkerName $FileCreateMarker -SnippetPath $SnippetFile
} else {
    Write-Host "FileCreate telemetry already present; skipping FileCreate merge."
}

# --- 5b. merge FileDelete rules (if not already present) ---
# FileDelete (EID 23) is the BACKSTOP for create-and-delete files. Sysmon copies
# the file to ArchiveDirectory BEFORE the delete syscall returns. The archived
# copy persists, so even with poller latency the file content is guaranteed.
if (-not $hasFD) {
    if (-not (Test-Path $FileDeleteSnippet)) {
        throw "FileDelete snippet not found: $FileDeleteSnippet"
    }
    Merge-SysmonRules -Doc $xml -ElementName "FileDelete" -MarkerName $FileDeleteMarker -SnippetPath $FileDeleteSnippet
} else {
    Write-Host "FileDelete telemetry already present; skipping FileDelete merge."
}

# --- 5c. add ArchiveDirectory (if not already present) ---
# Sysmon stores archived copies of deleted files here. The value is a directory
# NAME; Sysmon creates it at the system drive root (e.g. C:\SentinelArchive\).
# The sentinel daemon finds archived copies via -sysmon-archive-dir flag.
# It is a sibling of <EventFiltering>, directly under <Sysmon> (NOT inside
# EventFiltering) — that is where the schema places it.
$existingAD = $xml.SelectSingleNode("//ArchiveDirectory")
if (-not $existingAD) {
    $ad = $xml.CreateElement("ArchiveDirectory")
    $ad.InnerText = $ArchiveDirName
    # Sysmon schema enforces element order: ArchiveDirectory must come AFTER
    # HashAlgorithms and BEFORE EventFiltering. Prepending (first child of
    # <Sysmon>) puts it before HashAlgorithms — out of schema order. Sysmon
    # silently ignores out-of-order elements (config accepted, feature off —
    # root cause of empty archive dir despite Archived="true" in events).
    # Inserting right before EventFiltering satisfies the schema ordering.
    $eventFiltering = $xml.SelectSingleNode("//EventFiltering")
    if ($eventFiltering) {
        $null = $xml.DocumentElement.InsertBefore($ad, $eventFiltering)
    } else {
        $null = $xml.DocumentElement.AppendChild($ad)
    }
    Write-Host ("Added ArchiveDirectory (before EventFiltering): " + $ArchiveDirName)
} else {
    Write-Host ("ArchiveDirectory already present: " + $existingAD.InnerText)
}

# The DOM guarantees well-formed XML (no separate validation step needed).
$patched = Join-Path $workDir "sentinel-sysmon-patched.xml"
# Save UTF-8 without BOM (Sysmon rejects BOM in some versions).
$enc = New-Object System.Text.UTF8Encoding($false)
$writer = New-Object System.Xml.XmlTextWriter($patched, $enc)
$writer.Formatting = [System.Xml.Formatting]::Indented
$xml.Save($writer)
$writer.Close()
Write-Host "Patched config written: $patched"

# Confirm ps-script rules landed in REAL elements (not comments).
$psRuleFC = $false
$nodes = $xml.SelectNodes("//FileCreate[@onmatch='include']/TargetFilename")
foreach ($n in $nodes) { if ($n.InnerText -match 'ps-script') { $psRuleFC = $true } }
$psRuleFD = $false
$nodesFD = $xml.SelectNodes("//FileDelete[@onmatch='include']/TargetFilename")
foreach ($n in $nodesFD) { if ($n.InnerText -match 'ps-script') { $psRuleFD = $true } }
if ($psRuleFC) {
    Write-Host "VERIFIED: ps-script rule active in FileCreate(include)."
} else {
    Write-Host "WARNING: ps-script rule NOT in FileCreate(include) after merge!"
}
if ($psRuleFD) {
    Write-Host "VERIFIED: ps-script rule active in FileDelete(include)."
} else {
    Write-Host "WARNING: ps-script rule NOT in FileDelete(include) after merge!"
}

# --- 7. validate + apply ---
Write-Host ""
Write-Host "Validating + applying config ..."
# Single-quoted segments hold the literal " chars (PowerShell has no \ escape).
$apply = Invoke-Native -Binary $sysmon -ArgString ('-accepteula -c "' + $patched + '"')
if ($apply.StdOut) { Write-Host $apply.StdOut }
if ($apply.StdErr) { Write-Host $apply.StdErr }
if ($apply.ExitCode -ne 0) {
    $msg = "sysmon64 rejected the patched config (exit $($apply.ExitCode)). Inspect: $patched"
    throw $msg
}
Write-Host "Config applied successfully."

# --- 8. verify ---
Write-Host ""
Write-Host "Current Sysmon config summary (FileCreate + FileDelete should now be active):"
$conf = Invoke-Native -Binary $sysmon -ArgString "-c"
$confText = $conf.StdOut
if ($conf.StdErr) { $confText = $confText + "`r`n" + $conf.StdErr }
$confText -split "`n" | Select-String -Pattern "FileCreate|FileDelete|Archive" | Select-Object -First 5

Write-Host ""
Write-Host "Done. EID 11 (FileCreate) + EID 23 (FileDelete) are now monitored for:"
Write-Host "  - \Temp\ps-script-          (snapshot vault capture)"
Write-Host "  - ...\Start Menu\Programs\Startup  (PERSIST-004)"
Write-Host "  - sentinel config files     (CONFIG-001)"
Write-Host ""
Write-Host "Archived FileDelete copies are in: C:\" + $ArchiveDirName + "\"
Write-Host "Pass this path to sentinel: -sysmon-archive-dir C:\" + $ArchiveDirName
Write-Host ""
Write-Host "To verify live: open a Cursor window (creates+deletes Temp\ps-script-*.ps1),"
Write-Host "then check the vault for captured content."

# Restore the caller's original ErrorActionPreference (we set Stop at top).
$ErrorActionPreference = $script:prevEAP

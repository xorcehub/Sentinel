// Package pathnorm normalizes Windows file/process paths so that rule matching
// and allowlist matching are insensitive to drive-slash vs drive-colon form and
// to slash direction.
//
// This is the fix for the exact bug that made the operator's old PowerShell
// detector self-trigger: git-bash exposes paths as /d/Analysis/foo while native
// Windows reports D:\Analysis\foo, and a naive match against one form missed the
// other. NormalizePath collapses both to a canonical lowercase backslash form.
//
// Canonical form: lowercase, backslash separators, drive letter colon form.
//
//	/d/Analysis/foo  ->  d:\analysis\foo
//	D:\Analysis\foo  ->  d:\analysis\foo
//	C:\Users\User01\  ->  c:\users\user01\
//
// This is applied to path-valued Event fields by the engine before rule
// evaluation, and by the allowlist before path-regex matching. It is NOT applied
// to registry key paths (TargetObject) — those are left as Sysmon reports them.
package pathnorm

import "strings"

// NormalizePath returns the canonical form of p. It is idempotent.
func NormalizePath(p string) string {
	if p == "" {
		return ""
	}
	// 1. unify separators to backslash
	p = strings.ReplaceAll(p, "/", "\\")
	// 2. drive-slash form at start:  \x\...  ->  X:\...
	//    (covers the git-bash /x/ form after step 1)
	if len(p) >= 3 && p[0] == '\\' {
		c := p[1]
		if isASCIILetter(c) && p[2] == '\\' {
			p = string(toUpperASCII(c)) + ":\\" + p[3:]
		}
	}
	// 3. lowercase
	return strings.ToLower(p)
}

func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func toUpperASCII(c byte) byte {
	if c >= 'a' && c <= 'z' {
		return c - ('a' - 'A')
	}
	return c
}

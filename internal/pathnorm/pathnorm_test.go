package pathnorm

import "testing"

func TestNormalizePath(t *testing.T) {
	cases := []struct{ in, want string }{
		{`/d/Analysis/foo`, `d:\analysis\foo`},
		{`D:\Analysis\foo`, `d:\analysis\foo`},
		{`C:\Users\User01\`, `c:\users\user01\`},
		{`/c/Users/User01/`, `c:\users\user01\`},
		{`C:\Windows\System32\conhost.exe`, `c:\windows\system32\conhost.exe`},
		{``, ``},
		// idempotent: normalizing an already-canonical path yields the same
		{`d:\analysis\foo`, `d:\analysis\foo`},
		// mixed slashes
		{`C:/Users/user01/x`, `c:\users\user01\x`},
	}
	for _, c := range cases {
		got := NormalizePath(c.in)
		// normalize twice and confirm stability
		if got2 := NormalizePath(got); got2 != got {
			t.Errorf("not idempotent: %q -> %q -> %q", c.in, got, got2)
		}
		if got != c.want {
			t.Errorf("NormalizePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The motivating bug: git-bash /d/ form and native D:\ form must compare equal
// after normalization. This is a dedicated regression test so it never returns.
func TestGitBashVsNativeEqual(t *testing.T) {
	a := NormalizePath(`/d/Analysis/auto_alert.ps1`)
	b := NormalizePath(`D:\Analysis\auto_alert.ps1`)
	if a != b {
		t.Fatalf("drive-slash vs drive-colon forms differ after normalize: %q vs %q", a, b)
	}
}

package uri

import (
	"path/filepath"
	"runtime"
	"testing"
)

func TestToPath_Unix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix path semantics")
	}
	cases := map[string]string{
		"file:///tmp/foo.conf":                "/tmp/foo.conf",
		"file:///home/user/.coraza.json":      "/home/user/.coraza.json",
		"file:///path%20with%20spaces/x.conf": "/path with spaces/x.conf",
		"/already/a/path":                     "/already/a/path",
	}
	for in, want := range cases {
		if got := ToPath(in); got != want {
			t.Errorf("ToPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestToPath_Windows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("windows path semantics")
	}
	cases := map[string]string{
		`file:///C:/dir/x.conf`:             `C:\dir\x.conf`,
		`file:///C:/path%20with%20spaces/y`: `C:\path with spaces\y`,
		`C:\already\a\path`:                 `C:\already\a\path`,
	}
	for in, want := range cases {
		if got := ToPath(in); got != want {
			t.Errorf("ToPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// ToURI(ToPath(x)) must round-trip to a well-formed file:// URI on every OS.
func TestRoundTrip(t *testing.T) {
	var uris []string
	if runtime.GOOS == "windows" {
		uris = []string{`file:///C:/dir/x.conf`, `file:///C:/a/b.conf`}
	} else {
		uris = []string{"file:///tmp/foo.conf", "file:///home/u/x.conf"}
	}
	for _, u := range uris {
		if got := ToURI(ToPath(u)); got != u {
			t.Errorf("round-trip ToURI(ToPath(%q)) = %q", u, got)
		}
	}
}

func TestToURI_IsWellFormed(t *testing.T) {
	// Whatever the OS, ToURI must produce a file:/// URI with forward slashes
	// and no backslashes (the bug on Windows was emitting file://C:\dir).
	p := filepath.Join("dirA", "dirB", "x.conf")
	abs, _ := filepath.Abs(p)
	got := ToURI(abs)
	if got[:8] != "file:///" {
		t.Errorf("ToURI(%q) = %q, want file:/// prefix", abs, got)
	}
	for _, c := range got {
		if c == '\\' {
			t.Errorf("ToURI produced a backslash: %q", got)
		}
	}
}

func TestToURI_Passthrough(t *testing.T) {
	const u = "file:///already/a/uri.conf"
	if got := ToURI(u); got != u {
		t.Errorf("ToURI(%q) = %q, want passthrough", u, got)
	}
}

// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package lsp

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coraza-incubator/coraza-lsp/internal/analysis"
	"github.com/coraza-incubator/coraza-lsp/internal/config"
)

// newTestServer returns a minimal Server without the glsp scaffolding.
// Enough to exercise cfgState and the diagnostic-options path. Uses
// OSFileSystem so existing temp-directory based tests keep working.
func newTestServer() *Server {
	return &Server{store: NewDocumentStore(), fs: OSFileSystem()}
}

func writeConfig(t *testing.T, dir, contents string) string {
	t.Helper()
	path := filepath.Join(dir, config.DefaultFilename)
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o644))
	return path
}

// --- LoadConfig --------------------------------------------------------------

func TestLoadConfig_NoFile_UsesDefaults(t *testing.T) {
	t.Parallel()
	s := newTestServer()
	dir := t.TempDir()

	var errs []string
	s.LoadConfig(dir, func(msg string) { errs = append(errs, msg) })

	assert.Equal(t, config.Default().FilePatterns, s.Config().FilePatterns)
	assert.Empty(t, errs, "no errors should be surfaced when config is absent")
	// DefaultOptions() is zero-value → severity overrides nil, EntrypointAware false.
	assert.Equal(t, analysis.DefaultOptions(), s.analysisOptions())
}

func TestLoadConfig_AppliesSeverityOverrides(t *testing.T) {
	t.Parallel()
	s := newTestServer()
	dir := t.TempDir()
	writeConfig(t, dir, `{
		"diagnostics": {
			"skipafter-not-found": "error",
			"unknown-variable": "off"
		}
	}`)

	var errs []string
	s.LoadConfig(dir, func(msg string) { errs = append(errs, msg) })
	assert.Empty(t, errs)

	opts := s.analysisOptions()
	assert.Equal(t, config.SeverityError, opts.SeverityOverrides["skipafter-not-found"])
	assert.Equal(t, config.SeverityOff, opts.SeverityOverrides["unknown-variable"])
}

func TestLoadConfig_ValidationErrorSurfaced(t *testing.T) {
	t.Parallel()
	s := newTestServer()
	dir := t.TempDir()
	writeConfig(t, dir, `{
		"diagnostics": {
			"not-a-real-code": "warning"
		}
	}`)

	var errs []string
	s.LoadConfig(dir, func(msg string) { errs = append(errs, msg) })
	require.NotEmpty(t, errs, "unknown diagnostic code should be surfaced")
	assert.Contains(t, errs[0], "unknown diagnostic code")
}

func TestLoadConfig_ParseErrorSurfaced(t *testing.T) {
	t.Parallel()
	s := newTestServer()
	dir := t.TempDir()
	writeConfig(t, dir, `{ this is not json`)

	var errs []string
	s.LoadConfig(dir, func(msg string) { errs = append(errs, msg) })
	require.NotEmpty(t, errs, "parse error should be surfaced")
	assert.Contains(t, errs[0], config.DefaultFilename)
}

// --- Hot reload via fsnotify --------------------------------------------------

// TestWatchConfig_HotReload edits the config file at runtime and asserts the
// server picks up the new severity map within the debounce window.
func TestWatchConfig_HotReload(t *testing.T) {
	t.Parallel()
	s := newTestServer()
	dir := t.TempDir()
	writeConfig(t, dir, `{
		"diagnostics": {"missing-id": "warning"}
	}`)

	s.LoadConfig(dir, func(string) {})
	assert.Equal(t, config.SeverityWarning, s.analysisOptions().SeverityOverrides["missing-id"])

	var changed int32
	require.NoError(t, s.WatchConfig(
		func(old, new config.Config) { atomic.AddInt32(&changed, 1) },
		func(msg string) { t.Logf("watch error: %s", msg) },
	))
	t.Cleanup(s.StopWatchConfig)

	// Edit the file in place.
	writeConfig(t, dir, `{
		"diagnostics": {"missing-id": "off"}
	}`)

	// Wait up to 2s (debounce is 100ms; fsnotify + macOS can be lazy).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&changed) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	assert.GreaterOrEqual(t, atomic.LoadInt32(&changed), int32(1), "onChange must fire after file edit")
	assert.Equal(t, config.SeverityOff, s.analysisOptions().SeverityOverrides["missing-id"])
}

// TestWatchConfig_CreationAfterStart: no config at start → config appears → loaded.
func TestWatchConfig_CreationAfterStart(t *testing.T) {
	t.Parallel()
	s := newTestServer()
	dir := t.TempDir()

	s.LoadConfig(dir, func(string) {}) // no file yet → defaults
	assert.Equal(t, analysis.DefaultOptions(), s.analysisOptions())

	var changed int32
	require.NoError(t, s.WatchConfig(
		func(_, _ config.Config) { atomic.AddInt32(&changed, 1) },
		func(string) {},
	))
	t.Cleanup(s.StopWatchConfig)

	// Create the config file now.
	writeConfig(t, dir, `{"diagnostics": {"invalid-phase": "off"}}`)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&changed) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	assert.GreaterOrEqual(t, atomic.LoadInt32(&changed), int32(1))
	assert.Equal(t, config.SeverityOff, s.analysisOptions().SeverityOverrides["invalid-phase"])
}

func TestWatchConfig_StopIsIdempotent(t *testing.T) {
	t.Parallel()
	s := newTestServer()
	dir := t.TempDir()
	s.LoadConfig(dir, func(string) {})
	require.NoError(t, s.WatchConfig(nil, nil))
	s.StopWatchConfig()
	s.StopWatchConfig() // must not panic or deadlock
}

// --- URI path parsing --------------------------------------------------------

func TestUriToPath(t *testing.T) {
	t.Parallel()
	// file:// URIs map to native OS paths (separators differ on Windows); the
	// passthrough case is returned verbatim. internal/uri has the OS-specific
	// unit tests; here we just confirm pkg/lsp delegates correctly.
	cases := []struct {
		in, want string
	}{
		{"file:///tmp/foo.conf", filepath.FromSlash("/tmp/foo.conf")},
		{"file:///home/user/.coraza.json", filepath.FromSlash("/home/user/.coraza.json")},
		{"file:///path%20with%20spaces/x.conf", filepath.FromSlash("/path with spaces/x.conf")},
		{"/already/a/path", "/already/a/path"}, // passthrough (not a file:// URI)
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, uriToPath(tc.in))
		})
	}
}

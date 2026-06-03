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

func TestOptionsFromConfig_ExtraNamesNormalized(t *testing.T) {
	t.Parallel()
	cfg := config.Config{
		ExtraOperators:       []string{"@detectXSS", "MyCustomOp"},
		ExtraActions:         []string{"MyAction"},
		ExtraTransformations: []string{"MyTransform"},
	}
	opts := optionsFromConfig(cfg)

	// Operator names: leading '@' stripped and lowercased.
	assert.Equal(t, map[string]bool{"detectxss": true, "mycustomop": true}, opts.ExtraOperators)
	// A name written without '@' still resolves.
	assert.True(t, opts.ExtraOperators["mycustomop"])
	// Actions and transformations: just lowercased.
	assert.Equal(t, map[string]bool{"myaction": true}, opts.ExtraActions)
	assert.Equal(t, map[string]bool{"mytransform": true}, opts.ExtraTransformations)
}

func TestOptionsFromConfig_OnlyExtrasStillBuildsOptions(t *testing.T) {
	t.Parallel()
	// No diagnostics/global/entrypoint — only Extra* set. The early-return guard
	// must NOT fire, so the Extra* maps are populated rather than dropped.
	cfg := config.Config{ExtraOperators: []string{"myop"}}
	opts := optionsFromConfig(cfg)

	assert.NotEqual(t, analysis.DefaultOptions(), opts, "extras-only config must produce non-default options")
	assert.True(t, opts.ExtraOperators["myop"])
}

func TestOptionsFromConfig_EmptyIsDefault(t *testing.T) {
	t.Parallel()
	assert.Equal(t, analysis.DefaultOptions(), optionsFromConfig(config.Config{}))
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

// --- client-declared extras (LSP initializationOptions) ---------------------

// TestSetClientExtra_NormalizedIntoOptions verifies that extras declared by the
// editor client are normalized (operator '@' stripped, all lowercased) and
// surface through analysisOptions().
func TestSetClientExtra_NormalizedIntoOptions(t *testing.T) {
	t.Parallel()
	s := newTestServer()

	s.setClientExtra(
		[]string{"@myOp"},
		[]string{"MyAction"},
		[]string{"MyTransform"},
	)

	opts := s.analysisOptions()
	assert.True(t, opts.ExtraOperators["myop"], "operator '@myOp' should normalize to 'myop'")
	assert.True(t, opts.ExtraActions["myaction"])
	assert.True(t, opts.ExtraTransformations["mytransform"])
}

// TestAnalysisOptions_UnionsConfigAndClientExtras verifies that the extras from
// `.coraza.json` and from the client are UNIONed, not replaced, and that the
// merge does not mutate the loaded config's own maps.
func TestAnalysisOptions_UnionsConfigAndClientExtras(t *testing.T) {
	t.Parallel()
	s := newTestServer()
	dir := t.TempDir()
	writeConfig(t, dir, `{
		"extraOperators": ["@fromConfig"],
		"extraActions": ["actFromConfig"],
		"extraTransformations": ["tfFromConfig"]
	}`)

	var errs []string
	s.LoadConfig(dir, func(msg string) { errs = append(errs, msg) })
	assert.Empty(t, errs)

	s.setClientExtra(
		[]string{"@fromClient"},
		[]string{"actFromClient"},
		[]string{"tfFromClient"},
	)

	opts := s.analysisOptions()
	// Operators: both config- and client-declared present.
	assert.True(t, opts.ExtraOperators["fromconfig"])
	assert.True(t, opts.ExtraOperators["fromclient"])
	// Actions: union.
	assert.True(t, opts.ExtraActions["actfromconfig"])
	assert.True(t, opts.ExtraActions["actfromclient"])
	// Transformations: union.
	assert.True(t, opts.ExtraTransformations["tffromconfig"])
	assert.True(t, opts.ExtraTransformations["tffromclient"])

	// The union must not have mutated cfgState.opts' own maps.
	s.cfgState.mu.RLock()
	base := s.cfgState.opts.ExtraOperators
	s.cfgState.mu.RUnlock()
	assert.Equal(t, map[string]bool{"fromconfig": true}, base,
		"config-derived ExtraOperators must not be mutated by the union")
}

// TestAnalysisOptions_NoExtrasStaysNil verifies an empty union leaves the
// Extra* fields nil (so they index as false in the analyser).
func TestAnalysisOptions_NoExtrasStaysNil(t *testing.T) {
	t.Parallel()
	s := newTestServer()
	dir := t.TempDir()
	s.LoadConfig(dir, nil)
	s.setClientExtra(nil, nil, nil)

	opts := s.analysisOptions()
	assert.Nil(t, opts.ExtraOperators)
	assert.Nil(t, opts.ExtraActions)
	assert.Nil(t, opts.ExtraTransformations)
}

// TestStringSliceFromAny covers the JSON-decode helper used to parse
// initializationOptions.
func TestStringSliceFromAny(t *testing.T) {
	t.Parallel()

	assert.Equal(t, []string{"a", "b"}, stringSliceFromAny([]any{"a", "b"}))
	// Non-string elements are filtered out.
	assert.Equal(t, []string{"a"}, stringSliceFromAny([]any{"a", 1, true, nil}))
	// An array with no strings yields nil.
	assert.Nil(t, stringSliceFromAny([]any{1, 2}))
	// Non-array inputs yield nil.
	assert.Nil(t, stringSliceFromAny("not-an-array"))
	assert.Nil(t, stringSliceFromAny(map[string]any{"x": "y"}))
	assert.Nil(t, stringSliceFromAny(nil))
}

// TestParseClientExtras covers the initializationOptions object parser.
func TestParseClientExtras(t *testing.T) {
	t.Parallel()

	// nil / wrong-typed InitializationOptions must be safe (no extras).
	ops, acts, tfs := parseClientExtras(nil)
	assert.Nil(t, ops)
	assert.Nil(t, acts)
	assert.Nil(t, tfs)

	ops, acts, tfs = parseClientExtras("garbage")
	assert.Nil(t, ops)
	assert.Nil(t, acts)
	assert.Nil(t, tfs)

	// A well-formed object with all three keys.
	ops, acts, tfs = parseClientExtras(map[string]any{
		"extraOperators":       []any{"@myOp"},
		"extraActions":         []any{"myAct"},
		"extraTransformations": []any{"myTf"},
	})
	assert.Equal(t, []string{"@myOp"}, ops)
	assert.Equal(t, []string{"myAct"}, acts)
	assert.Equal(t, []string{"myTf"}, tfs)

	// Missing keys yield nil for those.
	ops, acts, tfs = parseClientExtras(map[string]any{"extraActions": []any{"only"}})
	assert.Nil(t, ops)
	assert.Equal(t, []string{"only"}, acts)
	assert.Nil(t, tfs)
}

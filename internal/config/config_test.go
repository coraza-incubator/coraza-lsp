// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	return path
}

func TestLoad_Missing(t *testing.T) {
	t.Parallel()
	cfg, err := Load(filepath.Join(t.TempDir(), "does-not-exist.json"))
	assert.NoError(t, err)
	assert.Nil(t, cfg)
}

func TestLoad_FullRoundTrip(t *testing.T) {
	t.Parallel()
	src := `{
		"$schema": "https://example.com/schema.json",
		"entrypoint": "crs-setup.conf",
		"includePaths": ["rules", "vendor/rules"],
		"global": true,
		"filePatterns": ["**/*.conf", "**/*.modsec"],
		"ignore": ["**/deprecated/**"],
		"diagnostics": {
			"skipafter-not-found": "warning",
			"unknown-variable": "off"
		}
	}`
	path := writeTemp(t, ".coraza.json", src)
	cfg, err := Load(path)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "crs-setup.conf", cfg.Entrypoint)
	assert.Equal(t, []string{"rules", "vendor/rules"}, cfg.IncludePaths)
	assert.True(t, cfg.Global)
	assert.Equal(t, []string{"**/*.conf", "**/*.modsec"}, cfg.FilePatterns)
	assert.Equal(t, []string{"**/deprecated/**"}, cfg.Ignore)
	assert.Equal(t, SeverityWarning, cfg.Diagnostics["skipafter-not-found"])
	assert.Equal(t, SeverityOff, cfg.Diagnostics["unknown-variable"])
}

func TestLoad_JSONCCommentsStripped(t *testing.T) {
	t.Parallel()
	// The Template shipped by `coraza-lsp init` has several "//" keys at the
	// top level. This asserts they parse without error.
	path := writeTemp(t, ".coraza.json", Template)
	cfg, err := Load(path)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, []string{"**/*.conf"}, cfg.FilePatterns)
}

func TestLoad_CommentsAtArbitraryDepth(t *testing.T) {
	t.Parallel()
	src := `{
		"//": "top",
		"diagnostics": {
			"//": "nested",
			"skipafter-not-found": "warning"
		}
	}`
	path := writeTemp(t, ".coraza.json", src)
	cfg, err := Load(path)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.NotContains(t, cfg.Diagnostics, "//")
	assert.Equal(t, SeverityWarning, cfg.Diagnostics["skipafter-not-found"])
}

func TestLoad_Malformed(t *testing.T) {
	t.Parallel()
	path := writeTemp(t, ".coraza.json", `{ this is not json`)
	_, err := Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), filepath.Base(path), "error should name the file")
}

func TestDiscover_FindsClosest(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	nested := filepath.Join(root, "a", "b", "c")
	require.NoError(t, os.MkdirAll(nested, 0o755))
	// Only the `a/` level has a config.
	configPath := filepath.Join(root, "a", DefaultFilename)
	require.NoError(t, os.WriteFile(configPath, []byte("{}"), 0o644))

	got := Discover(nested)
	// Use EvalSymlinks to compare — macOS /var → /private/var etc.
	want, _ := filepath.EvalSymlinks(configPath)
	gotResolved, _ := filepath.EvalSymlinks(got)
	assert.Equal(t, want, gotResolved)
}

func TestDiscover_None(t *testing.T) {
	t.Parallel()
	got := Discover(t.TempDir())
	assert.Equal(t, "", got)
}

func TestMerge_FileWinsWithoutOverride(t *testing.T) {
	t.Parallel()
	file := Config{Entrypoint: "foo.conf", Global: true}
	defaults := Default()
	file.Merge(defaults)
	assert.Equal(t, "foo.conf", file.Entrypoint)
	assert.True(t, file.Global)
	assert.Equal(t, defaults.FilePatterns, file.FilePatterns, "unset list should inherit")
	assert.Equal(t, defaults.Ignore, file.Ignore)
}

func TestMerge_ExplicitEmptyIgnore(t *testing.T) {
	t.Parallel()
	// File author wrote "ignore": [] — respect that, don't re-inject defaults.
	file := Config{Ignore: []string{}}
	file.Merge(Default())
	assert.Equal(t, []string{}, file.Ignore)
}

func TestValidate_UnknownDiagnosticCode(t *testing.T) {
	t.Parallel()
	RegisterDiagnosticCodes("missing-id", "invalid-phase")
	cfg := &Config{Diagnostics: map[string]Severity{"not-a-real-code": SeverityWarning}}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown diagnostic code")
	assert.Contains(t, err.Error(), "not-a-real-code")
}

func TestValidate_InvalidSeverity(t *testing.T) {
	t.Parallel()
	RegisterDiagnosticCodes("missing-id")
	cfg := &Config{Diagnostics: map[string]Severity{"missing-id": Severity("panic")}}
	err := cfg.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid severity")
	assert.Contains(t, err.Error(), "panic")
}

func TestValidate_OK(t *testing.T) {
	t.Parallel()
	RegisterDiagnosticCodes("missing-id", "skipafter-not-found")
	cfg := &Config{Diagnostics: map[string]Severity{
		"missing-id":          SeverityError,
		"skipafter-not-found": SeverityOff,
	}}
	assert.NoError(t, cfg.Validate())
}

func TestRegisterDiagnosticCodes_Idempotent(t *testing.T) {
	// Not parallel — this test mutates a package-level registry.
	RegisterDiagnosticCodes("a", "b")
	RegisterDiagnosticCodes("a", "c")
	got := knownDiagnosticCodes()
	assert.Contains(t, got, "a")
	assert.Contains(t, got, "b")
	assert.Contains(t, got, "c")
	// No duplicates.
	n := 0
	for _, k := range got {
		if k == "a" {
			n++
		}
	}
	assert.Equal(t, 1, n, "code 'a' should not be registered twice")
}

func TestTemplateValidJSONAfterStrip(t *testing.T) {
	t.Parallel()
	// Sanity: the shipped Template must parse cleanly through stripCommentProps.
	cleaned, err := stripCommentProps([]byte(Template))
	require.NoError(t, err)
	require.True(t, strings.Contains(string(cleaned), `"filePatterns"`))
	require.False(t, strings.Contains(string(cleaned), `"//"`), "cleaned template should have no // keys")
}

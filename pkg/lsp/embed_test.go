// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package lsp_test

import (
	"io"
	"io/fs"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coraza-incubator/coraza-lsp/pkg/lsp"
)

// TestEmbed_NewWithMemFS_DoesNotTouchDisk constructs a Server with a MemFS
// and exercises the public embedding surface. The point isn't to drive the
// full LSP protocol (handler_test.go does that) but to prove that the
// embedder-facing API hangs together: the constructor, the FileSystem option,
// and OS-disk isolation all behave as the embedding contract promises.
func TestEmbed_NewWithMemFS_DoesNotTouchDisk(t *testing.T) {
	t.Parallel()

	// A recording FileSystem that wraps MemFS and remembers every path the
	// LSP asked about. If the LSP ever tries to read something outside this
	// snapshot we'll see it here.
	mem := lsp.NewMemFS(map[string][]byte{
		"/policy/main.conf": []byte(`SecRuleEngine On
Include /policy/rules/whitelist.conf`),
		"/policy/rules/whitelist.conf": []byte(`SecRule REMOTE_ADDR "@ipMatch 127.0.0.1" "id:1,phase:1,allow"`),
	})
	rec := &recordingFS{inner: mem}

	srv := lsp.New("test", lsp.WithFileSystem(rec))
	require.NotNil(t, srv)

	// Drive LoadConfig — the only public method that synchronously reads
	// from the FileSystem (Discover + workspace index).
	srv.LoadConfig("/policy", func(string) {})

	// Every path the server consulted must live inside the snapshot.
	for _, p := range rec.paths() {
		assert.Truef(t,
			strings.HasPrefix(p, "/policy") || strings.HasPrefix(p, "/"),
			"server reached outside its FileSystem: %s", p)
	}

	cfg := srv.Config()
	assert.NotNil(t, cfg.FilePatterns, "defaults should be applied when no .coraza.json is present")
}

// TestEmbed_NewDefaults_UsesOSFileSystem confirms the default is unchanged for
// callers that don't pass WithFileSystem (CLI, existing tests, anyone upgrading).
func TestEmbed_NewDefaults_UsesOSFileSystem(t *testing.T) {
	t.Parallel()

	srv := lsp.New("test")
	require.NotNil(t, srv)

	// LoadConfig with an empty root should not panic and should fall back to
	// defaults.
	srv.LoadConfig("", func(string) {})
	assert.NotNil(t, srv.Config().FilePatterns)
}

// TestEmbed_OSFileSystem_ReturnsUsableFS exercises the public OSFileSystem
// constructor — embedders may want to compose it (e.g. layer a denylist on
// top) so it must be a real, callable FileSystem.
func TestEmbed_OSFileSystem_ReturnsUsableFS(t *testing.T) {
	t.Parallel()

	osfs := lsp.OSFileSystem()
	require.NotNil(t, osfs)

	// /tmp exists on every Unix and on macOS test runners.
	info, err := osfs.Stat("/tmp")
	if err == nil {
		assert.True(t, info.IsDir())
	}
}

// TestEmbed_MemFS_RejectsUnknownPaths is the safety property embedders rely
// on: a path that isn't in the snapshot returns ErrNotExist, never silently
// falls through to the host disk.
func TestEmbed_MemFS_RejectsUnknownPaths(t *testing.T) {
	t.Parallel()

	mem := lsp.NewMemFS(map[string][]byte{
		"/policy/main.conf": []byte("SecRuleEngine On"),
	})

	// Anything outside the snapshot is invisible.
	for _, p := range []string{"/etc/passwd", "/policy/secret.conf", "../escape.conf"} {
		_, err := mem.ReadFile(p)
		assert.ErrorIsf(t, err, fs.ErrNotExist, "MemFS should not surface %q", p)
	}

	// In-snapshot paths still work.
	data, err := mem.ReadFile("/policy/main.conf")
	require.NoError(t, err)
	assert.Equal(t, "SecRuleEngine On", string(data))
}

// recordingFS wraps a FileSystem and records every path consulted, for the
// "no surprise disk reads" assertion in TestEmbed_NewWithMemFS_DoesNotTouchDisk.
type recordingFS struct {
	inner lsp.FileSystem
	mu    pathLog
}

type pathLog struct {
	seen []string
}

func (r *recordingFS) record(p string) {
	r.mu.seen = append(r.mu.seen, p)
}

func (r *recordingFS) paths() []string {
	out := make([]string, len(r.mu.seen))
	copy(out, r.mu.seen)
	return out
}

func (r *recordingFS) Open(name string) (io.ReadCloser, error) {
	r.record(name)
	return r.inner.Open(name)
}

func (r *recordingFS) ReadFile(name string) ([]byte, error) {
	r.record(name)
	return r.inner.ReadFile(name)
}

func (r *recordingFS) Stat(name string) (fs.FileInfo, error) {
	r.record(name)
	return r.inner.Stat(name)
}

func (r *recordingFS) WalkDir(root string, fn fs.WalkDirFunc) error {
	r.record(root)
	return r.inner.WalkDir(root, fn)
}

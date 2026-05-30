// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package lsp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coraza-incubator/coraza-lsp/internal/config"
	"github.com/coraza-incubator/coraza-lsp/internal/parser"
	"github.com/coraza-incubator/coraza-lsp/internal/vfs"
)

// testFS is the FileSystem used by indexWorkspace tests in this file.
var testFS = vfs.OSFileSystem()

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

// --- indexWorkspace ----------------------------------------------------------

func TestIndexWorkspace_SniffsSecLang(t *testing.T) {
	t.Parallel()
	root := t.TempDir()

	// Yes — SecLang.
	writeFile(t, filepath.Join(root, "rules", "main.conf"),
		`SecRule ARGS "@rx x" "id:1,phase:2,deny"`)
	// Yes — SecRuleEngine directive.
	writeFile(t, filepath.Join(root, "rules", "engine.conf"),
		`SecRuleEngine On`)
	// No — nginx-like, matches .conf but not sniff.
	writeFile(t, filepath.Join(root, "nginx.conf"),
		"server {\n  listen 80;\n}\n")
	// No — wrong extension.
	writeFile(t, filepath.Join(root, "rules", "notes.txt"),
		`SecRule ARGS "@rx x" "id:2,phase:2,deny"`)

	idx := indexWorkspace(testFS, root, []string{"**/*.conf"}, []string{"**/.git/**"})
	assert.Len(t, idx, 2, "expected two indexed SecLang files")

	// Spot-check the parse worked.
	for _, f := range idx {
		assert.NotNil(t, f.AST)
	}
}

func TestIndexWorkspace_RespectsIgnore(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "keep.conf"),
		`SecRule ARGS "@rx x" "id:1,phase:2,deny"`)
	writeFile(t, filepath.Join(root, "deprecated", "old.conf"),
		`SecRule ARGS "@rx x" "id:2,phase:2,deny"`)
	writeFile(t, filepath.Join(root, ".git", "hidden.conf"),
		`SecRule ARGS "@rx x" "id:3,phase:2,deny"`)

	idx := indexWorkspace(testFS, root,
		[]string{"**/*.conf"},
		[]string{"**/deprecated/**", "**/.git/**"})

	// Only keep.conf should be indexed.
	assert.Len(t, idx, 1)
	for _, f := range idx {
		assert.Contains(t, f.Path, "keep.conf")
	}
}

// --- matchesAny (doublestar glob semantics) ---------------------------------

func TestMatchesAny_Doublestar(t *testing.T) {
	t.Parallel()
	root := "/ws"
	cases := []struct {
		name  string
		path  string
		globs []string
		want  bool
	}{
		{"doublestar matches nested", "/ws/a/b/c.conf", []string{"**/*.conf"}, true},
		{"doublestar matches top-level", "/ws/c.conf", []string{"**/*.conf"}, true},
		{"non-matching extension", "/ws/a/b/c.txt", []string{"**/*.conf"}, false},
		{"bare basename glob matches at depth", "/ws/a/b/c.conf", []string{"*.conf"}, true},
		{"brace alternation", "/ws/a/x.modsec", []string{"**/*.{conf,modsec}"}, true},
		{"multi doublestar", "/ws/a/b/c/d.conf", []string{"**/**/*.conf"}, true},
		{"anchored subdir does not match other depth", "/ws/a/rules/foo.conf", []string{"rules/*.conf"}, false},
		{"anchored subdir matches at root", "/ws/rules/foo.conf", []string{"rules/*.conf"}, true},
		{"ignore deprecated tree", "/ws/x/deprecated/old.conf", []string{"**/deprecated/**"}, true},
		{"ignore git tree", "/ws/.git/hidden.conf", []string{"**/.git/**"}, true},
		{"malformed glob is skipped", "/ws/a.conf", []string{"[", "**/*.conf"}, true},
		{"empty globs", "/ws/a.conf", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := matchesAny(filepath.FromSlash(tc.path), tc.globs, filepath.FromSlash(root))
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestIndexWorkspace_NestedDoublestar(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a", "b", "c.conf"),
		`SecRule ARGS "@rx x" "id:1,phase:2,deny"`)

	idx := indexWorkspace(testFS, root, []string{"**/*.conf"}, nil)
	assert.Len(t, idx, 1, "**/*.conf must match a deeply nested file")
}

func TestIndexWorkspace_EmptyRoot(t *testing.T) {
	t.Parallel()
	idx := indexWorkspace(testFS, "", []string{"**/*.conf"}, nil)
	assert.Empty(t, idx)
}

// --- DocumentStore index + AllASTs ------------------------------------------

func TestDocumentStore_SetIndex_AllASTs(t *testing.T) {
	t.Parallel()
	s := NewDocumentStore()

	// Open doc.
	s.Open("file:///open.conf", `SecRule ARGS "@rx x" "id:100,phase:2,deny"`, 1)
	// Indexed-only doc.
	f := parser.Parse("file:///indexed.conf", `SecRule ARGS "@rx x" "id:200,phase:2,deny"`)
	s.SetIndex(map[string]*indexedFile{
		"file:///indexed.conf": {Path: "/indexed.conf", AST: f},
	})

	all := s.AllASTs()
	assert.Len(t, all, 2)
	assert.Contains(t, all, "file:///open.conf")
	assert.Contains(t, all, "file:///indexed.conf")

	// Nil SetIndex clears.
	s.SetIndex(nil)
	all = s.AllASTs()
	assert.Len(t, all, 1)
}

// --- Cross-file duplicate-id augmentation -----------------------------------

func TestAugmentCrossFile_FlagsDuplicateAcrossFiles(t *testing.T) {
	t.Parallel()
	srv := newTestServer()

	// cfgState starts zero; explicitly enable Global.
	srv.cfgState.cfg = config.Config{Global: true}
	srv.cfgState.opts = optionsFromConfig(srv.cfgState.cfg)

	// Current (open) file with id:1001.
	currentAST := parser.Parse("file:///current.conf",
		`SecRule ARGS "@rx x" "id:1001,phase:2,deny"`)
	// Another indexed file with the same id.
	otherAST := parser.Parse("file:///other.conf",
		`SecRule ARGS "@rx y" "id:1001,phase:2,deny"`)
	srv.store.SetIndex(map[string]*indexedFile{
		"file:///other.conf": {Path: "/other.conf", AST: otherAST},
	})

	got := srv.augmentCrossFile("file:///current.conf", currentAST, nil)
	require.Len(t, got, 1)
	assert.Contains(t, got[0].Message, "1001")
	assert.Contains(t, got[0].Message, "file:///other.conf")
}

func TestAugmentCrossFile_SkippedWhenGlobalFalse(t *testing.T) {
	t.Parallel()
	srv := newTestServer()
	srv.cfgState.cfg = config.Config{Global: false}

	currentAST := parser.Parse("file:///current.conf",
		`SecRule ARGS "@rx x" "id:1001,phase:2,deny"`)
	srv.store.SetIndex(map[string]*indexedFile{
		"file:///other.conf": {
			AST: parser.Parse("file:///other.conf",
				`SecRule ARGS "@rx y" "id:1001,phase:2,deny"`),
		},
	})

	got := srv.augmentCrossFile("file:///current.conf", currentAST, nil)
	assert.Empty(t, got, "global:false should suppress cross-file detection")
}

func TestAugmentCrossFile_RespectsOffSeverity(t *testing.T) {
	t.Parallel()
	srv := newTestServer()
	srv.cfgState.cfg = config.Config{
		Global: true,
		Diagnostics: map[string]config.Severity{
			"duplicate-id": config.SeverityOff,
		},
	}
	srv.cfgState.opts = optionsFromConfig(srv.cfgState.cfg)

	currentAST := parser.Parse("file:///c.conf",
		`SecRule ARGS "@rx x" "id:1,phase:2,deny"`)
	srv.store.SetIndex(map[string]*indexedFile{
		"file:///o.conf": {
			AST: parser.Parse("file:///o.conf",
				`SecRule ARGS "@rx y" "id:1,phase:2,deny"`),
		},
	})

	got := srv.augmentCrossFile("file:///c.conf", currentAST, nil)
	assert.Empty(t, got, "duplicate-id:off should suppress cross-file hits")
}

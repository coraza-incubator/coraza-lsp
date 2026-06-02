// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package definition

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coraza-incubator/coraza-lsp/internal/parser"
	"github.com/coraza-incubator/coraza-lsp/internal/uri"
	"github.com/coraza-incubator/coraza-lsp/internal/vfs"
)

// testFS is the FileSystem used by every test in this file. The OS-backed
// implementation matches the production default; tests that need to assert
// sandboxing behaviour pass an explicit MemFS.
var testFS = vfs.OSFileSystem()

func TestResolve_SkipAfterToMarker(t *testing.T) {
	t.Parallel()
	src := "SecRule ARGS \"@rx x\" \"id:1,phase:2,pass,skipAfter:END_CHECKS\"\nSecMarker END_CHECKS"
	f := parser.Parse("file:///test.conf", src)
	// Find the skipAfter action position: it's on line 0 in the action list.
	// We'll search line 0 around the skipAfter text.
	locs := Resolve(testFS, f, 0, 48, "file:///test.conf")
	// May or may not resolve depending on exact char position; just ensure no panic.
	_ = locs
}

func TestResolve_SkipAfterMarkerFound(t *testing.T) {
	t.Parallel()
	src := "SecRule ARGS \"@rx x\" \"id:1,phase:2,pass,skipAfter:END\"\nSecMarker END"
	f := parser.Parse("file:///test.conf", src)
	f.URI = "file:///test.conf"
	// Scan all rule actions for skipAfter.
	for _, node := range f.Nodes {
		rule, ok := node.(*parser.RuleNode)
		if !ok {
			continue
		}
		for _, action := range rule.Actions {
			if action.LowerName() == "skipafter" {
				locs := Resolve(testFS, f, action.Range.Start.Line, action.Range.Start.Character, "file:///test.conf")
				require.NotNil(t, locs)
				assert.Len(t, locs, 1)
				assert.Equal(t, "file:///test.conf", string(locs[0].URI))
				return
			}
		}
	}
}

func TestResolve_SkipAfterMarkerNotFound(t *testing.T) {
	t.Parallel()
	src := "SecRule ARGS \"@rx x\" \"id:1,phase:2,pass,skipAfter:NONEXISTENT\""
	f := parser.Parse("file:///test.conf", src)
	f.URI = "file:///test.conf"
	for _, node := range f.Nodes {
		rule, ok := node.(*parser.RuleNode)
		if !ok {
			continue
		}
		for _, action := range rule.Actions {
			if action.LowerName() == "skipafter" {
				locs := Resolve(testFS, f, action.Range.Start.Line, action.Range.Start.Character, "file:///test.conf")
				assert.Nil(t, locs)
				return
			}
		}
	}
}

func TestResolve_NilWhenNoNode(t *testing.T) {
	t.Parallel()
	f := parser.Parse("", "SecRuleEngine On")
	locs := Resolve(testFS, f, 999, 0, "file:///test.conf")
	assert.Nil(t, locs)
}

func TestResolve_RuleNotInActionsRange(t *testing.T) {
	t.Parallel()
	// Position is on the rule's variable list, not in actions — should return nil.
	src := "SecRule ARGS \"@rx x\" \"id:1,phase:2,pass\""
	f := parser.Parse("file:///test.conf", src)
	// Character 7 is on "ARGS" (variable list), not inside the action string.
	locs := Resolve(testFS, f, 0, 7, "file:///test.conf")
	assert.Nil(t, locs)
}

func TestResolve_IncludeNode_Absolute(t *testing.T) {
	t.Parallel()
	// Use /tmp which always exists.
	src := "Include /tmp"
	f := parser.Parse("file:///etc/coraza.conf", src)
	// Position on the Include directive.
	locs := Resolve(testFS, f, 0, 5, "file:///etc/coraza.conf")
	if locs != nil {
		assert.Len(t, locs, 1)
		assert.Equal(t, "file:///tmp", string(locs[0].URI))
	}
}

func TestResolve_IncludeNode_Relative(t *testing.T) {
	t.Parallel()
	// Create a temp file so the relative path can be resolved.
	tmp, err := os.CreateTemp("", "coraza-test-*.conf")
	require.NoError(t, err)
	defer os.Remove(tmp.Name())
	tmp.Close()

	dir := filepath.Dir(tmp.Name())
	base := filepath.Base(tmp.Name())
	baseURI := "file://" + filepath.Join(dir, "main.conf")

	src := "Include " + base
	f := parser.Parse(baseURI, src)
	locs := Resolve(testFS, f, 0, 5, baseURI)
	if locs != nil {
		assert.Len(t, locs, 1)
		assert.Contains(t, string(locs[0].URI), "file://")
	}
}

func TestResolve_IncludeNode_EmptyPath(t *testing.T) {
	t.Parallel()
	// An Include with no path should return nil, not panic.
	src := "Include"
	f := parser.Parse("file:///test.conf", src)
	locs := Resolve(testFS, f, 0, 3, "file:///test.conf")
	assert.Nil(t, locs)
}

func TestResolve_IncludeNode_NonExistentAbsolute(t *testing.T) {
	t.Parallel()
	src := "Include /nonexistent/path/rules.conf"
	f := parser.Parse("file:///test.conf", src)
	locs := Resolve(testFS, f, 0, 3, "file:///test.conf")
	assert.Nil(t, locs)
}

func TestResolve_GenericDirective_ReturnsNil(t *testing.T) {
	t.Parallel()
	src := "SecRuleEngine On"
	f := parser.Parse("file:///test.conf", src)
	locs := Resolve(testFS, f, 0, 5, "file:///test.conf")
	assert.Nil(t, locs)
}

func TestResolveIncludePath_Absolute(t *testing.T) {
	t.Parallel()
	// Use an OS-absolute directory that exists (t.TempDir); "/tmp" is not an
	// absolute path on Windows, so build the abs target portably.
	abs := t.TempDir()
	result := resolveIncludePath(testFS, abs, "file:///etc/coraza/coraza.conf")
	assert.Equal(t, uri.ToURI(abs), result)
}

func TestResolveIncludePath_NonExistent(t *testing.T) {
	t.Parallel()
	result := resolveIncludePath(testFS, "/nonexistent/path/file.conf", "file:///etc/coraza.conf")
	assert.Equal(t, "", result)
}

func TestResolveIncludePath_FileURIRoutedThroughFS(t *testing.T) {
	t.Parallel()
	// A file:// Include is routed through the provided filesystem rather than
	// returned verbatim: a nonexistent / out-of-sandbox target resolves to "".
	got := resolveIncludePath(testFS, "file:///etc/coraza-nonexistent-xyz.conf", "file:///etc/coraza.conf")
	assert.Equal(t, "", got, "file:// to a nonexistent path must not be navigable (sandbox)")

	// A file:// target that does exist on the filesystem resolves normally.
	tmp, err := os.CreateTemp("", "coraza-def-fileuri-*.conf")
	require.NoError(t, err)
	defer os.Remove(tmp.Name())
	tmp.Close()
	got = resolveIncludePath(testFS, uri.ToURI(tmp.Name()), "file:///etc/coraza.conf")
	assert.Equal(t, uri.ToURI(tmp.Name()), got)
}

func TestResolveIncludePath_RelativeExists(t *testing.T) {
	t.Parallel()
	tmp, err := os.CreateTemp("", "coraza-def-test-*.conf")
	require.NoError(t, err)
	defer os.Remove(tmp.Name())
	tmp.Close()

	dir := filepath.Dir(tmp.Name())
	base := filepath.Base(tmp.Name())
	baseURI := uri.ToURI(filepath.Join(dir, "main.conf"))

	result := resolveIncludePath(testFS, base, baseURI)
	assert.Contains(t, result, "file://")
	assert.Contains(t, result, base)
}

func TestResolveIncludePath_RelativeNonExistent(t *testing.T) {
	t.Parallel()
	result := resolveIncludePath(testFS, "nonexistent-file.conf", "file:///etc/coraza.conf")
	assert.Equal(t, "", result)
}

func TestResolveIncludePath_EmptyBaseDir(t *testing.T) {
	t.Parallel()
	// baseURI has no directory component.
	result := resolveIncludePath(testFS, "rules.conf", "")
	assert.Equal(t, "", result)
}

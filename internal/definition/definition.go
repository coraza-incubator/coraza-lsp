// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

// Package definition provides go-to-definition for SecLang elements.
package definition

import (
	"path/filepath"
	"strings"

	protocol_3_16 "github.com/tliron/glsp/protocol_3_16"

	"github.com/coraza-incubator/coraza-lsp/internal/parser"
	"github.com/coraza-incubator/coraza-lsp/internal/uri"
	"github.com/coraza-incubator/coraza-lsp/internal/vfs"
)

// Resolve returns the definition location(s) for the element at the given position.
// Returns nil when no definition is available. fs is consulted to verify that
// the targets of Include directives exist; pass vfs.OSFileSystem() for the
// CLI server or an embedder-provided FileSystem for sandboxed deployments.
//
// Supported cases:
//  1. Cursor on a skipAfter: value → SecMarker in the same file
//  2. Cursor on an Include path → the included file URI
func Resolve(filesys vfs.FileSystem, f *parser.File, line, char int, docURI string) []protocol_3_16.Location {
	node := f.NodeAtPosition(line, char)
	if node == nil {
		return nil
	}

	switch n := node.(type) {
	case *parser.IncludeNode:
		// Cursor anywhere on an Include line → jump to the included file.
		if n.Path == "" {
			return nil
		}
		uri := resolveIncludePath(filesys, n.Path, docURI)
		if uri == "" {
			return nil
		}
		return []protocol_3_16.Location{
			{
				URI:   protocol_3_16.DocumentUri(uri),
				Range: protocol_3_16.Range{}, // start of file
			},
		}

	case *parser.RuleNode:
		return resolveInRule(n, f, line, char)
	}

	return nil
}

// resolveInRule looks for skipAfter targets within a rule node.
func resolveInRule(rule *parser.RuleNode, f *parser.File, line, char int) []protocol_3_16.Location {
	if !rule.ActionsRange.ContainsPosition(line, char) {
		return nil
	}
	for _, action := range rule.Actions {
		if action.LowerName() != "skipafter" {
			continue
		}
		if !action.Range.ContainsPosition(line, char) {
			continue
		}
		// Found cursor on a skipAfter action — look up the marker.
		marker := f.FindMarker(action.Value)
		if marker == nil {
			return nil
		}
		return []protocol_3_16.Location{
			{
				URI:   protocol_3_16.DocumentUri(f.URI),
				Range: toProtoRange(marker.GetRange()),
			},
		}
	}
	return nil
}

// resolveIncludePath converts an Include path to a file URI.
// baseURI is the URI of the document containing the Include directive.
func resolveIncludePath(filesys vfs.FileSystem, path, baseURI string) string {
	if strings.HasPrefix(path, "file://") {
		// Route the file:// target through the provided filesystem rather than
		// returning it verbatim — otherwise an Include of e.g. file:///etc/passwd
		// would bypass the embedder's VFS sandbox entirely.
		p := uri.ToPath(path)
		if fileExists(filesys, p) {
			return uri.ToURI(p)
		}
		return ""
	}
	if filepath.IsAbs(path) {
		if fileExists(filesys, path) {
			return uri.ToURI(path)
		}
		return ""
	}
	// Relative path: resolve against the directory of the base URI.
	baseDir := uri.Dir(baseURI)
	if baseDir == "" {
		return ""
	}
	resolved := filepath.Join(baseDir, path)
	if fileExists(filesys, resolved) {
		return uri.ToURI(resolved)
	}
	return ""
}

func fileExists(filesys vfs.FileSystem, path string) bool {
	_, err := filesys.Stat(path)
	return err == nil
}

func toProtoRange(r parser.Range) protocol_3_16.Range {
	return protocol_3_16.Range{
		Start: protocol_3_16.Position{
			Line:      uint32(r.Start.Line),
			Character: uint32(r.Start.Character),
		},
		End: protocol_3_16.Position{
			Line:      uint32(r.End.Line),
			Character: uint32(r.End.Character),
		},
	}
}

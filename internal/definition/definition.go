// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

// Package definition provides go-to-definition for SecLang elements.
package definition

import (
	"os"
	"path/filepath"
	"strings"

	protocol_3_16 "github.com/tliron/glsp/protocol_3_16"

	"github.com/coraza-incubator/coraza-lsp/internal/parser"
)

// Resolve returns the definition location(s) for the element at the given position.
// Returns nil when no definition is available.
//
// Supported cases:
//  1. Cursor on a skipAfter: value → SecMarker in the same file
//  2. Cursor on an Include path → the included file URI
func Resolve(f *parser.File, line, char int, docURI string) []protocol_3_16.Location {
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
		uri := resolveIncludePath(n.Path, docURI)
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
func resolveIncludePath(path, baseURI string) string {
	if strings.HasPrefix(path, "file://") {
		return path
	}
	if filepath.IsAbs(path) {
		if fileExists(path) {
			return "file://" + path
		}
		return ""
	}
	// Relative path: resolve against the directory of the base URI.
	baseDir := uriDir(baseURI)
	if baseDir == "" {
		return ""
	}
	resolved := filepath.Join(baseDir, path)
	if fileExists(resolved) {
		return "file://" + resolved
	}
	return ""
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func uriDir(uri string) string {
	path := strings.TrimPrefix(uri, "file://")
	return filepath.Dir(path)
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

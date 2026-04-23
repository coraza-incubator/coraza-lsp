// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

// Package symbols extracts document and workspace symbols from SecLang ASTs.
package symbols

import (
	"fmt"

	protocol_3_16 "github.com/tliron/glsp/protocol_3_16"

	"github.com/coraza-incubator/coraza-lsp/internal/parser"
)

// DocumentSymbols returns the symbol tree for a single file.
// Rules are listed by their id action value; markers and includes are also included.
func DocumentSymbols(f *parser.File) []protocol_3_16.DocumentSymbol {
	var result []protocol_3_16.DocumentSymbol

	for _, node := range f.Nodes {
		switch n := node.(type) {
		case *parser.RuleNode:
			sym := ruleSymbol(n)
			if sym != nil {
				result = append(result, *sym)
			}
		case *parser.MarkerNode:
			sym := markerSymbol(n)
			result = append(result, sym)
		case *parser.IncludeNode:
			sym := includeSymbol(n)
			result = append(result, sym)
		}
	}

	return result
}

// WorkspaceSymbols returns symbols from all documents whose name/msg/tag matches query.
// query is a case-insensitive substring match.
func WorkspaceSymbols(query string, documents map[string]*parser.File) []protocol_3_16.SymbolInformation {
	var result []protocol_3_16.SymbolInformation
	for uri, f := range documents {
		for _, node := range f.Nodes {
			rule, ok := node.(*parser.RuleNode)
			if !ok {
				continue
			}
			label := ruleLabel(rule)
			if query == "" || containsIgnoreCase(label, query) {
				sym := ruleToSymbolInfo(rule, uri, label)
				result = append(result, sym)
			}
		}
	}
	return result
}

func ruleSymbol(rule *parser.RuleNode) *protocol_3_16.DocumentSymbol {
	label := ruleLabel(rule)
	kind := protocol_3_16.SymbolKindKey

	r := toProtoRange(rule.GetRange())
	sel := toProtoRange(rule.NameRange)
	deprecated := false

	return &protocol_3_16.DocumentSymbol{
		Name:           label,
		Kind:           kind,
		Range:          r,
		SelectionRange: sel,
		Deprecated:     &deprecated,
	}
}

func markerSymbol(m *parser.MarkerNode) protocol_3_16.DocumentSymbol {
	name := fmt.Sprintf("Marker: %s", m.MarkerID)
	r := toProtoRange(m.GetRange())
	deprecated := false
	return protocol_3_16.DocumentSymbol{
		Name:           name,
		Kind:           protocol_3_16.SymbolKindNamespace,
		Range:          r,
		SelectionRange: r,
		Deprecated:     &deprecated,
	}
}

func includeSymbol(inc *parser.IncludeNode) protocol_3_16.DocumentSymbol {
	name := fmt.Sprintf("Include: %s", inc.Path)
	r := toProtoRange(inc.GetRange())
	deprecated := false
	return protocol_3_16.DocumentSymbol{
		Name:           name,
		Kind:           protocol_3_16.SymbolKindFile,
		Range:          r,
		SelectionRange: r,
		Deprecated:     &deprecated,
	}
}

func ruleToSymbolInfo(rule *parser.RuleNode, uri, label string) protocol_3_16.SymbolInformation {
	deprecated := false
	return protocol_3_16.SymbolInformation{
		Name: label,
		Kind: protocol_3_16.SymbolKindKey,
		Location: protocol_3_16.Location{
			URI:   protocol_3_16.DocumentUri(uri),
			Range: toProtoRange(rule.GetRange()),
		},
		Deprecated: &deprecated,
	}
}

// ruleLabel builds a human-readable name for a rule, using its id if available.
func ruleLabel(rule *parser.RuleNode) string {
	idAction := rule.FindAction("id")
	msgAction := rule.FindAction("msg")

	directive := rule.Directive
	switch directive {
	case "secrule":
		directive = "SecRule"
	case "secaction":
		directive = "SecAction"
	case "secdefaultaction":
		directive = "SecDefaultAction"
	}

	if idAction != nil {
		if msgAction != nil && msgAction.Value != "" {
			return fmt.Sprintf("%s %s: %s", directive, idAction.Value, msgAction.Value)
		}
		return fmt.Sprintf("%s %s", directive, idAction.Value)
	}
	return directive
}

func containsIgnoreCase(s, substr string) bool {
	sLower := toLower(s)
	subLower := toLower(substr)
	return len(subLower) == 0 || contains(sLower, subLower)
}

func toLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

func contains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
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

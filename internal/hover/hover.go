// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

// Package hover provides hover documentation for SecLang elements.
package hover

import (
	"strings"

	protocol_3_16 "github.com/tliron/glsp/protocol_3_16"

	"github.com/coraza-incubator/coraza-lsp/internal/knowledge"
	"github.com/coraza-incubator/coraza-lsp/internal/lsppos"
	"github.com/coraza-incubator/coraza-lsp/internal/parser"
)

// Result is the hover content returned for a position.
type Result struct {
	Contents protocol_3_16.MarkupContent
	Range    *parser.Range
}

// Hover returns hover documentation for the given (line, char) position in the AST.
// source is the raw document text used as a fallback for multi-line action lists
// where per-action ranges are compressed to the opening-quote line.
// Returns nil when the cursor is not over a recognisable element.
//
// Performance: single AST walk followed by a single O(1) map lookup.
func Hover(f *parser.File, source string, line, char int) *Result {
	node := f.NodeAtPosition(line, char)
	if node == nil {
		return nil
	}

	switch n := node.(type) {
	case *parser.CommentNode:
		return nil

	case *parser.GenericDirectiveNode:
		// Hover over the directive name.
		if n.NameRange.ContainsPosition(line, char) {
			item := knowledge.Directive(n.Name)
			if item != nil {
				r := n.NameRange
				return buildResult(item, &r)
			}
		}

	case *parser.MarkerNode:
		if n.NameRange.ContainsPosition(line, char) {
			item := knowledge.Directive(n.Name)
			if item != nil {
				r := n.NameRange
				return buildResult(item, &r)
			}
		}

	case *parser.IncludeNode:
		if n.NameRange.ContainsPosition(line, char) {
			item := knowledge.Directive(n.Name)
			if item != nil {
				r := n.NameRange
				return buildResult(item, &r)
			}
		}

	case *parser.RuleNode:
		return hoverInRule(n, source, line, char)
	}

	return nil
}

// hoverInRule resolves hover within a SecRule/SecAction/SecDefaultAction node.
func hoverInRule(rule *parser.RuleNode, source string, line, char int) *Result {
	// Hover over directive name.
	if rule.NameRange.ContainsPosition(line, char) {
		item := knowledge.Directive(rule.Directive)
		if item != nil {
			r := rule.NameRange
			return buildResult(item, &r)
		}
	}

	// Hover over a variable.
	if rule.VariablesRange.ContainsPosition(line, char) {
		for i := range rule.Variables {
			v := &rule.Variables[i]
			if v.Range.ContainsPosition(line, char) {
				item := knowledge.Variable(v.Name)
				if item != nil {
					r := v.Range
					return buildResult(item, &r)
				}
			}
		}
	}

	// Macro expansion hover wins over the enclosing operator/action: %{COLLECTION...}
	// can appear inside an operator argument or an action value, and the macro's
	// variable doc is more specific than the operator/action doc around it.
	if source != "" {
		if item := macroVarAtPos(source, line, char); item != nil {
			return buildResult(item, nil)
		}
	}

	// Hover over the operator.
	if rule.Operator != nil && rule.Operator.Range.ContainsPosition(line, char) {
		// Check if hovering over operator name specifically.
		if rule.Operator.NameRange.ContainsPosition(line, char) {
			item := knowledge.Operator(rule.Operator.Name)
			if item != nil {
				r := rule.Operator.NameRange
				return buildResult(item, &r)
			}
		}
		// Fall through: hover anywhere in operator zone gives operator doc.
		item := knowledge.Operator(rule.Operator.Name)
		if item != nil {
			r := rule.OperatorRange
			return buildResult(item, &r)
		}
	}

	// Hover over an action.
	if rule.ActionsRange.ContainsPosition(line, char) {
		// Try exact per-action range first (works for single-line action lists).
		for i := range rule.Actions {
			a := &rule.Actions[i]
			if a.Range.ContainsPosition(line, char) {
				name := a.LowerName()
				// For a transformation action `t:NAME`, show the transformation doc
				// only when the cursor is on the value; on the `t` / `:` keyword
				// itself show the `t` action doc.
				if name == "t" && a.HasColon {
					valueStart := a.Range.Start.Character + 2 // past "t:"
					onValue := line == a.Range.Start.Line && char >= valueStart
					if onValue {
						if item := knowledge.Transformation(a.Value); item != nil {
							r := a.Range
							return buildResult(item, &r)
						}
					} else if item := knowledge.Action("t"); item != nil {
						r := a.Range
						return buildResult(item, &r)
					}
				}
				item := knowledge.Action(name)
				if item != nil {
					r := a.Range
					return buildResult(item, &r)
				}
			}
		}

		// Fallback for multi-line action lists: per-action ranges are compressed
		// to the opening-quote line, so range matching fails on continuation lines.
		// Extract the identifier word at the cursor from the raw source text and
		// look it up directly.
		if source != "" {
			word := wordAtPos(source, line, char)
			if word != "" {
				lower := strings.ToLower(word)
				// Transformation value (cursor is on the value after "t:").
				if item := knowledge.Transformation(lower); item != nil {
					return buildResult(item, nil)
				}
				// Action name.
				if item := knowledge.Action(lower); item != nil {
					return buildResult(item, nil)
				}
			}
		}
	}

	return nil
}

// macroVarAtPos returns the knowledge Item for the variable collection if the
// cursor is inside a %{COLLECTION...} macro expansion on the given source line.
// Returns nil when the cursor is not inside a macro.
func macroVarAtPos(source string, line, char int) *knowledge.Item {
	lines := strings.Split(source, "\n")
	if line >= len(lines) {
		return nil
	}
	// char arrives as a UTF-16 column; convert to a rune index for runes[].
	char = lsppos.UTF16ColumnToRune(lines[line], char)
	runes := []rune(lines[line])
	if char >= len(runes) {
		return nil
	}
	// Scan backward from cursor to find opening `{`.
	i := char
	for i >= 1 && runes[i] != '{' {
		i--
	}
	if i == 0 || runes[i-1] != '%' {
		return nil // not inside %{...}
	}
	// Scan forward from cursor to find closing `}`.
	j := char + 1
	for j < len(runes) && runes[j] != '}' {
		j++
	}
	if j >= len(runes) {
		return nil // unclosed macro
	}
	// Extract the collection name: the portion before the first `.` or `:`.
	content := string(runes[i+1 : j])
	if sep := strings.IndexAny(content, ".:"); sep >= 0 {
		content = content[:sep]
	}
	return knowledge.Variable(content)
}

// wordAtPos extracts the identifier word (letters, digits, underscore) at
// (line, char) from source. Returns "" when out of range or not on an identifier.
func wordAtPos(source string, line, char int) string {
	lines := strings.Split(source, "\n")
	if line >= len(lines) {
		return ""
	}
	// char arrives as a UTF-16 column; convert to a rune index for runes[].
	char = lsppos.UTF16ColumnToRune(lines[line], char)
	runes := []rune(lines[line])
	if char >= len(runes) {
		return ""
	}
	isIdent := func(r rune) bool {
		return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_'
	}
	if !isIdent(runes[char]) {
		return ""
	}
	start := char
	for start > 0 && isIdent(runes[start-1]) {
		start--
	}
	end := char + 1
	for end < len(runes) && isIdent(runes[end]) {
		end++
	}
	return string(runes[start:end])
}

// buildResult constructs a hover Result from a knowledge Item.
func buildResult(item *knowledge.Item, r *parser.Range) *Result {
	var sb strings.Builder
	sb.WriteString("## ")
	sb.WriteString(item.Name)
	sb.WriteString("\n\n")
	sb.WriteString(item.Description)
	if item.Syntax != "" {
		sb.WriteString("\n\n**Syntax:** `")
		sb.WriteString(item.Syntax)
		sb.WriteString("`")
	}
	if item.Example != "" {
		sb.WriteString("\n\n**Example:**\n```seclang\n")
		sb.WriteString(item.Example)
		sb.WriteString("\n```")
	}

	return &Result{
		Contents: protocol_3_16.MarkupContent{
			Kind:  protocol_3_16.MarkupKindMarkdown,
			Value: sb.String(),
		},
		Range: r,
	}
}

// ToProtocol converts the Result to the LSP Hover type.
func (res *Result) ToProtocol() *protocol_3_16.Hover {
	if res == nil {
		return nil
	}
	h := &protocol_3_16.Hover{
		Contents: res.Contents,
	}
	if res.Range != nil {
		pr := toProtoRange(*res.Range)
		h.Range = &pr
	}
	return h
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

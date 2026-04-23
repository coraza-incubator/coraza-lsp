// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

// Package codeactions provides quick-fix code actions for SecLang diagnostics.
package codeactions

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	protocol_3_16 "github.com/tliron/glsp/protocol_3_16"

	"github.com/coraza-incubator/coraza-lsp/internal/analysis"
	"github.com/coraza-incubator/coraza-lsp/internal/parser"
)

// CodeActionsForDiagnostics returns quick-fix code actions for diagnostics
// that overlap with the given range.
func CodeActionsForDiagnostics(
	diags []protocol_3_16.Diagnostic,
	f *parser.File,
	source string,
	reqRange protocol_3_16.Range,
) []protocol_3_16.CodeAction {
	var result []protocol_3_16.CodeAction

	for _, diag := range diags {
		// Only offer actions for diagnostics that overlap the requested range.
		if !rangesOverlap(diag.Range, reqRange) {
			continue
		}
		actions := actionsForDiagnostic(diag, f, source)
		result = append(result, actions...)
	}
	return result
}

// actionsForDiagnostic returns code actions for a single diagnostic.
func actionsForDiagnostic(diag protocol_3_16.Diagnostic, f *parser.File, source string) []protocol_3_16.CodeAction {
	if diag.Code == nil {
		return nil
	}
	code, ok := diag.Code.Value.(string)
	if !ok {
		return nil
	}

	line := int(diag.Range.Start.Line)
	node := f.NodeAtPosition(line, int(diag.Range.Start.Character))

	switch code {
	case analysis.CodeMissingID:
		return missingIDAction(diag, f, source, node)
	case analysis.CodeMissingPhase:
		return missingPhaseAction(diag, source, node)
	case analysis.CodeUnknownDirective:
		return deleteLineAction(diag, source)
	}
	return nil
}

// missingIDAction adds an id action to the rule.
func missingIDAction(diag protocol_3_16.Diagnostic, f *parser.File, source string, node parser.Node) []protocol_3_16.CodeAction {
	rule, ok := node.(*parser.RuleNode)
	if !ok {
		return nil
	}

	nextID := nextAvailableID(f)
	insertText := fmt.Sprintf("id:%d,", nextID)

	// Insert at the beginning of the action list.
	edit := insertAtStartOfActions(rule, source, insertText)
	if edit == nil {
		return nil
	}

	title := fmt.Sprintf("Add id:%d", nextID)
	return []protocol_3_16.CodeAction{
		{
			Title:       title,
			Kind:        kindPtr(protocol_3_16.CodeActionKindQuickFix),
			Diagnostics: []protocol_3_16.Diagnostic{diag},
			Edit: &protocol_3_16.WorkspaceEdit{
				Changes: map[string][]protocol_3_16.TextEdit{
					"": {*edit},
				},
			},
		},
	}
}

// missingPhaseAction adds a phase:2 action to the rule.
func missingPhaseAction(diag protocol_3_16.Diagnostic, source string, node parser.Node) []protocol_3_16.CodeAction {
	rule, ok := node.(*parser.RuleNode)
	if !ok {
		return nil
	}

	edit := insertAtStartOfActions(rule, source, "phase:2,")
	if edit == nil {
		return nil
	}

	return []protocol_3_16.CodeAction{
		{
			Title:       "Add phase:2",
			Kind:        kindPtr(protocol_3_16.CodeActionKindQuickFix),
			Diagnostics: []protocol_3_16.Diagnostic{diag},
			Edit: &protocol_3_16.WorkspaceEdit{
				Changes: map[string][]protocol_3_16.TextEdit{
					"": {*edit},
				},
			},
		},
	}
}

// deleteLineAction offers to remove the offending directive line.
func deleteLineAction(diag protocol_3_16.Diagnostic, source string) []protocol_3_16.CodeAction {
	lines := strings.Split(source, "\n")
	lineIdx := int(diag.Range.Start.Line)
	if lineIdx >= len(lines) {
		return nil
	}

	startLine := uint32(lineIdx)
	endLine := startLine + 1
	if int(endLine) >= len(lines) {
		endLine = startLine
	}

	return []protocol_3_16.CodeAction{
		{
			Title:       "Remove this line",
			Kind:        kindPtr(protocol_3_16.CodeActionKindQuickFix),
			Diagnostics: []protocol_3_16.Diagnostic{diag},
			Edit: &protocol_3_16.WorkspaceEdit{
				Changes: map[string][]protocol_3_16.TextEdit{
					"": {
						{
							Range: protocol_3_16.Range{
								Start: protocol_3_16.Position{Line: startLine, Character: 0},
								End:   protocol_3_16.Position{Line: endLine, Character: 0},
							},
							NewText: "",
						},
					},
				},
			},
		},
	}
}

// insertAtStartOfActions builds a TextEdit that inserts text at the beginning
// of the action list of the given rule.
func insertAtStartOfActions(rule *parser.RuleNode, source string, text string) *protocol_3_16.TextEdit {
	// Find the action list in the source line.
	lines := strings.Split(source, "\n")
	actLine := int(rule.ActionsRange.Start.Line)
	if actLine >= len(lines) {
		return nil
	}

	// The actions range start is the position of the opening " of the action list.
	// We want to insert after the opening " character.
	insertChar := rule.ActionsRange.Start.Character + 1 // after opening "
	if insertChar < 0 {
		insertChar = 0
	}

	pos := protocol_3_16.Position{
		Line:      uint32(actLine),
		Character: uint32(insertChar),
	}
	return &protocol_3_16.TextEdit{
		Range:   protocol_3_16.Range{Start: pos, End: pos},
		NewText: text,
	}
}

// nextAvailableID returns max(existing_ids) + 1, or 900001 if no rules have ids.
func nextAvailableID(f *parser.File) int {
	var ids []int
	for _, rule := range f.AllRules() {
		idAction := rule.FindAction("id")
		if idAction == nil {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(idAction.Value))
		if err == nil && n > 0 {
			ids = append(ids, n)
		}
	}
	if len(ids) == 0 {
		return 900001
	}
	sort.Ints(ids)
	return ids[len(ids)-1] + 1
}

func kindPtr(k protocol_3_16.CodeActionKind) *protocol_3_16.CodeActionKind {
	return &k
}

// rangesOverlap reports whether two LSP ranges overlap.
func rangesOverlap(a, b protocol_3_16.Range) bool {
	// a ends before b starts, or b ends before a starts.
	if a.End.Line < b.Start.Line {
		return false
	}
	if a.End.Line == b.Start.Line && a.End.Character < b.Start.Character {
		return false
	}
	if b.End.Line < a.Start.Line {
		return false
	}
	if b.End.Line == a.Start.Line && b.End.Character < a.Start.Character {
		return false
	}
	return true
}

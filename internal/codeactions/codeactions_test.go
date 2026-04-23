// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package codeactions

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	protocol_3_16 "github.com/tliron/glsp/protocol_3_16"

	"github.com/coraza-incubator/coraza-lsp/internal/analysis"
	"github.com/coraza-incubator/coraza-lsp/internal/parser"
)

func diagAt(code string, line uint32) protocol_3_16.Diagnostic {
	r := protocol_3_16.Range{
		Start: protocol_3_16.Position{Line: line, Character: 0},
		End:   protocol_3_16.Position{Line: line, Character: 10},
	}
	c := protocol_3_16.IntegerOrString{Value: code}
	return protocol_3_16.Diagnostic{Range: r, Code: &c}
}

func fullRange(source string) protocol_3_16.Range {
	return protocol_3_16.Range{
		Start: protocol_3_16.Position{Line: 0, Character: 0},
		End:   protocol_3_16.Position{Line: 9999, Character: 9999},
	}
}

// ---- missingIDAction -------------------------------------------------------

func TestMissingIDAction_InsertID(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx x" "phase:2,deny"`
	f := parser.Parse("file:///test.conf", src)
	diag := diagAt(analysis.CodeMissingID, 0)
	actions := CodeActionsForDiagnostics([]protocol_3_16.Diagnostic{diag}, f, src, fullRange(src))
	require.Len(t, actions, 1)
	assert.Contains(t, actions[0].Title, "Add id:")
	require.NotNil(t, actions[0].Edit)
	changes := actions[0].Edit.Changes[""]
	require.Len(t, changes, 1)
	assert.Contains(t, changes[0].NewText, "id:")
}

func TestMissingIDAction_UsesNextAvailableID(t *testing.T) {
	t.Parallel()
	// First rule has id:1001 — next should be 1002.
	src := "SecRule ARGS \"@rx x\" \"id:1001,phase:2,pass\"\nSecRule ARGS \"@rx y\" \"phase:2,deny\""
	f := parser.Parse("file:///test.conf", src)
	diag := diagAt(analysis.CodeMissingID, 1)
	actions := CodeActionsForDiagnostics([]protocol_3_16.Diagnostic{diag}, f, src, fullRange(src))
	require.Len(t, actions, 1)
	assert.Contains(t, actions[0].Title, "1002")
}

func TestMissingIDAction_DefaultsTo900001WhenNoIDs(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx x" "phase:2,deny"`
	f := parser.Parse("file:///test.conf", src)
	diag := diagAt(analysis.CodeMissingID, 0)
	actions := CodeActionsForDiagnostics([]protocol_3_16.Diagnostic{diag}, f, src, fullRange(src))
	require.Len(t, actions, 1)
	assert.Contains(t, actions[0].Title, "900001")
}

func TestMissingIDAction_NotARuleNode(t *testing.T) {
	t.Parallel()
	src := `SecRuleEngine On`
	f := parser.Parse("file:///test.conf", src)
	diag := diagAt(analysis.CodeMissingID, 0)
	actions := CodeActionsForDiagnostics([]protocol_3_16.Diagnostic{diag}, f, src, fullRange(src))
	// SecRuleEngine is a GenericDirective node, not a RuleNode — no action.
	assert.Empty(t, actions)
}

// ---- missingPhaseAction ----------------------------------------------------

func TestMissingPhaseAction_InsertsPhase2(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx x" "id:1001,deny"`
	f := parser.Parse("file:///test.conf", src)
	diag := diagAt(analysis.CodeMissingPhase, 0)
	actions := CodeActionsForDiagnostics([]protocol_3_16.Diagnostic{diag}, f, src, fullRange(src))
	require.Len(t, actions, 1)
	assert.Equal(t, "Add phase:2", actions[0].Title)
	changes := actions[0].Edit.Changes[""]
	require.Len(t, changes, 1)
	assert.Equal(t, "phase:2,", changes[0].NewText)
}

func TestMissingPhaseAction_NotARuleNode(t *testing.T) {
	t.Parallel()
	src := `SecRuleEngine On`
	f := parser.Parse("file:///test.conf", src)
	diag := diagAt(analysis.CodeMissingPhase, 0)
	actions := CodeActionsForDiagnostics([]protocol_3_16.Diagnostic{diag}, f, src, fullRange(src))
	assert.Empty(t, actions)
}

// ---- deleteLineAction ------------------------------------------------------

func TestDeleteLineAction_RemovesLine(t *testing.T) {
	t.Parallel()
	src := "UnknownDirective foo\nSecRuleEngine On"
	f := parser.Parse("file:///test.conf", src)
	diag := diagAt(analysis.CodeUnknownDirective, 0)
	actions := CodeActionsForDiagnostics([]protocol_3_16.Diagnostic{diag}, f, src, fullRange(src))
	require.Len(t, actions, 1)
	assert.Equal(t, "Remove this line", actions[0].Title)
	changes := actions[0].Edit.Changes[""]
	require.Len(t, changes, 1)
	edit := changes[0]
	// Edit should span from line 0 char 0 to line 1 char 0 (delete full line).
	assert.Equal(t, uint32(0), edit.Range.Start.Line)
	assert.Equal(t, uint32(0), edit.Range.Start.Character)
	assert.Equal(t, uint32(1), edit.Range.End.Line)
	assert.Equal(t, uint32(0), edit.Range.End.Character)
	assert.Equal(t, "", edit.NewText)
}

func TestDeleteLineAction_LastLine(t *testing.T) {
	t.Parallel()
	src := "UnknownDirective foo"
	f := parser.Parse("file:///test.conf", src)
	diag := diagAt(analysis.CodeUnknownDirective, 0)
	actions := CodeActionsForDiagnostics([]protocol_3_16.Diagnostic{diag}, f, src, fullRange(src))
	require.Len(t, actions, 1)
	// When the line is the last one, start == end (no next line to anchor to).
	changes := actions[0].Edit.Changes[""]
	require.Len(t, changes, 1)
	edit := changes[0]
	assert.Equal(t, uint32(0), edit.Range.Start.Line)
	assert.Equal(t, uint32(0), edit.Range.End.Line)
}

func TestDeleteLineAction_OutOfRangeLineIndex(t *testing.T) {
	t.Parallel()
	src := "SecRuleEngine On"
	f := parser.Parse("file:///test.conf", src)
	// Fabricate a diagnostic on a line that doesn't exist.
	diag := diagAt(analysis.CodeUnknownDirective, 99)
	actions := CodeActionsForDiagnostics([]protocol_3_16.Diagnostic{diag}, f, src, fullRange(src))
	// The diagnostic range (line 99) doesn't overlap with the request range unless we widen it,
	// but even if it does, deleteLineAction should return nil for out-of-bounds index.
	// Either way: no crash.
	_ = actions
}

// ---- rangesOverlap ---------------------------------------------------------

func TestRangesOverlap_Overlapping(t *testing.T) {
	t.Parallel()
	a := protocol_3_16.Range{
		Start: protocol_3_16.Position{Line: 0, Character: 0},
		End:   protocol_3_16.Position{Line: 2, Character: 0},
	}
	b := protocol_3_16.Range{
		Start: protocol_3_16.Position{Line: 1, Character: 0},
		End:   protocol_3_16.Position{Line: 3, Character: 0},
	}
	assert.True(t, rangesOverlap(a, b))
	assert.True(t, rangesOverlap(b, a))
}

func TestRangesOverlap_Adjacent(t *testing.T) {
	t.Parallel()
	a := protocol_3_16.Range{
		Start: protocol_3_16.Position{Line: 0, Character: 0},
		End:   protocol_3_16.Position{Line: 1, Character: 0},
	}
	b := protocol_3_16.Range{
		Start: protocol_3_16.Position{Line: 1, Character: 0},
		End:   protocol_3_16.Position{Line: 2, Character: 0},
	}
	// a ends exactly where b starts — counts as overlap (touching).
	assert.True(t, rangesOverlap(a, b))
}

func TestRangesOverlap_NonOverlapping(t *testing.T) {
	t.Parallel()
	a := protocol_3_16.Range{
		Start: protocol_3_16.Position{Line: 0, Character: 0},
		End:   protocol_3_16.Position{Line: 0, Character: 5},
	}
	b := protocol_3_16.Range{
		Start: protocol_3_16.Position{Line: 1, Character: 0},
		End:   protocol_3_16.Position{Line: 1, Character: 5},
	}
	assert.False(t, rangesOverlap(a, b))
}

func TestRangesOverlap_SameLine_CharGap(t *testing.T) {
	t.Parallel()
	a := protocol_3_16.Range{
		Start: protocol_3_16.Position{Line: 0, Character: 0},
		End:   protocol_3_16.Position{Line: 0, Character: 3},
	}
	b := protocol_3_16.Range{
		Start: protocol_3_16.Position{Line: 0, Character: 5},
		End:   protocol_3_16.Position{Line: 0, Character: 10},
	}
	assert.False(t, rangesOverlap(a, b))
}

// ---- nextAvailableID -------------------------------------------------------

func TestNextAvailableID_NoRules(t *testing.T) {
	t.Parallel()
	f := parser.Parse("file:///test.conf", "# comment")
	assert.Equal(t, 900001, nextAvailableID(f))
}

func TestNextAvailableID_SingleRule(t *testing.T) {
	t.Parallel()
	f := parser.Parse("file:///test.conf", `SecRule ARGS "@rx x" "id:500,phase:2,deny"`)
	assert.Equal(t, 501, nextAvailableID(f))
}

func TestNextAvailableID_MultipleRules(t *testing.T) {
	t.Parallel()
	src := "SecRule ARGS \"@rx x\" \"id:100,phase:2,deny\"\nSecRule ARGS \"@rx y\" \"id:200,phase:2,deny\""
	f := parser.Parse("file:///test.conf", src)
	assert.Equal(t, 201, nextAvailableID(f))
}

// ---- CodeActionsForDiagnostics: no matching range --------------------------

func TestCodeActionsForDiagnostics_NoOverlap(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx x" "phase:2,deny"`
	f := parser.Parse("file:///test.conf", src)
	diag := diagAt(analysis.CodeMissingID, 5) // line 5 — not in the source
	// Request range is only line 0.
	reqRange := protocol_3_16.Range{
		Start: protocol_3_16.Position{Line: 0, Character: 0},
		End:   protocol_3_16.Position{Line: 0, Character: 100},
	}
	actions := CodeActionsForDiagnostics([]protocol_3_16.Diagnostic{diag}, f, src, reqRange)
	assert.Empty(t, actions)
}

func TestCodeActionsForDiagnostics_NilCode(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx x" "phase:2,deny"`
	f := parser.Parse("file:///test.conf", src)
	diag := protocol_3_16.Diagnostic{
		Range: protocol_3_16.Range{
			Start: protocol_3_16.Position{Line: 0, Character: 0},
			End:   protocol_3_16.Position{Line: 0, Character: 10},
		},
		Code: nil, // no code
	}
	actions := CodeActionsForDiagnostics([]protocol_3_16.Diagnostic{diag}, f, src, fullRange(src))
	assert.Empty(t, actions)
}

func TestCodeActionsForDiagnostics_UnknownCode(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx x" "phase:2,deny"`
	f := parser.Parse("file:///test.conf", src)
	diag := diagAt("some-unknown-code", 0)
	actions := CodeActionsForDiagnostics([]protocol_3_16.Diagnostic{diag}, f, src, fullRange(src))
	assert.Empty(t, actions)
}

func TestCodeActionsForDiagnostics_EmptyDiags(t *testing.T) {
	t.Parallel()
	src := `SecRuleEngine On`
	f := parser.Parse("file:///test.conf", src)
	actions := CodeActionsForDiagnostics(nil, f, src, fullRange(src))
	assert.Empty(t, actions)
}

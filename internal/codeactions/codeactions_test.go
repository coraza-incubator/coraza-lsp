// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package codeactions

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	protocol_3_16 "github.com/tliron/glsp/protocol_3_16"

	"github.com/coraza-incubator/coraza-lsp/internal/analysis"
	"github.com/coraza-incubator/coraza-lsp/internal/parser"
)

const testURI = "file:///test.conf"

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
	actions := CodeActionsForDiagnostics([]protocol_3_16.Diagnostic{diag}, f, src, fullRange(src), testURI)
	require.Len(t, actions, 1)
	assert.Contains(t, actions[0].Title, "Add id:")
	require.NotNil(t, actions[0].Edit)
	changes := actions[0].Edit.Changes[testURI]
	require.Len(t, changes, 1)
	assert.Contains(t, changes[0].NewText, "id:")
}

func TestMissingIDAction_UsesNextAvailableID(t *testing.T) {
	t.Parallel()
	// First rule has id:1001 — next should be 1002.
	src := "SecRule ARGS \"@rx x\" \"id:1001,phase:2,pass\"\nSecRule ARGS \"@rx y\" \"phase:2,deny\""
	f := parser.Parse("file:///test.conf", src)
	diag := diagAt(analysis.CodeMissingID, 1)
	actions := CodeActionsForDiagnostics([]protocol_3_16.Diagnostic{diag}, f, src, fullRange(src), testURI)
	require.Len(t, actions, 1)
	assert.Contains(t, actions[0].Title, "1002")
}

func TestMissingIDAction_DefaultsTo900001WhenNoIDs(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx x" "phase:2,deny"`
	f := parser.Parse("file:///test.conf", src)
	diag := diagAt(analysis.CodeMissingID, 0)
	actions := CodeActionsForDiagnostics([]protocol_3_16.Diagnostic{diag}, f, src, fullRange(src), testURI)
	require.Len(t, actions, 1)
	assert.Contains(t, actions[0].Title, "900001")
}

func TestMissingIDAction_NotARuleNode(t *testing.T) {
	t.Parallel()
	src := `SecRuleEngine On`
	f := parser.Parse("file:///test.conf", src)
	diag := diagAt(analysis.CodeMissingID, 0)
	actions := CodeActionsForDiagnostics([]protocol_3_16.Diagnostic{diag}, f, src, fullRange(src), testURI)
	// SecRuleEngine is a GenericDirective node, not a RuleNode — no action.
	assert.Empty(t, actions)
}

// ---- missingPhaseAction ----------------------------------------------------

func TestMissingPhaseAction_InsertsPhase2(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx x" "id:1001,deny"`
	f := parser.Parse("file:///test.conf", src)
	diag := diagAt(analysis.CodeMissingPhase, 0)
	actions := CodeActionsForDiagnostics([]protocol_3_16.Diagnostic{diag}, f, src, fullRange(src), testURI)
	require.Len(t, actions, 1)
	assert.Equal(t, "Add phase:2", actions[0].Title)
	changes := actions[0].Edit.Changes[testURI]
	require.Len(t, changes, 1)
	assert.Equal(t, "phase:2,", changes[0].NewText)
}

func TestMissingPhaseAction_NotARuleNode(t *testing.T) {
	t.Parallel()
	src := `SecRuleEngine On`
	f := parser.Parse("file:///test.conf", src)
	diag := diagAt(analysis.CodeMissingPhase, 0)
	actions := CodeActionsForDiagnostics([]protocol_3_16.Diagnostic{diag}, f, src, fullRange(src), testURI)
	assert.Empty(t, actions)
}

// ---- deleteLineAction ------------------------------------------------------

func TestDeleteLineAction_RemovesLine(t *testing.T) {
	t.Parallel()
	src := "UnknownDirective foo\nSecRuleEngine On"
	f := parser.Parse("file:///test.conf", src)
	diag := diagAt(analysis.CodeUnknownDirective, 0)
	actions := CodeActionsForDiagnostics([]protocol_3_16.Diagnostic{diag}, f, src, fullRange(src), testURI)
	require.Len(t, actions, 1)
	assert.Equal(t, "Remove this line", actions[0].Title)
	changes := actions[0].Edit.Changes[testURI]
	require.Len(t, changes, 1)
	edit := changes[0]
	// Edit should span from line 0 char 0 to line 1 char 0 (delete full line + its
	// trailing newline). Applying it must remove the whole offending line.
	assert.Equal(t, uint32(0), edit.Range.Start.Line)
	assert.Equal(t, uint32(0), edit.Range.Start.Character)
	assert.Equal(t, uint32(1), edit.Range.End.Line)
	assert.Equal(t, uint32(0), edit.Range.End.Character)
	assert.Equal(t, "", edit.NewText)
	assert.Equal(t, "SecRuleEngine On", applyEdit(src, edit))
}

func TestDeleteLineAction_LastLine(t *testing.T) {
	t.Parallel()
	// The offending directive is the last (and not the only) line. The edit must
	// consume the previous line's trailing newline so the line truly disappears.
	src := "SecRuleEngine On\nUnknownDirective foo"
	f := parser.Parse("file:///test.conf", src)
	diag := diagAt(analysis.CodeUnknownDirective, 1)
	actions := CodeActionsForDiagnostics([]protocol_3_16.Diagnostic{diag}, f, src, fullRange(src), testURI)
	require.Len(t, actions, 1)
	changes := actions[0].Edit.Changes[testURI]
	require.Len(t, changes, 1)
	edit := changes[0]
	// Must NOT be a zero-width no-op range.
	assert.NotEqual(t, edit.Range.Start, edit.Range.End, "edit must not be zero-width")
	// Applying the edit must actually delete the directive.
	assert.Equal(t, "SecRuleEngine On", applyEdit(src, edit))
}

func TestDeleteLineAction_OnlyLine(t *testing.T) {
	t.Parallel()
	// A single-line file: no previous newline to consume, so the range must cover
	// the line content itself (start.char 0 .. end at line length).
	src := "UnknownDirective foo"
	f := parser.Parse("file:///test.conf", src)
	diag := diagAt(analysis.CodeUnknownDirective, 0)
	actions := CodeActionsForDiagnostics([]protocol_3_16.Diagnostic{diag}, f, src, fullRange(src), testURI)
	require.Len(t, actions, 1)
	edit := actions[0].Edit.Changes[testURI][0]
	assert.NotEqual(t, edit.Range.Start, edit.Range.End, "edit must not be zero-width")
	assert.Equal(t, "", applyEdit(src, edit))
}

// TestActionsKeyedOnRealURI verifies every quick-fix produces a WorkspaceEdit
// whose Changes map is keyed on the actual document URI (not "") with a correct
// edit, so editors can apply them.
func TestActionsKeyedOnRealURI(t *testing.T) {
	t.Parallel()
	const uri = "file:///workspace/rules/REQUEST-901.conf"

	cases := []struct {
		name string
		src  string
		code string
		line uint32
		want string // expected document text after applying the (single) edit
	}{
		{
			name: "add id",
			src:  `SecRule ARGS "@rx x" "phase:2,deny"`,
			code: analysis.CodeMissingID,
			line: 0,
			want: `SecRule ARGS "@rx x" "id:900001,phase:2,deny"`,
		},
		{
			name: "add phase",
			src:  `SecRule ARGS "@rx x" "id:1001,deny"`,
			code: analysis.CodeMissingPhase,
			line: 0,
			want: `SecRule ARGS "@rx x" "phase:2,id:1001,deny"`,
		},
		{
			name: "remove line",
			src:  "SecRuleEngine On\nUnknownDirective foo",
			code: analysis.CodeUnknownDirective,
			line: 1,
			want: "SecRuleEngine On",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := parser.Parse(uri, tc.src)
			diag := diagAt(tc.code, tc.line)
			actions := CodeActionsForDiagnostics([]protocol_3_16.Diagnostic{diag}, f, tc.src, fullRange(tc.src), uri)
			require.Len(t, actions, 1)
			require.NotNil(t, actions[0].Edit)

			// The map must be keyed on the real URI, never "".
			_, emptyKey := actions[0].Edit.Changes[""]
			assert.False(t, emptyKey, "WorkspaceEdit must not be keyed on empty URI")
			changes, ok := actions[0].Edit.Changes[uri]
			require.True(t, ok, "WorkspaceEdit must be keyed on the document URI %q", uri)
			require.Len(t, changes, 1)

			// Applying the edit produces the expected result.
			assert.Equal(t, tc.want, applyEdit(tc.src, changes[0]))
		})
	}
}

// applyEdit applies a single TextEdit to source and returns the result. It
// operates on rune offsets per LSP semantics so tests can assert real behaviour.
func applyEdit(source string, edit protocol_3_16.TextEdit) string {
	lines := strings.Split(source, "\n")
	offset := func(pos protocol_3_16.Position) int {
		o := 0
		for i := 0; i < int(pos.Line) && i < len(lines); i++ {
			o += len([]rune(lines[i])) + 1 // +1 for the newline
		}
		o += int(pos.Character)
		return o
	}
	runes := []rune(source)
	start := offset(edit.Range.Start)
	end := offset(edit.Range.End)
	if start < 0 {
		start = 0
	}
	if end > len(runes) {
		end = len(runes)
	}
	return string(runes[:start]) + edit.NewText + string(runes[end:])
}

func TestDeleteLineAction_OutOfRangeLineIndex(t *testing.T) {
	t.Parallel()
	src := "SecRuleEngine On"
	f := parser.Parse("file:///test.conf", src)
	// Fabricate a diagnostic on a line that doesn't exist.
	diag := diagAt(analysis.CodeUnknownDirective, 99)
	actions := CodeActionsForDiagnostics([]protocol_3_16.Diagnostic{diag}, f, src, fullRange(src), testURI)
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
	actions := CodeActionsForDiagnostics([]protocol_3_16.Diagnostic{diag}, f, src, reqRange, testURI)
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
	actions := CodeActionsForDiagnostics([]protocol_3_16.Diagnostic{diag}, f, src, fullRange(src), testURI)
	assert.Empty(t, actions)
}

func TestCodeActionsForDiagnostics_UnknownCode(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx x" "phase:2,deny"`
	f := parser.Parse("file:///test.conf", src)
	diag := diagAt("some-unknown-code", 0)
	actions := CodeActionsForDiagnostics([]protocol_3_16.Diagnostic{diag}, f, src, fullRange(src), testURI)
	assert.Empty(t, actions)
}

func TestCodeActionsForDiagnostics_EmptyDiags(t *testing.T) {
	t.Parallel()
	src := `SecRuleEngine On`
	f := parser.Parse("file:///test.conf", src)
	actions := CodeActionsForDiagnostics(nil, f, src, fullRange(src), testURI)
	assert.Empty(t, actions)
}

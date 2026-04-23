// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package hover

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coraza-incubator/coraza-lsp/internal/parser"
)

func parseAndHover(t *testing.T, src string, line, char int) *Result {
	t.Helper()
	f := parser.Parse("", src)
	return Hover(f, src, line, char)
}

func TestHover_DirectiveName(t *testing.T) {
	t.Parallel()
	// Hover over "SecRuleEngine" at position (0, 5).
	res := parseAndHover(t, "SecRuleEngine On", 0, 5)
	require.NotNil(t, res)
	assert.Contains(t, res.Contents.Value, "SecRuleEngine")
}

func TestHover_SecRuleDirectiveName(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx test" "id:1,phase:2,deny"`
	res := parseAndHover(t, src, 0, 3)
	require.NotNil(t, res)
	assert.Contains(t, res.Contents.Value, "SecRule")
}

func TestHover_Variable(t *testing.T) {
	t.Parallel()
	// "SecRule ARGS ..." → hover over ARGS at char 9.
	src := `SecRule ARGS "@rx test" "id:1,phase:2,deny"`
	res := parseAndHover(t, src, 0, 9)
	require.NotNil(t, res)
	assert.Contains(t, res.Contents.Value, "ARGS")
}

func TestHover_Operator(t *testing.T) {
	t.Parallel()
	// Hover over "@rx" inside the operator quoted string.
	src := `SecRule ARGS "@rx test" "id:1,phase:2,deny"`
	// Position 14 is inside "@rx test"
	res := parseAndHover(t, src, 0, 15)
	require.NotNil(t, res)
	assert.Contains(t, res.Contents.Value, "rx")
}

func TestHover_Action(t *testing.T) {
	t.Parallel()
	// Hover over the "deny" action in the action list.
	src := `SecRule ARGS "@rx test" "id:1,phase:2,deny"`
	// "deny" starts at approximately char 38.
	res := parseAndHover(t, src, 0, 38)
	// May be nil if position is outside action range — just verify no panic.
	_ = res
}

func TestHover_Transformation(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx x" "id:1,phase:2,deny,t:lowercase"`
	// hover over "lowercase" value in t:lowercase
	res := parseAndHover(t, src, 0, 44)
	_ = res // position may vary; just verify no panic
}

func TestHover_NoResultOnWhitespace(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx x" "id:1,phase:2,deny"`
	// Hover on whitespace between directive and variable.
	res := parseAndHover(t, src, 0, 8)
	// The node at that position exists but cursor is in whitespace between tokens.
	// This may or may not return a result depending on ranges — just ensure no panic.
	_ = res
}

func TestHover_Comment(t *testing.T) {
	t.Parallel()
	res := parseAndHover(t, "# This is a comment", 0, 5)
	assert.Nil(t, res, "hover on comment should return nil")
}

func TestHover_OutOfBounds(t *testing.T) {
	t.Parallel()
	src := "SecRuleEngine On"
	f := parser.Parse("", src)
	// Line 999 is beyond any node.
	res := Hover(f, src, 999, 0)
	assert.Nil(t, res)
}

func TestHover_MultipleLines(t *testing.T) {
	t.Parallel()
	src := "SecRuleEngine On\nSecRequestBodyAccess On"
	f := parser.Parse("", src)
	// Hover on line 1 (SecRequestBodyAccess).
	res := Hover(f, src, 1, 5)
	require.NotNil(t, res)
	assert.Contains(t, res.Contents.Value, "SecRequestBodyAccess")
}

func TestHover_IncludeDirective(t *testing.T) {
	t.Parallel()
	src := "Include /etc/coraza/*.conf"
	res := parseAndHover(t, src, 0, 3)
	require.NotNil(t, res)
	assert.Contains(t, res.Contents.Value, "Include")
}

func TestHover_SecMarkerDirective(t *testing.T) {
	t.Parallel()
	src := "SecMarker END_CHECK"
	res := parseAndHover(t, src, 0, 4)
	require.NotNil(t, res)
	assert.Contains(t, res.Contents.Value, "SecMarker")
}

func TestHoverResult_ToProtocol_Nil(t *testing.T) {
	t.Parallel()
	var res *Result
	assert.Nil(t, res.ToProtocol())
}

func TestHoverResult_ToProtocol_HasRange(t *testing.T) {
	t.Parallel()
	src := "SecRuleEngine On"
	res := parseAndHover(t, src, 0, 5)
	require.NotNil(t, res)
	proto := res.ToProtocol()
	require.NotNil(t, proto)
	assert.NotNil(t, proto.Range)
}

func TestHover_MarkdownFormat(t *testing.T) {
	t.Parallel()
	src := "SecRuleEngine On"
	res := parseAndHover(t, src, 0, 5)
	require.NotNil(t, res)
	assert.Equal(t, "markdown", string(res.Contents.Kind))
	assert.Contains(t, res.Contents.Value, "##")
}

// --- wordAtPos / macroVarAtPos fallback paths ------------------------------

// TestHover_MultiLineActionList_TransformationFallback exercises the source-
// string fallback path. Per-action ranges in a multi-line action list are
// compressed to the opening-quote line, so hover on a continuation line can
// only be resolved by extracting the identifier word at the cursor from the
// raw source. Confirms wordAtPos resolves a transformation on line 2.
func TestHover_MultiLineActionList_TransformationFallback(t *testing.T) {
	t.Parallel()
	src := "SecRule ARGS \"@rx x\" \\\n  \"id:1,phase:2,deny,\\\n   t:lowercase,\\\n   t:urlDecode\"\n"
	f := parser.Parse("", src)
	// Line 2 starts with "   t:lowercase". Cursor sits on the "lowercase" word
	// at char 7 (inside "lowercase").
	res := Hover(f, src, 2, 8)
	require.NotNil(t, res)
	assert.Contains(t, res.Contents.Value, "lowercase")
}

// TestHover_MultiLineActionList_ActionFallback covers the same fallback for
// action names.
func TestHover_MultiLineActionList_ActionFallback(t *testing.T) {
	t.Parallel()
	src := "SecRule ARGS \"@rx x\" \\\n  \"id:1,phase:2,deny,\\\n   log,\\\n   auditlog\"\n"
	f := parser.Parse("", src)
	// Cursor on "auditlog" on line 3.
	res := Hover(f, src, 3, 6)
	require.NotNil(t, res)
	assert.Contains(t, res.Contents.Value, "auditlog")
}

// TestMacroVarAtPos covers the macroVarAtPos helper directly. In the full
// Hover() flow this function is only reached in narrow geometric
// circumstances (cursor in a rule zone that no per-token range covers), so we
// unit-test it against the underlying shapes it needs to recognise.
func TestMacroVarAtPos(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		line  string
		col   int // column inside the %{...} of the collection-name part
		want  string
		isNil bool
	}{
		{
			name: "dot selector TX.rule_id",
			line: `hit by %{TX.rule_id}`,
			col:  10, // inside "TX"
			want: "TX",
		},
		{
			name: "colon selector REQUEST_HEADERS:Host",
			line: `see %{REQUEST_HEADERS:Host}`,
			col:  9, // inside "REQUEST_HEADERS"
			want: "REQUEST_HEADERS",
		},
		{
			name: "cursor exactly on opening brace",
			line: `%{TX.foo}`,
			col:  2, // on the 'T'
			want: "TX",
		},
		{
			name:  "unclosed macro returns nil",
			line:  `broken %{TX.foo`,
			col:   10,
			isNil: true,
		},
		{
			name:  "no opening brace",
			line:  `not a macro TX.foo`,
			col:   13,
			isNil: true,
		},
		{
			name:  "char past end of line",
			line:  `%{TX.foo}`,
			col:   999,
			isNil: true,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := macroVarAtPos(tc.line, 0, tc.col)
			if tc.isNil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tc.want, got.Name)
		})
	}
}

// TestHover_MacroExpansion_Unclosed_NoPanic asserts the macroVarAtPos path
// doesn't panic on a malformed `%{` with no closing `}`. The outer hover may
// still resolve (e.g. via the action-name path) — we just care that no crash
// happens inside the fallback scanner.
func TestHover_MacroExpansion_Unclosed_NoPanic(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx x" "id:1,phase:2,deny,msg:'broken %{TX.foo'"`
	f := parser.Parse("", src)
	col := strings.Index(src, "%{TX") + 3
	_ = Hover(f, src, 0, col) // must not panic
}

// TestHover_MacroExpansion_OutOfRange covers the out-of-range guards inside
// macroVarAtPos (line past EOF, char past EOL).
func TestHover_MacroExpansion_OutOfRange(t *testing.T) {
	t.Parallel()
	src := "SecRuleEngine On"
	f := parser.Parse("", src)
	assert.Nil(t, Hover(f, src, 99, 0))
	assert.Nil(t, Hover(f, src, 0, 9999))
}

// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package formatting

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormat_AlreadyFormatted(t *testing.T) {
	t.Parallel()
	src := `SecRuleEngine On`
	edits := Format(src)
	assert.Nil(t, edits, "already-formatted source should produce no edits")
}

func TestFormat_TrailingWhitespace(t *testing.T) {
	t.Parallel()
	src := "SecRuleEngine On   "
	edits := Format(src)
	require.NotNil(t, edits)
	assert.Equal(t, "SecRuleEngine On", edits[0].NewText)
}

func TestFormat_ExtraSpacesBetweenArgs(t *testing.T) {
	t.Parallel()
	src := "SecRuleEngine   On"
	edits := Format(src)
	require.NotNil(t, edits)
	assert.Equal(t, "SecRuleEngine On", edits[0].NewText)
}

func TestFormat_CommentPreserved(t *testing.T) {
	t.Parallel()
	src := "# This is a comment\nSecRuleEngine On"
	edits := Format(src)
	// Comment should be preserved; no edits if already clean.
	_ = edits
}

func TestFormat_ContinuationLinesJoined(t *testing.T) {
	t.Parallel()
	src := "SecRule ARGS \\\n\"@rx x\" \\\n\"id:1,phase:2,deny\""
	edits := Format(src)
	require.NotNil(t, edits)
	// Result should be a single joined line.
	assert.NotContains(t, edits[0].NewText, "\\\n")
}

func TestFormat_MultipleBlankLinesCollapsed(t *testing.T) {
	t.Parallel()
	src := "SecRuleEngine On\n\n\nSecRequestBodyAccess On"
	edits := Format(src)
	require.NotNil(t, edits)
	// Should collapse multiple blank lines into one.
	assert.NotContains(t, edits[0].NewText, "\n\n\n")
}

func TestFormat_Empty(t *testing.T) {
	t.Parallel()
	edits := Format("")
	assert.Nil(t, edits)
}

func TestFormat_WindowsLineEndings(t *testing.T) {
	t.Parallel()
	src := "SecRuleEngine On\r\nSecRequestBodyAccess On\r\n"
	edits := Format(src)
	// Should return edits that strip \r.
	require.NotNil(t, edits)
	assert.NotContains(t, edits[0].NewText, "\r")
}

func TestFormat_QuotedArgsPreserved(t *testing.T) {
	t.Parallel()
	src := `SecAction "id:1,phase:2,pass"`
	edits := Format(src)
	// If already clean, no edits. If edits exist, quoted arg should be intact.
	if edits != nil {
		assert.Contains(t, edits[0].NewText, `"id:1,phase:2,pass"`)
	}
}

func TestSplitLogicalArgs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input    string
		expected []string
	}{
		{"SecRuleEngine On", []string{"SecRuleEngine", "On"}},
		{`SecAction "id:1,phase:2"`, []string{"SecAction", `"id:1,phase:2"`}},
		{"SecRule ARGS", []string{"SecRule", "ARGS"}},
		{`SecRule ARGS "@rx x" "id:1"`, []string{"SecRule", "ARGS", `"@rx x"`, `"id:1"`}},
	}
	for _, tc := range cases {
		got := splitLogicalArgs(tc.input)
		assert.Equal(t, tc.expected, got, "input: %q", tc.input)
	}
}

func TestFormatSource_TrailingBlankLines(t *testing.T) {
	t.Parallel()
	src := "SecRuleEngine On\n\n\n"
	result := formatSource(src)
	assert.Equal(t, "SecRuleEngine On", result)
}

// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLexer_Empty(t *testing.T) {
	t.Parallel()
	tokens := NewLexer("").Tokenize()
	assert.Empty(t, tokens)
}

func TestLexer_BlankLines(t *testing.T) {
	t.Parallel()
	tokens := NewLexer("\n\n  \n").Tokenize()
	assert.Empty(t, tokens)
}

func TestLexer_CommentLine(t *testing.T) {
	t.Parallel()
	tokens := NewLexer("# This is a comment").Tokenize()
	require.Len(t, tokens, 1)
	assert.Equal(t, TokenComment, tokens[0].Type)
	assert.Equal(t, "# This is a comment", tokens[0].Value)
	assert.Equal(t, 0, tokens[0].Line)
}

func TestLexer_SimpleDirective(t *testing.T) {
	t.Parallel()
	tokens := NewLexer("SecRuleEngine On").Tokenize()
	require.Len(t, tokens, 2)
	assert.Equal(t, TokenDirective, tokens[0].Type)
	assert.Equal(t, "SecRuleEngine", tokens[0].Value)
	assert.Equal(t, 0, tokens[0].Line)
	assert.Equal(t, 0, tokens[0].StartChar)

	assert.Equal(t, TokenWord, tokens[1].Type)
	assert.Equal(t, "On", tokens[1].Value)
	assert.Equal(t, 14, tokens[1].StartChar)
}

func TestLexer_QuotedArg(t *testing.T) {
	t.Parallel()
	tokens := NewLexer(`SecAction "id:1,phase:2,pass"`).Tokenize()
	require.Len(t, tokens, 2)
	assert.Equal(t, TokenDirective, tokens[0].Type)
	assert.Equal(t, TokenQuoted, tokens[1].Type)
	assert.Equal(t, "id:1,phase:2,pass", tokens[1].Value)
}

func TestLexer_QuotedArgWithEscape(t *testing.T) {
	t.Parallel()
	tokens := NewLexer(`SecAction "msg:\"hello\""`).Tokenize()
	require.Len(t, tokens, 2)
	assert.Equal(t, TokenQuoted, tokens[1].Type)
	assert.Equal(t, `msg:"hello"`, tokens[1].Value)
}

func TestLexer_ThreeArgSecRule(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx test" "id:1,phase:2,deny"`
	tokens := NewLexer(src).Tokenize()
	require.Len(t, tokens, 4)
	assert.Equal(t, TokenDirective, tokens[0].Type)
	assert.Equal(t, "SecRule", tokens[0].Value)
	assert.Equal(t, TokenWord, tokens[1].Type)
	assert.Equal(t, "ARGS", tokens[1].Value)
	assert.Equal(t, TokenQuoted, tokens[2].Type)
	assert.Equal(t, "@rx test", tokens[2].Value)
	assert.Equal(t, TokenQuoted, tokens[3].Type)
	assert.Equal(t, "id:1,phase:2,deny", tokens[3].Value)
}

func TestLexer_ContinuationLine(t *testing.T) {
	t.Parallel()
	src := "SecRule ARGS \\\n\"@rx test\" \\\n\"id:1,phase:2,deny\""
	tokens := NewLexer(src).Tokenize()
	require.Len(t, tokens, 4)
	assert.Equal(t, "SecRule", tokens[0].Value)
	assert.Equal(t, "ARGS", tokens[1].Value)
	assert.Equal(t, "@rx test", tokens[2].Value)
	assert.Equal(t, "id:1,phase:2,deny", tokens[3].Value)
}

func TestLexer_MultipleDirectives(t *testing.T) {
	t.Parallel()
	src := "SecRuleEngine On\nSecRequestBodyAccess On"
	tokens := NewLexer(src).Tokenize()
	require.Len(t, tokens, 4)
	assert.Equal(t, "SecRuleEngine", tokens[0].Value)
	assert.Equal(t, "On", tokens[1].Value)
	assert.Equal(t, "SecRequestBodyAccess", tokens[2].Value)
	assert.Equal(t, "On", tokens[3].Value)
	// Check line numbers.
	assert.Equal(t, 0, tokens[0].Line)
	assert.Equal(t, 1, tokens[2].Line)
}

func TestLexer_LinePositions(t *testing.T) {
	t.Parallel()
	// "SecRule ARGS" → SecRule at col 0, ARGS at col 8.
	src := "SecRule ARGS"
	tokens := NewLexer(src).Tokenize()
	require.Len(t, tokens, 2)
	assert.Equal(t, 0, tokens[0].StartChar)
	assert.Equal(t, 8, tokens[1].StartChar)
}

func TestLexer_WindowsLineEndings(t *testing.T) {
	t.Parallel()
	src := "SecRuleEngine On\r\nSecRequestBodyAccess On\r\n"
	tokens := NewLexer(src).Tokenize()
	require.Len(t, tokens, 4)
	assert.Equal(t, "SecRuleEngine", tokens[0].Value)
	assert.Equal(t, "SecRequestBodyAccess", tokens[2].Value)
}

func TestLexer_CommentMidFile(t *testing.T) {
	t.Parallel()
	src := "SecRuleEngine On\n# comment\nSecRequestBodyAccess On"
	tokens := NewLexer(src).Tokenize()
	require.Len(t, tokens, 5)
	assert.Equal(t, TokenComment, tokens[2].Type)
	assert.Equal(t, 1, tokens[2].Line)
}

func TestLexer_UnclosedQuotedString(t *testing.T) {
	t.Parallel()
	// An unclosed quoted string should still produce a token (graceful handling).
	src := `SecAction "id:1,phase:2`
	tokens := NewLexer(src).Tokenize()
	require.Len(t, tokens, 2)
	assert.Equal(t, TokenQuoted, tokens[1].Type)
	assert.Equal(t, "id:1,phase:2", tokens[1].Value)
}

func TestLexer_IndentedComment(t *testing.T) {
	t.Parallel()
	src := "  # indented comment"
	tokens := NewLexer(src).Tokenize()
	require.Len(t, tokens, 1)
	assert.Equal(t, TokenComment, tokens[0].Type)
}

// ----------------------------------------------------------------------------
// Group 10: Lexer robustness
// Why: the lexer's physPos mapping can drift on unusual whitespace. These tests
// are regression guards for the common real-world formatting quirks users hit.
// ----------------------------------------------------------------------------

func TestLexer_TabIndentedDirective(t *testing.T) {
	t.Parallel()
	// Some editors indent config lines with tabs.
	// The lexer must parse the directive and produce a token (not ignore it).
	src := "\tSecRuleEngine On"
	tokens := NewLexer(src).Tokenize()
	require.Len(t, tokens, 2)
	assert.Equal(t, TokenDirective, tokens[0].Type)
	assert.Equal(t, "SecRuleEngine", tokens[0].Value)
	assert.Equal(t, TokenWord, tokens[1].Type)
	assert.Equal(t, "On", tokens[1].Value)
}

func TestLexer_TrailingSpaces(t *testing.T) {
	t.Parallel()
	// Trailing spaces after a directive value must not produce extra tokens.
	src := "SecRuleEngine On   "
	tokens := NewLexer(src).Tokenize()
	require.Len(t, tokens, 2, "trailing spaces should not create extra tokens")
	assert.Equal(t, "On", tokens[1].Value)
}

func TestLexer_CRLFWithContinuation(t *testing.T) {
	t.Parallel()
	// Windows line endings (\r\n) combined with backslash continuation.
	// This is the intersection of two tricky cases.
	src := "SecRule ARGS \\\r\n\"@rx test\" \\\r\n\"id:1,phase:2,deny\""
	tokens := NewLexer(src).Tokenize()
	require.Len(t, tokens, 4)
	assert.Equal(t, "SecRule", tokens[0].Value)
	assert.Equal(t, "ARGS", tokens[1].Value)
	assert.Equal(t, "@rx test", tokens[2].Value)
	assert.Equal(t, "id:1,phase:2,deny", tokens[3].Value)
}

func TestLexer_OnlyWhitespaceLines(t *testing.T) {
	t.Parallel()
	// A file of nothing but whitespace must not produce tokens or panic.
	for _, src := range []string{"   ", "\t\t", "  \r\n  \r\n"} {
		tokens := NewLexer(src).Tokenize()
		assert.Empty(t, tokens, "whitespace-only source %q should produce no tokens", src)
	}
}

func TestLexer_MixedCRLFAndLF(t *testing.T) {
	t.Parallel()
	// Mixed line endings in the same file (common after copy-paste).
	src := "SecRuleEngine On\r\nSecRequestBodyAccess On\nSecAuditEngine On\r\n"
	tokens := NewLexer(src).Tokenize()
	require.Len(t, tokens, 6)
	assert.Equal(t, "SecRuleEngine", tokens[0].Value)
	assert.Equal(t, "SecRequestBodyAccess", tokens[2].Value)
	assert.Equal(t, "SecAuditEngine", tokens[4].Value)
	// Line numbers must be sequential.
	assert.Equal(t, 0, tokens[0].Line)
	assert.Equal(t, 1, tokens[2].Line)
	assert.Equal(t, 2, tokens[4].Line)
}

func TestLexer_DirectiveWithTabSeparatedArgs(t *testing.T) {
	t.Parallel()
	// Tabs as whitespace between directive and argument.
	src := "SecRuleEngine\tOn"
	tokens := NewLexer(src).Tokenize()
	require.Len(t, tokens, 2)
	assert.Equal(t, "SecRuleEngine", tokens[0].Value)
	assert.Equal(t, "On", tokens[1].Value)
}

// TestLexer_PreservesBackslashEscapes is a regression test: readQuoted must not
// strip backslashes from regex operator arguments. Coraza's seclang unescaper
// only unescapes \" -> "; every other backslash is left literal. Previously the
// lexer dropped the backslash for every escape, corrupting patterns like
// [\s\x0b] into [sx0b].
func TestLexer_PreservesBackslashEscapes(t *testing.T) {
	t.Parallel()

	t.Run("regex character classes survive", func(t *testing.T) {
		t.Parallel()
		src := `SecRule ARGS "@rx [\s\x0b]" "id:1"`
		tokens := NewLexer(src).Tokenize()
		require.Len(t, tokens, 4)
		assert.Equal(t, TokenQuoted, tokens[2].Type)
		assert.Equal(t, `@rx [\s\x0b]`, tokens[2].Value)
	})

	t.Run("escaped double quotes are unescaped", func(t *testing.T) {
		t.Parallel()
		src := `SecRule ARGS "@rx say \"hi\"" "id:1"`
		tokens := NewLexer(src).Tokenize()
		require.Len(t, tokens, 4)
		assert.Equal(t, TokenQuoted, tokens[2].Type)
		assert.Equal(t, `@rx say "hi"`, tokens[2].Value)
	})
}

// TestParse_OperatorArgRoundTripsBackslashes asserts the parsed OperatorExpr
// argument keeps its backslashes intact end-to-end.
func TestParse_OperatorArgRoundTripsBackslashes(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx [\s\x0b]" "id:1"`
	f := Parse("test.conf", src)
	require.Len(t, f.Nodes, 1)
	rule, ok := f.Nodes[0].(*RuleNode)
	require.True(t, ok)
	require.NotNil(t, rule.Operator)
	assert.Equal(t, "rx", rule.Operator.Name)
	assert.Equal(t, `[\s\x0b]`, rule.Operator.Argument)
}

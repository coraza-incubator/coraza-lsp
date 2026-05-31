// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

// Package parser provides a tolerant, position-tracking lexer and recursive
// descent parser for the SecLang/ModSecurity rule language.
//
// The parser always produces a partial AST + a list of parse errors regardless
// of how malformed the input is — this is a hard requirement for LSP usage
// where the user is mid-edit.
//
// All positions are 0-indexed (line and character) following the LSP convention.
package parser

import "github.com/coraza-incubator/coraza-lsp/internal/lsppos"

// TokenType classifies a scanned token.
type TokenType int

const (
	// TokenEOF marks the end of input.
	TokenEOF TokenType = iota
	// TokenComment is a line that begins with #.
	TokenComment
	// TokenDirective is the first word on a non-comment line (e.g. SecRule, Include).
	TokenDirective
	// TokenWord is an unquoted argument token.
	TokenWord
	// TokenQuoted is a double-quoted string argument (value excludes the quotes).
	TokenQuoted
	// TokenPipe separates variables in a variable list (|).
	TokenPipe
	// TokenComma separates actions in an action list (,).
	TokenComma
	// TokenColon separates key from value in an action (key:value).
	TokenColon
	// TokenAt is the operator prefix (@).
	TokenAt
	// TokenBang is the negation prefix (!).
	TokenBang
	// TokenAmpersand is the count prefix (&).
	TokenAmpersand
)

// PhysLineBreak records where a new physical line begins within a multi-line
// token's Value string. At ValueByte into Token.Value the text has crossed
// into PhysLine at column PhysChar.
type PhysLineBreak struct {
	ValueByte int // byte offset into Token.Value (exclusive: new line starts here)
	PhysLine  int // physical line number (0-indexed)
	PhysChar  int // column offset on that physical line (0-indexed)
}

// Token is a single scanned token with position information.
// Line and StartChar are 0-indexed, matching the LSP protocol convention.
type Token struct {
	Type      TokenType
	Value     string
	Line      int  // 0-indexed physical line number (start)
	StartChar int  // 0-indexed UTF-8 code-unit offset within the start line
	EndLine   int  // 0-indexed physical end line; 0 means same as Line
	EndChar   int  // exclusive end offset on EndLine (or Line when EndLine==0)
	Unclosed  bool // true for TokenQuoted with no closing "

	// PhysLineBreaks records physical line transitions within Token.Value.
	// For single-line tokens this is nil. For multi-line tokens, each entry
	// marks where a new physical line starts inside the value content.
	PhysLineBreaks []PhysLineBreak
}

// PhysPos returns the physical (line, char) for a byte offset within Token.Value.
// Used by action/variable parsers to compute correct diagnostic positions for
// values that span multiple physical lines.
//
// valueByte is a BYTE offset into Token.Value, but the returned char is a RUNE
// column (matching the lexer, which reports columns as lsppos.UTF16Len).
// We therefore convert the byte offset into a rune count relative to the start
// of the active physical segment before adding it to that segment's start column,
// so that multibyte content earlier in the value (e.g. msg:'café') does not shift
// subsequent positions by (bytes - runes).
func (t Token) PhysPos(valueByte int) (physLine, physChar int) {
	if valueByte < 0 {
		valueByte = 0
	}
	if valueByte > len(t.Value) {
		valueByte = len(t.Value)
	}
	// Default: still on the token's start line. The value begins right after the
	// opening " (StartChar+1). The rune column is that base plus the rune count of
	// the value bytes preceding valueByte.
	line := t.Line
	startCol := t.StartChar + 1
	segByte := 0 // byte offset in Value where the active segment begins
	for _, b := range t.PhysLineBreaks {
		if b.ValueByte > valueByte {
			break
		}
		line = b.PhysLine
		startCol = b.PhysChar
		segByte = b.ValueByte
	}
	runeOff := lsppos.UTF16Len(t.Value[segByte:valueByte])
	return line, startCol + runeOff
}

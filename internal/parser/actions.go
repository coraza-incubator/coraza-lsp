// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"github.com/coraza-incubator/coraza-lsp/internal/lsppos"
	"strings"
)

// parseActions parses an action list string into ActionExpr nodes.
// tok is the quoted Token whose Value is s; it provides position mapping for
// multi-line tokens via tok.PhysPos so that each action's Range reflects its
// true physical (line, character) position even when the action list spans
// multiple physical lines via backslash continuation.
//
// Action list syntax (comma-separated):
//
//	id:1001,phase:2,deny,msg:'SQL injection',t:lowercase,t:urlDecode
//
// Values may be single-quoted strings: msg:'text with, commas'.
// The parser is tolerant: errors on one action do not prevent parsing the rest.
func parseActions(s string, tok Token) ([]ActionExpr, []ParseError) {
	var exprs []ActionExpr
	var errs []ParseError

	parts := splitOnComma(s)
	byteOffset := 0 // byte offset into tok.Value (== s)

	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			byteOffset += len(part) + 1
			continue
		}

		// Leading whitespace in bytes (ASCII spaces/tabs — same as rune count for these).
		leadingBytes := len(part) - len(strings.TrimLeft(part, " \t"))
		// Map the trimmed action's start byte to its physical (line, char).
		physLine, physChar := tok.PhysPos(byteOffset + leadingBytes)
		actionStart := Position{Line: physLine, Character: physChar}

		expr := parseSingleAction(trimmed, actionStart)
		exprs = append(exprs, expr)

		byteOffset += len(part) + 1 // +1 for comma
	}

	return exprs, errs
}

// parseSingleAction parses a single action like: id:1001 or deny or msg:'text'.
func parseSingleAction(s string, start Position) ActionExpr {
	expr := ActionExpr{}

	colonIdx := strings.IndexByte(s, ':')
	if colonIdx < 0 {
		// No colon: action with no value (e.g. "deny", "pass", "log", "capture").
		expr.Name = s
		expr.HasColon = false
		expr.Value = ""
	} else {
		expr.Name = s[:colonIdx]
		expr.HasColon = true
		raw := s[colonIdx+1:]
		// Unquote single-quoted values: msg:'text' → text
		expr.Value = unquoteSingle(raw)
	}

	endChar := start.Character + lsppos.UTF16Len(s)
	expr.Range = Range{
		Start: start,
		End:   Position{Line: start.Line, Character: endChar},
	}
	return expr
}

// unquoteSingle removes surrounding single quotes from a value if present.
// Handles escaped single quotes inside: msg:'it\'s fine'.
func unquoteSingle(s string) string {
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		inner := s[1 : len(s)-1]
		return strings.ReplaceAll(inner, "\\'", "'")
	}
	return s
}

// splitOnComma splits s on commas that are not inside single-quoted strings.
// This handles action values like msg:'a,b,c'.
// It scans bytes and returns subslices of the original string, preserving the
// byte offsets that downstream position mapping relies on (no rune copy).
func splitOnComma(s string) []string {
	var parts []string
	inSingle := false
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && inSingle && i+1 < len(s) && s[i+1] == '\'':
			// Escaped single quote inside single-quoted string.
			i++
		case c == '\'':
			inSingle = !inSingle
		case c == ',' && !inSingle:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

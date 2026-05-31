// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"github.com/coraza-incubator/coraza-lsp/internal/lsppos"
	"strconv"
	"strings"
)

// ParseVariables parses a SecRule variable list string into VariableExpr nodes.
// The offset is the position in the source file where the string begins.
//
// Variable list syntax (pipe-separated):
//
//	!ARGS:foo|&REQUEST_HEADERS:User-Agent|ARGS_NAMES|TX:/regex/
//
// The parser is tolerant: partial or malformed expressions produce a ParseError
// but do not prevent parsing subsequent variables.
func ParseVariables(s string, offset Position) ([]VariableExpr, []ParseError) {
	var exprs []VariableExpr
	var errs []ParseError

	// Split on unquoted pipes.
	parts := splitOnPipe(s)

	charOffset := offset.Character
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			charOffset += lsppos.UTF16Len(part) + 1 // +1 for pipe
			continue
		}

		// Track the start position of this variable in the source.
		leadingSpaces := lsppos.UTF16Len(part) - lsppos.UTF16Len(strings.TrimLeft(part, " \t"))
		varStart := Position{Line: offset.Line, Character: charOffset + leadingSpaces}

		expr, err := parseSingleVariable(trimmed, varStart, offset.Line)
		if err != nil {
			errs = append(errs, *err)
		} else {
			exprs = append(exprs, expr)
		}

		charOffset += lsppos.UTF16Len(part) + 1 // +1 for pipe separator
	}

	return exprs, errs
}

// parseSingleVariable parses a single variable expression like:
//
//	ARGS, !ARGS:foo, &FILES, REQUEST_HEADERS:/regex/
func parseSingleVariable(s string, start Position, line int) (VariableExpr, *ParseError) {
	expr := VariableExpr{}
	pos := 0

	// Negation prefix.
	if pos < len(s) && s[pos] == '!' {
		expr.Negated = true
		pos++
	}
	// Count prefix.
	if pos < len(s) && s[pos] == '&' {
		expr.Count = true
		pos++
	}
	if pos >= len(s) {
		return expr, &ParseError{
			Message: "expected variable name after prefix",
			Range: Range{
				Start: start,
				End:   Position{Line: line, Character: start.Character + lsppos.UTF16Len(s)},
			},
		}
	}

	// Variable name: uppercase letters, digits, underscores only.
	// Stop at ':' (key separator), '*' (wildcard suffix), or any character
	// that is not valid in a variable name — the latter is a syntax error.
	nameStart := pos
	for pos < len(s) && s[pos] != ':' && s[pos] != '*' {
		b := s[pos]
		if !((b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '_') {
			// Invalid character in variable name → syntax error.
			baseName := strings.ToUpper(s[nameStart:pos])
			msg := "invalid character " + strconv.Quote(string(rune(b))) + " in variable name"
			if b == '.' && baseName != "" {
				// Common typo: '.' used instead of ':' for key selectors.
				rest := s[pos+1:]
				msg = "invalid character '.' in variable name; use ':' as the key separator (e.g. " + baseName + ":" + rest + ")"
			}
			return expr, &ParseError{
				Message: msg,
				Range: Range{
					Start: start,
					End:   Position{Line: line, Character: start.Character + lsppos.UTF16Len(s)},
				},
			}
		}
		pos++
	}
	expr.Name = strings.ToUpper(s[nameStart:pos])

	if expr.Name == "" {
		return expr, &ParseError{
			Message: "empty variable name",
			Range: Range{
				Start: start,
				End:   Position{Line: line, Character: start.Character + lsppos.UTF16Len(s)},
			},
		}
	}

	// Wildcard suffix: COLLECTION* is equivalent to COLLECTION:*.
	if pos < len(s) && s[pos] == '*' {
		expr.Key = "*"
		endChar := start.Character + lsppos.UTF16Len(s)
		expr.Range = Range{
			Start: start,
			End:   Position{Line: line, Character: endChar},
		}
		return expr, nil
	}

	// Optional :key or :/regex/.
	if pos < len(s) && s[pos] == ':' {
		pos++ // skip colon
		key := s[pos:]
		if strings.ToUpper(expr.Name) == "XML" {
			// XML collection uses XPath syntax — the key is an XPath expression
			// (e.g. /*, //body//*), not a regex. Accept it as-is without attempting
			// regex validation.
			expr.Key = key
		} else if strings.HasPrefix(key, "/") && strings.HasSuffix(key, "/") && len(key) > 1 {
			expr.Key = key[1 : len(key)-1]
			expr.KeyIsRegex = true
		} else if strings.HasPrefix(key, "/") {
			// Starts with / but has no closing / — unclosed regex pattern.
			return expr, &ParseError{
				Message: `unclosed regex in variable key: missing closing /`,
				Range: Range{
					Start: start,
					End:   Position{Line: line, Character: start.Character + lsppos.UTF16Len(s)},
				},
			}
		} else {
			expr.Key = key
		}
	}

	endChar := start.Character + lsppos.UTF16Len(s)
	expr.Range = Range{
		Start: start,
		End:   Position{Line: line, Character: endChar},
	}

	return expr, nil
}

// splitOnPipe splits s on unquoted pipe characters.
// Pipes inside single-quoted strings (e.g. msg:'a|b') are not separators.
func splitOnPipe(s string) []string {
	var parts []string
	var cur strings.Builder
	inSingle := false
	for _, r := range s {
		switch {
		case r == '\'' && !inSingle:
			inSingle = true
			cur.WriteRune(r)
		case r == '\'' && inSingle:
			inSingle = false
			cur.WriteRune(r)
		case r == '|' && !inSingle:
			parts = append(parts, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	parts = append(parts, cur.String())
	return parts
}

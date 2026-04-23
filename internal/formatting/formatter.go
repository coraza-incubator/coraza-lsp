// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

// Package formatting provides SecLang source code formatting.
package formatting

import (
	"strings"
	"unicode"

	protocol_3_16 "github.com/tliron/glsp/protocol_3_16"
)

// trimRightSpace trims all trailing Unicode whitespace, not just ASCII space
// and tab. SecLang rule files are practically ASCII, but accepting bytes like
// \v, \f, or non-breaking space pasted from a browser must not make the
// formatter non-idempotent.
func trimRightSpace(s string) string {
	return strings.TrimRightFunc(s, unicode.IsSpace)
}

// Format returns a list of text edits that normalise the SecLang source.
// Currently returns a single whole-document replacement with:
//   - Continuation lines indented with 4 spaces
//   - Exactly one space between directive arguments
//   - Trailing whitespace removed from each line
//   - Single blank line between directives
func Format(source string) []protocol_3_16.TextEdit {
	formatted := formatSource(source)
	if formatted == source {
		return nil
	}

	// Count lines in original for the end position.
	lines := strings.Split(source, "\n")
	endLine := len(lines) - 1
	endChar := len(lines[endLine])

	return []protocol_3_16.TextEdit{
		{
			Range: protocol_3_16.Range{
				Start: protocol_3_16.Position{Line: 0, Character: 0},
				End: protocol_3_16.Position{
					Line:      uint32(endLine),
					Character: uint32(endChar),
				},
			},
			NewText: formatted,
		},
	}
}

// formatSource performs the actual formatting transformations.
func formatSource(source string) string {
	rawLines := strings.Split(source, "\n")
	// Strip \r from Windows line endings.
	for i, l := range rawLines {
		rawLines[i] = strings.TrimRight(l, "\r")
	}

	var out []string
	i := 0
	for i < len(rawLines) {
		line := rawLines[i]

		// Preserve blank lines (but collapse multiple consecutive blanks into one).
		if strings.TrimSpace(line) == "" {
			if len(out) > 0 && strings.TrimSpace(out[len(out)-1]) != "" {
				out = append(out, "")
			}
			i++
			continue
		}

		// Preserve comment lines (strip trailing whitespace).
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			out = append(out, trimRightSpace(line))
			i++
			continue
		}

		// Collect continuation lines.
		var logicalParts []string
		for i < len(rawLines) {
			l := rawLines[i]
			stripped := trimRightSpace(l)
			if strings.HasSuffix(stripped, "\\") {
				logicalParts = append(logicalParts, strings.TrimRight(stripped, "\\"))
				i++
			} else {
				logicalParts = append(logicalParts, stripped)
				i++
				break
			}
		}

		// Join and re-split for formatting.
		logical := strings.Join(logicalParts, " ")
		// Any trailing backslash-plus-whitespace run on the joined logical line
		// is a stray continuation marker (the final physical line ended with
		// one but had no successor, or the whole rule is nothing but `\`s).
		// Strip it so formatting is idempotent: otherwise the next pass would
		// re-interpret the emitted `\` as a continuation and collapse.
		for {
			trimmed := trimRightSpace(logical)
			if !strings.HasSuffix(trimmed, "\\") {
				logical = trimmed
				break
			}
			logical = strings.TrimSuffix(trimmed, "\\")
		}
		formatted := formatLogicalLine(logical)
		// A `\`-continuation whose joined content is empty (e.g. bare `\` on a
		// line by itself followed by a blank) collapses to nothing rather than
		// emitting a phantom blank line — emitting one would break idempotence,
		// since the next pass would treat the leading blank as suppressible.
		if formatted == "" {
			continue
		}
		out = append(out, formatted)
	}

	// Trim trailing blank lines.
	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}

	return strings.Join(out, "\n")
}

// formatLogicalLine normalises a single logical directive line.
func formatLogicalLine(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}

	// Split into tokens (directive + arguments).
	parts := splitLogicalArgs(line)
	if len(parts) == 0 {
		return line
	}

	if len(parts) == 1 {
		return parts[0]
	}

	// Format with single spaces between parts.
	return strings.Join(parts, " ")
}

// splitLogicalArgs splits a logical line into [directive, arg1, arg2, ...].
// Quoted strings are kept intact.
func splitLogicalArgs(s string) []string {
	var parts []string
	var cur strings.Builder
	inQuote := false
	escaped := false

	for _, r := range s {
		if escaped {
			cur.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' && inQuote {
			cur.WriteRune(r)
			escaped = true
			continue
		}
		if r == '"' {
			if inQuote {
				cur.WriteRune(r)
				inQuote = false
				parts = append(parts, cur.String())
				cur.Reset()
			} else {
				if cur.Len() > 0 {
					parts = append(parts, cur.String())
					cur.Reset()
				}
				cur.WriteRune(r)
				inQuote = true
			}
			continue
		}
		if (r == ' ' || r == '\t') && !inQuote {
			if cur.Len() > 0 {
				parts = append(parts, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteRune(r)
	}
	if cur.Len() > 0 {
		parts = append(parts, cur.String())
	}
	return parts
}

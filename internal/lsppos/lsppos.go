// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

// Package lsppos converts between the byte/rune view of source text and the
// UTF-16 code-unit columns the Language Server Protocol uses for the `character`
// field of a Position.
//
// LSP's default (and the only universally-supported) position encoding is
// UTF-16 code units, NOT bytes and NOT Unicode code points. For BMP characters
// (which includes virtually everything an AI tends to emit into a config file —
// smart quotes, em dashes, accents, arrows, CJK) one rune is exactly one UTF-16
// unit, so rune counting happens to be correct. But astral-plane characters
// (emoji such as U+1F600, mathematical alphanumerics, …) are a single rune yet
// TWO UTF-16 code units, so rune counting drifts and a diagnostic/hover lands on
// the wrong column. These helpers make the column exact for all of Unicode.
package lsppos

// UTF16Len returns the number of UTF-16 code units needed to encode s.
func UTF16Len(s string) int {
	n := 0
	for _, r := range s {
		if r > 0xFFFF {
			n += 2 // encoded as a surrogate pair
		} else {
			n++
		}
	}
	return n
}

// UTF16ColumnToByte maps a UTF-16 column within line to a byte offset into line.
// Out-of-range columns are clamped to [0, len(line)]. If the column falls in the
// middle of a surrogate pair (which a well-behaved client never sends) it rounds
// up to the byte after the offending rune.
func UTF16ColumnToByte(line string, col int) int {
	if col <= 0 {
		return 0
	}
	units := 0
	for i, r := range line {
		if units >= col {
			return i
		}
		if r > 0xFFFF {
			units += 2
		} else {
			units++
		}
	}
	return len(line)
}

// UTF16ColumnToRune maps a UTF-16 column within line to a rune index into line
// (i.e. an index into []rune(line)). Clamped to the line's rune count.
func UTF16ColumnToRune(line string, col int) int {
	if col <= 0 {
		return 0
	}
	units, runes := 0, 0
	for _, r := range line {
		if units >= col {
			return runes
		}
		if r > 0xFFFF {
			units += 2
		} else {
			units++
		}
		runes++
	}
	return runes
}

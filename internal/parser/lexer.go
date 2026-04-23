// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"strings"
	"unicode/utf8"
)

// Lexer tokenizes a SecLang source string.
//
// SecLang is a line-oriented language. Each logical line may span multiple
// physical lines via backslash continuation. The lexer stitches continuation
// lines before tokenizing, but maps tokens back to their physical line positions.
type Lexer struct {
	lines []string // physical source lines (no trailing newline)
}

// NewLexer creates a Lexer for the given source text.
func NewLexer(source string) *Lexer {
	lines := strings.Split(source, "\n")
	// Strip a trailing \r from each line (Windows line endings).
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, "\r")
	}
	return &Lexer{lines: lines}
}

// Tokenize returns all tokens in the source.
// Each call is O(n) in the number of source lines.
func (l *Lexer) Tokenize() []Token {
	var tokens []Token
	physLine := 0
	for physLine < len(l.lines) {
		line := l.lines[physLine]
		startLine := physLine

		// Skip blank lines.
		if strings.TrimSpace(line) == "" {
			physLine++
			continue
		}

		// Comment lines.
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			tokens = append(tokens, Token{
				Type:      TokenComment,
				Value:     line,
				Line:      physLine,
				StartChar: 0,
				EndChar:   utf8.RuneCountInString(line),
			})
			physLine++
			continue
		}

		// Stitch continuation lines.
		logical, lineMap := l.stitchContinuation(physLine)
		physLine += len(lineMap)

		// Tokenize the logical line.
		lineTokens := tokenizeLogical(logical, startLine, lineMap, l.lines)
		tokens = append(tokens, lineTokens...)
	}
	return tokens
}

// stitchContinuation collects the logical line starting at physLine,
// following backslash continuations.
//
// Returns:
//   - logical: the logical line with continuation markers removed and joined by space
//   - lineMap: slice of physical line indices (one entry per physical line consumed)
func (l *Lexer) stitchContinuation(start int) (string, []int) {
	var parts []string
	var lineMap []int
	i := start
	for i < len(l.lines) {
		raw := l.lines[i]
		lineMap = append(lineMap, i)
		if strings.HasSuffix(raw, "\\") {
			parts = append(parts, strings.TrimRight(raw, "\\"))
			i++
		} else {
			parts = append(parts, raw)
			i++
			break
		}
	}
	return strings.Join(parts, " "), lineMap
}

// tokenizeLogical tokenizes a logical line that may span multiple physical lines.
// startLine is the physical line index of the first line.
// lineMap maps logical-line indices back to physical lines.
func tokenizeLogical(logical string, startLine int, lineMap []int, physLines []string) []Token {
	var tokens []Token

	// We scan the logical line for the directive name and arguments.
	// Position mapping: we compute physical positions by scanning the
	// original physical lines in parallel.
	p := &logicalScanner{
		logical:   logical,
		pos:       0,
		startLine: startLine,
		lineMap:   lineMap,
		physLines: physLines,
	}

	// Skip leading whitespace.
	p.skipWS()
	if p.done() {
		return tokens
	}

	// First token: directive name.
	start := p.pos
	word := p.readWord()
	if word == "" {
		return tokens
	}
	physL, physC := p.physPos(start)
	tokens = append(tokens, Token{
		Type:      TokenDirective,
		Value:     word,
		Line:      physL,
		StartChar: physC,
		EndChar:   physC + utf8.RuneCountInString(word),
	})

	// Subsequent tokens: arguments (words or quoted strings).
	for {
		p.skipWS()
		if p.done() {
			break
		}
		ch := p.peek()
		if ch == '"' {
			tok := p.readQuoted()
			tokens = append(tokens, tok)
		} else {
			start := p.pos
			word := p.readWord()
			if word == "" {
				break
			}
			physL, physC := p.physPos(start)
			tokens = append(tokens, Token{
				Type:      TokenWord,
				Value:     word,
				Line:      physL,
				StartChar: physC,
				EndChar:   physC + utf8.RuneCountInString(word),
			})
		}
	}

	return tokens
}

// logicalScanner scans a logical line with position tracking back to physical lines.
type logicalScanner struct {
	logical   string
	pos       int    // byte position in logical
	startLine int    // physical line of first part
	lineMap   []int  // physical line index for each segment
	physLines []string
}

func (s *logicalScanner) done() bool { return s.pos >= len(s.logical) }

func (s *logicalScanner) peek() byte {
	if s.done() {
		return 0
	}
	return s.logical[s.pos]
}

func (s *logicalScanner) skipWS() {
	for !s.done() && isWS(s.logical[s.pos]) {
		s.pos++
	}
}

func (s *logicalScanner) readWord() string {
	start := s.pos
	for !s.done() && !isWS(s.logical[s.pos]) && s.logical[s.pos] != '"' {
		s.pos++
	}
	return s.logical[start:s.pos]
}

// readQuoted reads a double-quoted string, handling escape sequences.
// Returns a Token with Type=TokenQuoted and Value set to the unquoted content.
// Token.Unclosed is true when no closing " was found before end of input.
// For multi-line tokens (continuation lines), Token.PhysLineBreaks is populated
// so that callers can map value byte offsets to physical (line, char) positions.
func (s *logicalScanner) readQuoted() Token {
	startByte := s.pos
	physL, physC := s.physPos(startByte)
	s.pos++ // consume opening "
	var buf strings.Builder
	closed := false
	var physBreaks []PhysLineBreak

	// For multi-line logical lines, track which physical segment s.pos is in.
	// segmentBoundary(i) gives the byte offset in the logical string where segment i starts.
	curSeg := 0
	if len(s.lineMap) > 1 {
		// Find the starting segment for s.pos (first char of value, after opening ").
		for curSeg+1 < len(s.lineMap) && s.pos >= s.segmentBoundary(curSeg+1) {
			curSeg++
		}
	}

	for !s.done() {
		// Before processing the char at s.pos, check if we've entered a new segment.
		if len(s.lineMap) > 1 {
			for curSeg+1 < len(s.lineMap) {
				nextBoundary := s.segmentBoundary(curSeg + 1)
				if s.pos < nextBoundary {
					break
				}
				curSeg++
				// The current buf.Len() is the value byte index of the first character
				// in this new physical segment.
				physBreaks = append(physBreaks, PhysLineBreak{
					ValueByte: buf.Len(),
					PhysLine:  s.lineMap[curSeg],
					PhysChar:  0, // new segment starts at column 0 of its physical line
				})
			}
		}

		ch := s.logical[s.pos]
		if ch == '\\' && s.pos+1 < len(s.logical) {
			s.pos++ // skip backslash
			buf.WriteByte(s.logical[s.pos])
			s.pos++
		} else if ch == '"' {
			s.pos++ // consume closing "
			closed = true
			break
		} else {
			buf.WriteByte(ch)
			s.pos++
		}
	}
	value := buf.String()
	// Compute the physical end position (position of closing " or last char read).
	endByte := s.pos
	if endByte > 0 {
		endByte-- // step back to last consumed byte
	}
	endPhysL, endPhysC := s.physPos(endByte)
	return Token{
		Type:           TokenQuoted,
		Value:          value,
		Line:           physL,
		StartChar:      physC,
		EndLine:        endPhysL,
		EndChar:        endPhysC + 1, // +1: exclusive end past the closing " (or last char)
		Unclosed:       !closed,
		PhysLineBreaks: physBreaks,
	}
}

// segmentBoundary returns the byte offset in the logical string where segment i begins.
// Segment boundaries are computed from the actual stitched lengths: each non-last segment
// contributes len(physLine) - 1 bytes (backslash removed) plus 1 (space separator).
func (s *logicalScanner) segmentBoundary(i int) int {
	offset := 0
	for j := 0; j < i; j++ {
		physIdx := s.lineMap[j]
		seg := s.physLines[physIdx]
		n := len(seg)
		if strings.HasSuffix(seg, "\\") {
			n-- // the continuation backslash was removed during stitching
		}
		offset += n + 1 // +1 for the space separator added by strings.Join
	}
	return offset
}

// physPos maps a byte position in the logical line to (physicalLine, charOffset).
// This is an approximation that works for the common case:
// - Single-line directives map directly.
// - Multi-line (continuation) directives: the position is in the first physical line
//   unless it exceeds that line's length, in which case we advance to the next.
func (s *logicalScanner) physPos(logicalByte int) (line, char int) {
	if len(s.lineMap) == 1 {
		return s.lineMap[0], utf8.RuneCountInString(s.physLines[s.lineMap[0]][:min(logicalByte, len(s.physLines[s.lineMap[0]]))])
	}
	// For continuation lines, walk through segments.
	// Each non-last segment contributes exactly len(physLines[i]) bytes to the
	// logical string: the trailing backslash is removed (-1) and a space separator
	// is added (+1), so the net change is zero. Using < (strict) ensures the first
	// byte of segment N+1 is attributed to segment N+1, not N.
	offset := 0
	for i, physIdx := range s.lineMap {
		segLen := len(s.physLines[physIdx])
		if logicalByte < offset+segLen || i == len(s.lineMap)-1 {
			localByte := logicalByte - offset
			if localByte < 0 {
				localByte = 0
			}
			src := s.physLines[physIdx]
			if localByte > len(src) {
				localByte = len(src)
			}
			return physIdx, utf8.RuneCountInString(src[:localByte])
		}
		offset += segLen
	}
	return s.lineMap[len(s.lineMap)-1], 0
}

func isWS(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r'
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

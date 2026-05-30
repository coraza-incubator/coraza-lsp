// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

// Package completion provides context-aware SecLang completion items.
package completion

import (
	"strings"
)

// CompletionContext describes what kind of SecLang element is expected at
// the current cursor position.
type CompletionContext int

const (
	// ContextUnknown means the cursor position is unrecognised (e.g. inside a comment).
	ContextUnknown CompletionContext = iota
	// ContextDirectiveName means the cursor is at the beginning of a line (directive name).
	ContextDirectiveName
	// ContextVariableList means the cursor is in the variable list of a SecRule.
	ContextVariableList
	// ContextOperator means the cursor is where an @operator is expected.
	ContextOperator
	// ContextOperatorArg means the cursor is in the operator argument (first quoted string).
	ContextOperatorArg
	// ContextActionList means the cursor is at the start of a new action name in an action list.
	ContextActionList
	// ContextActionValue means the cursor is after the colon in an action (e.g. phase:|).
	ContextActionValue
	// ContextTransformation means the cursor is after t: in an action list.
	ContextTransformation
	// ContextPhaseValue means the cursor is after phase: in an action list.
	ContextPhaseValue
	// ContextIncludePath means the cursor is after the Include directive.
	ContextIncludePath
	// ContextRuleEngineValue means the cursor is after SecRuleEngine.
	ContextRuleEngineValue
	// ContextSeverityValue means the cursor is after severity:.
	ContextSeverityValue
	// ContextCtlKey means the cursor is typing the option key after ctl: (before =).
	ContextCtlKey
	// ContextCtlValue means the cursor is typing the option value after ctl:KEY=.
	// The prefix string is "KEY=valuePrefix" so the handler knows which key is active.
	ContextCtlValue
	// ContextSkipAfterValue means the cursor is after skipAfter: in an action list.
	// Completions are the SecMarker IDs defined in the current file.
	ContextSkipAfterValue
	// ContextMacroExpansion means the cursor is inside a %{...} macro expression.
	// The prefix is the text typed after %{. Completions are variable names (and
	// TX.key for file-local TX variables) in the dot-notation used by macros.
	ContextMacroExpansion
)

// DetectContext analyses the given line text up to the cursor position and
// returns the appropriate completion context plus the prefix to filter by.
//
// line is the full text of the current line; cursorChar is the 0-indexed
// character offset of the cursor within that line.
func DetectContext(line string, cursorChar int) (ctx CompletionContext, prefix string) {
	// Clamp cursor into range. A negative offset (which some clients can send
	// for an out-of-range position) would otherwise panic on line[:cursorChar].
	if cursorChar < 0 {
		cursorChar = 0
	}
	if cursorChar > len(line) {
		cursorChar = len(line)
	}
	textBeforeCursor := line[:cursorChar]

	// Comment lines never produce completions.
	trimmed := strings.TrimLeft(textBeforeCursor, " \t")
	if strings.HasPrefix(trimmed, "#") {
		return ContextUnknown, ""
	}

	// Split into tokens by whitespace, respecting quoted strings.
	tokens := tokenisePartial(textBeforeCursor)

	switch len(tokens) {
	case 0:
		return ContextDirectiveName, ""
	case 1:
		// Cursor is on or at the end of the first token (directive name).
		// If the line ends with a space, a second argument starts.
		if endsWithWS(textBeforeCursor) {
			return contextAfterDirective(tokens[0], "")
		}
		return ContextDirectiveName, tokens[0]
	default:
		// Two or more tokens: the directive is complete.
		directive := strings.ToLower(tokens[0])
		// The last token is the "current" prefix (may be empty if last char is space).
		var currentPrefix string
		if !endsWithWS(textBeforeCursor) {
			currentPrefix = tokens[len(tokens)-1]
		}
		argTokens := tokens[1:]
		return contextForArgs(directive, argTokens, textBeforeCursor, currentPrefix)
	}
}

// contextAfterDirective returns the context expected right after the directive name.
func contextAfterDirective(directive, prefix string) (CompletionContext, string) {
	switch strings.ToLower(directive) {
	case "secrule":
		return ContextVariableList, prefix
	case "secaction", "secdefaultaction":
		return ContextActionList, prefix
	case "include":
		return ContextIncludePath, prefix
	case "secruleengine":
		return ContextRuleEngineValue, prefix
	}
	return ContextUnknown, prefix
}

// contextForArgs determines context given the directive and already-seen arg tokens.
func contextForArgs(directive string, argTokens []string, fullText, prefix string) (CompletionContext, string) {
	switch directive {
	case "secrule":
		return contextInSecRule(argTokens, fullText, prefix)
	case "secaction", "secdefaultaction":
		return contextInActionList(prefix)
	case "include":
		return ContextIncludePath, prefix
	case "secruleengine":
		return ContextRuleEngineValue, prefix
	}
	return ContextUnknown, prefix
}

// contextInSecRule determines where in a SecRule the cursor is.
//
// SecRule structure:  DIRECTIVE  VARS  "@OP_ARG"  "ACTIONS"
//                                 ^         ^           ^
// The variable list is unquoted and precedes the first quoted string.
// The operator is inside the first quoted string.
// The action list is inside the second quoted string.
func contextInSecRule(argTokens []string, fullText, prefix string) (CompletionContext, string) {
	varStart := strings.Index(fullText, argTokens[0])
	if varStart < 0 {
		return ContextVariableList, lastSegment(prefix, '|')
	}
	textFromVars := fullText[varStart:]

	// Determine whether the cursor is currently inside an open quoted string
	// and how many complete quoted args precede it.
	insideQuote := isInsideQuotedArg(fullText)
	completedQuotes := countCompletedQuotedArgs(textFromVars)

	if insideQuote {
		switch completedQuotes {
		case 0:
			// Cursor is inside the first quoted arg. If the operator name is
			// already typed and followed by whitespace (e.g. `"@rx |`), the
			// cursor is in the operator ARGUMENT, not still selecting the
			// operator name.
			if openQuoteContent(textFromVars) != "" && inOperatorArg(openQuoteContent(textFromVars)) {
				return ContextOperatorArg, ""
			}
			// Otherwise the cursor is still selecting the @operator name.
			return ContextOperator, strings.TrimLeft(prefix, "! @")
		case 1:
			// Cursor is inside the second quoted arg → action list.
			return contextInActionList(prefix)
		}
		return ContextUnknown, prefix
	}

	// Cursor is not inside any quoted string.
	if completedQuotes == 0 {
		// Before any quoted arg → variable list.
		return ContextVariableList, lastSegment(prefix, '|')
	}
	return ContextUnknown, prefix
}

// openQuoteContent returns the text following the first '"' in s (the content of
// the currently-open quoted argument). Returns "" if there is no '"'.
func openQuoteContent(s string) string {
	i := strings.IndexByte(s, '"')
	if i < 0 {
		return ""
	}
	return s[i+1:]
}

// inOperatorArg reports whether the open-quote content is past the operator name
// (i.e. an optional '!', '@name', then whitespace) — meaning the cursor is in the
// operator argument rather than still typing the operator name.
func inOperatorArg(content string) bool {
	c := strings.TrimLeft(content, " \t")
	c = strings.TrimPrefix(c, "!")
	if !strings.HasPrefix(c, "@") {
		return false
	}
	c = c[1:]
	n := 0
	for n < len(c) {
		ch := c[n]
		isName := ch == '_' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')
		if !isName {
			break
		}
		n++
	}
	if n == 0 {
		return false // no operator name yet
	}
	// Operator name is followed by whitespace → we are in the argument.
	return n < len(c) && (c[n] == ' ' || c[n] == '\t')
}

// DetectContextInActionList detects completion context from the text of a
// single physical continuation line up to the cursor. It is used by the LSP
// server for multi-line SecRule action list lines where DetectContext cannot
// determine context from the line text alone (there is no directive keyword).
//
// lineBeforeCursor is the raw line text up to the cursor position. Leading
// whitespace, a possible opening '"' (first continuation line only), and a
// trailing '\' are stripped before analysis.
func DetectContextInActionList(lineBeforeCursor string) (CompletionContext, string) {
	// Strip leading whitespace and the optional opening " on the first
	// continuation line (e.g. `    "id:1,phase:2,`).
	trimmed := strings.TrimLeft(lineBeforeCursor, " \t")
	trimmed = strings.TrimPrefix(trimmed, "\"")
	// Strip trailing continuation marker / whitespace that comes before cursor.
	trimmed = strings.TrimRight(trimmed, " \t\\")
	return contextInActionList(trimmed)
}

// contextInActionList determines context within an action list string.
func contextInActionList(prefix string) (CompletionContext, string) {
	// Extract the current action "name" from the prefix.
	// prefix might be:  ""  |  "id"  |  "id:"  |  "t:"  |  "phase:"
	// Split at the last comma that is NOT inside a single-quoted string so that
	// action values like msg:'A,B' do not produce a false split point.
	actionFrag := strings.TrimLeft(lastActionFrag(prefix), " ")

	colonIdx := strings.Index(actionFrag, ":")
	if colonIdx < 0 {
		// No colon yet: completing action name.
		return ContextActionList, actionFrag
	}

	// Colon present: completing action value.
	actionName := strings.ToLower(actionFrag[:colonIdx])
	valuePart := actionFrag[colonIdx+1:]

	// Macro expansion takes priority: if the cursor is inside an unclosed %{...}
	// the user is typing a variable name in macro notation (e.g. TX.score).
	if macroPrefix, ok := extractMacroPrefix(valuePart); ok {
		return ContextMacroExpansion, macroPrefix
	}

	switch actionName {
	case "t":
		return ContextTransformation, valuePart
	case "phase":
		return ContextPhaseValue, valuePart
	case "severity":
		return ContextSeverityValue, valuePart
	case "skipafter":
		return ContextSkipAfterValue, valuePart
	case "setvar", "setenv", "expirevar":
		// Before =: completing the variable name — reuse macro notation (TX.key).
		// After =: value may contain macro expansions; the top-level macro check
		// above already handles %{... so here we just suppress generic completions.
		if eqIdx := strings.Index(valuePart, "="); eqIdx >= 0 {
			return ContextActionValue, valuePart[eqIdx+1:]
		}
		return ContextMacroExpansion, valuePart
	case "ctl":
		// ctl:KEY or ctl:KEY=VALUE — pass the full valuePart so the handler
		// can see both the key and the typed value prefix.
		if strings.Contains(valuePart, "=") {
			return ContextCtlValue, valuePart
		}
		return ContextCtlKey, valuePart
	default:
		return ContextActionValue, valuePart
	}
}

// lastActionFrag returns the last action fragment from an action list prefix,
// respecting single-quoted strings so that commas inside quoted values (e.g.
// msg:'A,B') do not produce a false split point.
func lastActionFrag(s string) string {
	inSingle := false
	lastComma := -1
	for i, r := range s {
		switch {
		case r == '\'' && !inSingle:
			inSingle = true
		case r == '\'' && inSingle:
			inSingle = false
		case r == ',' && !inSingle:
			lastComma = i
		}
	}
	if lastComma < 0 {
		return s
	}
	return s[lastComma+1:]
}

// tokenisePartial splits the partial line into whitespace-delimited tokens,
// treating double-quoted strings as single tokens.
//
// When the string ends inside an opened-but-not-yet-closed double-quoted argument
// that has no content yet (e.g. cursor right after the opening "), an empty string
// token is appended so that the context detection knows a new quoted argument has
// started even though nothing has been typed inside it.
func tokenisePartial(s string) []string {
	var tokens []string
	var cur strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"' && !inQuote:
			inQuote = true
			// Don't include the quote in the token — we track quoted regions separately.
		case r == '"' && inQuote:
			inQuote = false
			tokens = append(tokens, cur.String())
			cur.Reset()
		case (r == ' ' || r == '\t') && !inQuote:
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	} else if inQuote {
		// Cursor is inside a newly-opened quote with no content yet (e.g. `SecAction "`
		// or `SecRule ARGS "@rx x" "`). Emit an empty token so downstream context
		// detection sees the open quote as a distinct argument slot.
		tokens = append(tokens, "")
	}
	return tokens
}

// endsWithWS reports whether s ends with ASCII whitespace.
func endsWithWS(s string) bool {
	if s == "" {
		return false
	}
	last := s[len(s)-1]
	return last == ' ' || last == '\t'
}

// countCompletedQuotedArgs counts the number of complete double-quoted strings
// in s (i.e., strings that have been opened and closed).
func countCompletedQuotedArgs(s string) int {
	count := 0
	inQuote := false
	escaped := false
	for _, r := range s {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == '"' {
			if inQuote {
				inQuote = false
				count++
			} else {
				inQuote = true
			}
		}
	}
	return count
}

// isInsideQuotedArg reports whether the cursor (end of s) is currently inside
// a double-quoted string.
func isInsideQuotedArg(s string) bool {
	inQuote := false
	escaped := false
	for _, r := range s {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == '"' {
			inQuote = !inQuote
		}
	}
	return inQuote
}

// lastSegment returns the portion of s after the last occurrence of sep.
// If sep is not found, returns s.
func lastSegment(s string, sep rune) string {
	idx := strings.LastIndexByte(s, byte(sep))
	if idx < 0 {
		return s
	}
	return s[idx+1:]
}

// extractMacroPrefix detects whether s ends inside an unclosed %{...} macro
// expression. Returns the text typed after %{ and true when found, otherwise
// returns "", false.
func extractMacroPrefix(s string) (string, bool) {
	// Scan for the rightmost %{ — a later one supersedes an earlier one.
	start := -1
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '%' && s[i+1] == '{' {
			start = i + 2 // index of first char after %{
		}
	}
	if start < 0 {
		return "", false
	}
	// The macro is only "open" when there is no closing } from start to end.
	if strings.ContainsRune(s[start:], '}') {
		return "", false
	}
	return s[start:], true
}

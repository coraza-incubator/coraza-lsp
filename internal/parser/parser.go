// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"strings"
	"unicode/utf8"
)

// Parse parses a SecLang source file into an AST.
// It always returns a *File; errors are attached to both the file and individual nodes.
// The parser is tolerant: errors on one line do not prevent parsing subsequent lines.
func Parse(uri, source string) *File {
	l := NewLexer(source)
	tokens := l.Tokenize()
	return parseTokens(uri, tokens)
}

// parseTokens groups tokens by logical directive and builds the AST.
func parseTokens(uri string, tokens []Token) *File {
	file := &File{URI: uri}

	// Group tokens by directive line.
	groups := groupTokens(tokens)

	for _, group := range groups {
		if len(group) == 0 {
			continue
		}
		first := group[0]

		// Comment node.
		if first.Type == TokenComment {
			startLine := first.Line
			file.Nodes = append(file.Nodes, &CommentNode{
				baseNode: baseNode{
					kind: NodeKindComment,
					nodeRange: Range{
						Start: Position{Line: startLine, Character: 0},
						End:   Position{Line: startLine, Character: first.EndChar},
					},
				},
				Text: first.Value,
			})
			continue
		}

		// Directive node.
		if first.Type != TokenDirective {
			continue
		}

		node := parseDirectiveGroup(group)
		file.Nodes = append(file.Nodes, node)

		// Collect parse errors from rule nodes and generic directive nodes into the file.
		if r, ok := node.(*RuleNode); ok {
			file.Errors = append(file.Errors, r.ParseErrors...)
		}
		if g, ok := node.(*GenericDirectiveNode); ok {
			file.Errors = append(file.Errors, g.ParseErrors...)
		}
	}

	// Post-process: resolve chain relationships.
	// When a SecRule has a "chain" action the immediately following SecRule
	// (skipping comments) is a chained rule and does not need its own id or phase.
	// Chains can nest arbitrarily: a chained rule that also has "chain" makes the
	// one after it chained too.
	chainActive := false
	for _, node := range file.Nodes {
		switch n := node.(type) {
		case *CommentNode:
			// Comments do not break chains.
		case *RuleNode:
			if chainActive {
				n.IsChained = true
			}
			// If this rule has "chain" (regardless of whether it is itself chained)
			// the next rule is chained.
			chainActive = n.FindAction("chain") != nil
		default:
			// Any other directive breaks the chain.
			chainActive = false
		}
	}

	return file
}

// groupTokens groups the flat token stream into per-directive slices.
// Each group starts with a TokenDirective or TokenComment.
func groupTokens(tokens []Token) [][]Token {
	var groups [][]Token
	var current []Token

	for _, tok := range tokens {
		if tok.Type == TokenDirective || tok.Type == TokenComment {
			if len(current) > 0 {
				groups = append(groups, current)
			}
			current = []Token{tok}
		} else if len(current) > 0 {
			current = append(current, tok)
		}
	}
	if len(current) > 0 {
		groups = append(groups, current)
	}
	return groups
}

// parseDirectiveGroup parses a group of tokens starting with a directive token
// into the appropriate AST node type.
func parseDirectiveGroup(group []Token) Node {
	directive := group[0]
	lower := strings.ToLower(directive.Value)

	// Compute the full range of this directive.
	fullRange := directiveRange(group)
	nameRange := Range{
		Start: Position{Line: directive.Line, Character: directive.StartChar},
		End:   Position{Line: directive.Line, Character: directive.EndChar},
	}
	switch lower {
	case "secrule", "secaction", "secdefaultaction":
		return parseRuleDirective(lower, group, fullRange, nameRange)
	case "secmarker":
		return parseMarkerDirective(group, fullRange, nameRange)
	case "include":
		return parseIncludeDirective(group, fullRange, nameRange)
	default:
		argToks := collectArgTokens(group[1:])
		var args []string
		var parseErrs []ParseError
		for _, t := range argToks {
			args = append(args, t.Value)
			if t.Unclosed {
				parseErrs = append(parseErrs, unclosedStringError(t))
			}
		}
		return &GenericDirectiveNode{
			baseNode:    baseNode{kind: NodeKindGenericDirective, nodeRange: fullRange},
			Name:        directive.Value,
			NameRange:   nameRange,
			Args:        args,
			ArgTokens:   argToks,
			ParseErrors: parseErrs,
		}
	}
}

// parseRuleDirective builds a RuleNode from a directive group.
func parseRuleDirective(lower string, group []Token, fullRange, nameRange Range) *RuleNode {
	var kind NodeKind
	switch lower {
	case "secrule":
		kind = NodeKindSecRule
	case "secaction":
		kind = NodeKindSecAction
	default:
		kind = NodeKindSecDefaultAction
	}

	rule := &RuleNode{
		baseNode:  baseNode{kind: kind, nodeRange: fullRange},
		Directive: lower,
		NameRange: nameRange,
	}

	// Collect argument tokens (TokenWord and TokenQuoted after the directive).
	args := collectArgTokens(group[1:])

	// Pre-scan: report every unclosed quoted string in the arg list, regardless
	// of position. This catches stray lone `"` tokens that appear as extra args
	// beyond the expected count (e.g. trailing `""` after the action list).
	for _, arg := range args {
		if arg.Unclosed {
			rule.ParseErrors = append(rule.ParseErrors, unclosedStringError(arg))
		}
	}

	switch lower {
	case "secrule":
		// SecRule takes: VARIABLES  @OPERATOR_ARG  ACTION_LIST
		// The variable list is always unquoted. Operator arg and action list are quoted.
		if len(args) >= 1 {
			varTok := args[0]
			rule.VariablesRange = tokenRange(varTok)
			varOffset := Position{Line: varTok.Line, Character: varTok.StartChar}
			vars, varErrs := ParseVariables(varTok.Value, varOffset)
			rule.Variables = vars
			rule.ParseErrors = append(rule.ParseErrors, varErrs...)
		}
		if len(args) >= 2 {
			opTok := args[1]
			if !opTok.Unclosed {
				rule.OperatorRange = tokenRange(opTok)
				opOffset := Position{Line: opTok.Line, Character: opTok.StartChar + 1} // +1 skip leading "
				op, opErr := parseOperator(opTok.Value, opOffset, opTok.Line)
				if opErr != nil {
					rule.ParseErrors = append(rule.ParseErrors, *opErr)
				} else {
					rule.Operator = &op
				}
			}
		}
		if len(args) >= 3 {
			actTok := args[2]
			// Always set ActionsRange so ContainsPosition works for completions
			// and hover even when the user is actively typing (unclosed token).
			rule.ActionsRange = tokenRange(actTok)
			if !actTok.Unclosed {
				actions, _ := parseActions(actTok.Value, actTok)
				rule.Actions = actions
			}
		}
	case "secaction", "secdefaultaction":
		// SecAction / SecDefaultAction take a single quoted action list.
		if len(args) >= 1 {
			actTok := args[0]
			rule.ActionsRange = tokenRange(actTok)
			if !actTok.Unclosed {
				actions, _ := parseActions(actTok.Value, actTok)
				rule.Actions = actions
			}
		}
	}

	return rule
}

// parseOperator parses the operator argument (the content of the second quoted
// string in a SecRule directive). Examples:
//
//	@rx pattern        → OperatorExpr{Name:"rx", Argument:"pattern"}
//	!@pm word1 word2   → OperatorExpr{Negated:true, Name:"pm", Argument:"word1 word2"}
//	@detectSQLi        → OperatorExpr{Name:"detectSQLi"}
func parseOperator(s string, start Position, line int) (OperatorExpr, *ParseError) {
	op := OperatorExpr{}
	s = strings.TrimSpace(s)
	pos := 0

	if pos < len(s) && s[pos] == '!' {
		op.Negated = true
		pos++
	}

	if pos >= len(s) || s[pos] != '@' {
		// No @ prefix: treat whole string as a regex pattern (implicit @rx).
		op.Name = "rx"
		op.Argument = s[pos:]
		endChar := start.Character + utf8.RuneCountInString(s)
		op.Range = Range{Start: start, End: Position{Line: line, Character: endChar}}
		op.NameRange = op.Range
		return op, nil
	}
	pos++ // skip @

	// Operator name: letters and digits.
	nameStart := pos
	for pos < len(s) && (isAlpha(s[pos]) || isDigit(s[pos])) {
		pos++
	}
	op.Name = s[nameStart:pos]
	if op.Name == "" {
		return op, &ParseError{
			Message: "expected operator name after @",
			Range: Range{
				Start: start,
				End:   Position{Line: line, Character: start.Character + utf8.RuneCountInString(s)},
			},
		}
	}

	// Operator name range (relative to start).
	negOffset := 0
	if op.Negated {
		negOffset = 1
	}
	nameRuneLen := utf8.RuneCountInString(op.Name)
	op.NameRange = Range{
		Start: Position{Line: line, Character: start.Character + negOffset + 1}, // +1 for @
		End:   Position{Line: line, Character: start.Character + negOffset + 1 + nameRuneLen},
	}

	// Optional argument (rest of string after whitespace).
	if pos < len(s) && isWS(s[pos]) {
		pos++ // skip one space
	}
	op.Argument = s[pos:]

	endChar := start.Character + utf8.RuneCountInString(s)
	op.Range = Range{Start: start, End: Position{Line: line, Character: endChar}}

	return op, nil
}

func parseMarkerDirective(group []Token, fullRange, nameRange Range) *MarkerNode {
	args := collectArgTokens(group[1:])
	markerID := ""
	if len(args) > 0 {
		markerID = args[0].Value
	}
	directive := group[0].Value
	return &MarkerNode{
		baseNode:  baseNode{kind: NodeKindSecMarker, nodeRange: fullRange},
		Name:      directive,
		NameRange: nameRange,
		MarkerID:  markerID,
	}
}

func parseIncludeDirective(group []Token, fullRange, nameRange Range) *IncludeNode {
	args := collectArgTokens(group[1:])
	path := ""
	if len(args) > 0 {
		path = args[0].Value
	}
	directive := group[0].Value
	return &IncludeNode{
		baseNode:  baseNode{kind: NodeKindInclude, nodeRange: fullRange},
		Name:      directive,
		NameRange: nameRange,
		Path:      path,
	}
}

// collectArgTokens returns all non-directive tokens from a group.
func collectArgTokens(tokens []Token) []Token {
	var args []Token
	for _, t := range tokens {
		if t.Type == TokenWord || t.Type == TokenQuoted {
			args = append(args, t)
		}
	}
	return args
}


// directiveRange computes the Range covering all tokens in a group.
func directiveRange(group []Token) Range {
	if len(group) == 0 {
		return Range{}
	}
	first := group[0]
	last := group[len(group)-1]
	return Range{
		Start: Position{Line: first.Line, Character: first.StartChar},
		End:   Position{Line: tokenEndLine(last), Character: last.EndChar},
	}
}

// tokenRange converts a Token to a Range.
func tokenRange(t Token) Range {
	return Range{
		Start: Position{Line: t.Line, Character: t.StartChar},
		End:   Position{Line: tokenEndLine(t), Character: t.EndChar},
	}
}

// tokenEndLine returns the physical end line of a token.
// For single-line tokens EndLine is 0 (meaning same as Line).
func tokenEndLine(t Token) int {
	if t.EndLine > 0 {
		return t.EndLine
	}
	return t.Line
}

// unclosedStringError returns a ParseError for a TokenQuoted with no closing ".
func unclosedStringError(tok Token) ParseError {
	return ParseError{
		Message: `unclosed string literal: missing closing "`,
		Range: Range{
			Start: Position{Line: tok.Line, Character: tok.StartChar},
			End:   Position{Line: tok.Line, Character: tok.EndChar},
		},
	}
}

func isAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

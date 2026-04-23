// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package parser

// Position is a 0-indexed line+character offset, matching the LSP protocol.
type Position struct {
	Line      int
	Character int
}

// Range spans from Start (inclusive) to End (exclusive).
type Range struct {
	Start Position
	End   Position
}

// ContainsPosition reports whether the range contains the given position.
// The end position is inclusive for the last character.
func (r Range) ContainsPosition(line, char int) bool {
	if line < r.Start.Line || line > r.End.Line {
		return false
	}
	if line == r.Start.Line && char < r.Start.Character {
		return false
	}
	if line == r.End.Line && char > r.End.Character {
		return false
	}
	return true
}

// NodeKind classifies AST nodes.
type NodeKind int

const (
	NodeKindComment          NodeKind = iota
	NodeKindSecRule                   // SecRule directive
	NodeKindSecAction                 // SecAction directive
	NodeKindSecDefaultAction          // SecDefaultAction directive
	NodeKindSecMarker                 // SecMarker directive
	NodeKindInclude                   // Include directive
	NodeKindGenericDirective          // Any other recognized-or-unrecognized directive
)

// Node is the interface implemented by all AST nodes.
type Node interface {
	GetKind() NodeKind
	GetRange() Range
}

// baseNode is embedded in all concrete node types.
type baseNode struct {
	kind      NodeKind
	nodeRange Range
}

func (b *baseNode) GetKind() NodeKind { return b.kind }
func (b *baseNode) GetRange() Range   { return b.nodeRange }

// CommentNode represents a comment line.
type CommentNode struct {
	baseNode
	Text string
}

// GenericDirectiveNode represents a directive that is not specifically parsed.
type GenericDirectiveNode struct {
	baseNode
	Name      string
	NameRange Range
	// Args contains the string value of each argument token.
	Args []string
	// ArgTokens contains the raw Token for each argument, preserving metadata
	// such as whether a quoted string was properly closed.
	ArgTokens []Token
	// ParseErrors are errors encountered while pre-validating argument tokens
	// (e.g. unclosed quoted strings).
	ParseErrors []ParseError
}

// RuleNode represents a SecRule, SecAction, or SecDefaultAction directive.
// For SecAction/SecDefaultAction, Variables and Operator are empty/nil.
type RuleNode struct {
	baseNode
	// Directive is the lowercase directive name: "secrule", "secaction", "secdefaultaction".
	Directive string
	// NameRange is the range of the directive name token.
	NameRange Range

	// Variables is the parsed variable list (SecRule only).
	Variables []VariableExpr
	// VariablesRange is the range of the entire variable list argument.
	VariablesRange Range

	// Operator is the parsed operator expression (SecRule only; nil if not present).
	Operator *OperatorExpr
	// OperatorRange is the range of the operator argument.
	OperatorRange Range

	// Actions is the parsed action list.
	Actions []ActionExpr
	// ActionsRange is the range of the action list argument (the quoted string).
	ActionsRange Range

	// ParseErrors are errors collected while parsing this node's sub-components.
	ParseErrors []ParseError

	// IsChained is true when this rule is a continuation in a chain — i.e., the
	// immediately preceding SecRule had the "chain" action. Chained rules do not
	// require their own id or phase; they inherit them from the base rule.
	IsChained bool
}

// FindAction returns the first action with the given lowercase name, or nil.
func (r *RuleNode) FindAction(name string) *ActionExpr {
	for i := range r.Actions {
		if r.Actions[i].LowerName() == name {
			return &r.Actions[i]
		}
	}
	return nil
}

// MarkerNode represents a SecMarker directive.
type MarkerNode struct {
	baseNode
	Name      string // directive name
	NameRange Range
	// MarkerID is the marker label.
	MarkerID string
}

// IncludeNode represents an Include directive.
type IncludeNode struct {
	baseNode
	Name      string
	NameRange Range
	// Path is the file path or glob pattern.
	Path string
}

// VariableExpr is a single variable expression within a SecRule variable list.
type VariableExpr struct {
	// Negated is true when the variable is prefixed with !.
	Negated bool
	// Count is true when the variable is prefixed with &.
	Count bool
	// Name is the uppercase variable name (e.g. "ARGS", "REQUEST_HEADERS").
	Name string
	// Key is the optional collection key (e.g. "user-agent" from REQUEST_HEADERS:user-agent).
	Key string
	// KeyIsRegex is true when the key is a /regex/ pattern.
	KeyIsRegex bool
	// Range covers the entire variable expression in the source.
	Range Range
}

// OperatorExpr is the operator portion of a SecRule.
type OperatorExpr struct {
	// Negated is true when the operator is prefixed with !.
	Negated bool
	// Name is the operator name without the @ prefix (e.g. "rx", "pm").
	Name string
	// Argument is the operator's argument string.
	Argument string
	// Range covers the entire "@name argument" in the source.
	Range Range
	// NameRange covers just the "@name" portion.
	NameRange Range
}

// ActionExpr is a single action within an action list.
type ActionExpr struct {
	// Name is the action name as written (e.g. "id", "phase", "msg", "t").
	Name string
	// Value is the action's value (after the colon), empty for value-less actions.
	Value string
	// HasColon is true when a colon was present (distinguishes "pass" from "t:").
	HasColon bool
	// Range covers the full "name:value" or "name" in the source.
	Range Range
}

// LowerName returns the lowercased action name.
func (a ActionExpr) LowerName() string {
	name := a.Name
	result := make([]byte, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		result[i] = c
	}
	return string(result)
}

// ParseError is a parse-time error with position information.
type ParseError struct {
	Message string
	Range   Range
}

// File is the top-level AST node representing a complete SecLang source file.
type File struct {
	// URI is the document URI (may be empty for in-memory parsing).
	URI string
	// Nodes is the ordered list of top-level nodes.
	Nodes []Node
	// Errors is the list of parse errors encountered.
	Errors []ParseError
}

// AllRules returns all SecRule, SecAction, and SecDefaultAction nodes.
func (f *File) AllRules() []*RuleNode {
	var rules []*RuleNode
	for _, n := range f.Nodes {
		if r, ok := n.(*RuleNode); ok {
			rules = append(rules, r)
		}
	}
	return rules
}

// AllMarkers returns all SecMarker nodes.
func (f *File) AllMarkers() []*MarkerNode {
	var markers []*MarkerNode
	for _, n := range f.Nodes {
		if m, ok := n.(*MarkerNode); ok {
			markers = append(markers, m)
		}
	}
	return markers
}

// FindMarker returns the first SecMarker with the given ID, or nil.
func (f *File) FindMarker(id string) *MarkerNode {
	for _, m := range f.AllMarkers() {
		if m.MarkerID == id {
			return m
		}
	}
	return nil
}

// NodeAtPosition returns the deepest node whose range contains (line, char).
func (f *File) NodeAtPosition(line, char int) Node {
	for _, n := range f.Nodes {
		if n.GetRange().ContainsPosition(line, char) {
			return n
		}
	}
	return nil
}

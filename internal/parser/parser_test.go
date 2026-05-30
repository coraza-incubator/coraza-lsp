// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse_Empty(t *testing.T) {
	t.Parallel()
	f := Parse("", "")
	assert.Empty(t, f.Nodes)
	assert.Empty(t, f.Errors)
}

func TestParse_CommentOnly(t *testing.T) {
	t.Parallel()
	f := Parse("", "# just a comment")
	require.Len(t, f.Nodes, 1)
	comment, ok := f.Nodes[0].(*CommentNode)
	require.True(t, ok)
	assert.Contains(t, comment.Text, "just a comment")
}

func TestParse_SecRuleBasic(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx <script" "id:1001,phase:2,deny"`
	f := Parse("test.conf", src)
	require.Len(t, f.Nodes, 1)
	rule, ok := f.Nodes[0].(*RuleNode)
	require.True(t, ok)
	assert.Equal(t, NodeKindSecRule, rule.GetKind())
	assert.Equal(t, "secrule", rule.Directive)

	// Variables.
	require.Len(t, rule.Variables, 1)
	assert.Equal(t, "ARGS", rule.Variables[0].Name)
	assert.False(t, rule.Variables[0].Negated)
	assert.False(t, rule.Variables[0].Count)

	// Operator.
	require.NotNil(t, rule.Operator)
	assert.Equal(t, "rx", rule.Operator.Name)
	assert.Equal(t, "<script", rule.Operator.Argument)
	assert.False(t, rule.Operator.Negated)

	// Actions.
	assert.NotEmpty(t, rule.Actions)
	idAction := rule.FindAction("id")
	require.NotNil(t, idAction)
	assert.Equal(t, "1001", idAction.Value)

	phaseAction := rule.FindAction("phase")
	require.NotNil(t, phaseAction)
	assert.Equal(t, "2", phaseAction.Value)
}

func TestParse_SecAction(t *testing.T) {
	t.Parallel()
	src := `SecAction "id:1000,phase:1,pass,nolog"`
	f := Parse("", src)
	require.Len(t, f.Nodes, 1)
	rule, ok := f.Nodes[0].(*RuleNode)
	require.True(t, ok)
	assert.Equal(t, NodeKindSecAction, rule.GetKind())
	assert.Nil(t, rule.Operator)
	assert.Empty(t, rule.Variables)
	assert.NotEmpty(t, rule.Actions)
}

func TestParse_SecMarker(t *testing.T) {
	t.Parallel()
	src := "SecMarker END_DETECTION"
	f := Parse("", src)
	require.Len(t, f.Nodes, 1)
	marker, ok := f.Nodes[0].(*MarkerNode)
	require.True(t, ok)
	assert.Equal(t, "END_DETECTION", marker.MarkerID)
}

func TestParse_Include(t *testing.T) {
	t.Parallel()
	src := "Include /etc/coraza/rules/*.conf"
	f := Parse("", src)
	require.Len(t, f.Nodes, 1)
	inc, ok := f.Nodes[0].(*IncludeNode)
	require.True(t, ok)
	assert.Equal(t, "/etc/coraza/rules/*.conf", inc.Path)
}

func TestParse_MultipleVariables(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS|REQUEST_HEADERS:User-Agent "@rx test" "id:1,phase:2,deny"`
	f := Parse("", src)
	require.Len(t, f.Nodes, 1)
	rule := f.Nodes[0].(*RuleNode)
	require.Len(t, rule.Variables, 2)
	assert.Equal(t, "ARGS", rule.Variables[0].Name)
	assert.Equal(t, "REQUEST_HEADERS", rule.Variables[1].Name)
	assert.Equal(t, "User-Agent", rule.Variables[1].Key)
}

func TestParse_NegatedVariable(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS|!ARGS:safe "@rx test" "id:1,phase:2,deny"`
	f := Parse("", src)
	rule := f.Nodes[0].(*RuleNode)
	require.Len(t, rule.Variables, 2)
	assert.False(t, rule.Variables[0].Negated)
	assert.True(t, rule.Variables[1].Negated)
	assert.Equal(t, "ARGS", rule.Variables[1].Name)
	assert.Equal(t, "safe", rule.Variables[1].Key)
}

func TestParse_CountVariable(t *testing.T) {
	t.Parallel()
	src := `SecRule &ARGS "@gt 100" "id:1,phase:2,deny"`
	f := Parse("", src)
	rule := f.Nodes[0].(*RuleNode)
	require.Len(t, rule.Variables, 1)
	assert.True(t, rule.Variables[0].Count)
}

func TestParse_NegatedOperator(t *testing.T) {
	t.Parallel()
	src := `SecRule REQUEST_METHOD "!@within GET POST" "id:1,phase:1,deny"`
	f := Parse("", src)
	rule := f.Nodes[0].(*RuleNode)
	require.NotNil(t, rule.Operator)
	assert.True(t, rule.Operator.Negated)
	assert.Equal(t, "within", rule.Operator.Name)
	assert.Equal(t, "GET POST", rule.Operator.Argument)
}

func TestParse_ImplicitRxOperator(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "union select" "id:1,phase:2,deny"`
	f := Parse("", src)
	rule := f.Nodes[0].(*RuleNode)
	require.NotNil(t, rule.Operator)
	assert.Equal(t, "rx", rule.Operator.Name)
	assert.Equal(t, "union select", rule.Operator.Argument)
}

func TestParse_ActionWithSingleQuotedValue(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx test" "id:1,phase:2,deny,msg:'SQL injection attempt'"`
	f := Parse("", src)
	rule := f.Nodes[0].(*RuleNode)
	msgAction := rule.FindAction("msg")
	require.NotNil(t, msgAction)
	assert.Equal(t, "SQL injection attempt", msgAction.Value)
}

func TestParse_ActionWithCommaInValue(t *testing.T) {
	t.Parallel()
	// msg value contains a comma inside single quotes.
	src := `SecRule ARGS "@rx test" "id:1,phase:2,deny,msg:'a, b, c'"`
	f := Parse("", src)
	rule := f.Nodes[0].(*RuleNode)
	msgAction := rule.FindAction("msg")
	require.NotNil(t, msgAction)
	assert.Equal(t, "a, b, c", msgAction.Value)
}

func TestParse_TransformationActions(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx test" "id:1,phase:2,deny,t:none,t:lowercase,t:urlDecode"`
	f := Parse("", src)
	rule := f.Nodes[0].(*RuleNode)
	tActions := filterActionsByName(rule.Actions, "t")
	assert.Len(t, tActions, 3)
	values := []string{tActions[0].Value, tActions[1].Value, tActions[2].Value}
	assert.Contains(t, values, "none")
	assert.Contains(t, values, "lowercase")
	assert.Contains(t, values, "urlDecode")
}

func TestParse_SetvarAction(t *testing.T) {
	t.Parallel()
	src := `SecAction "id:100,phase:1,pass,setvar:TX.score=+5"`
	f := Parse("", src)
	rule := f.Nodes[0].(*RuleNode)
	sv := rule.FindAction("setvar")
	require.NotNil(t, sv)
	assert.Equal(t, "TX.score=+5", sv.Value)
}

func TestParse_GenericDirective(t *testing.T) {
	t.Parallel()
	src := "SecRuleEngine DetectionOnly"
	f := Parse("", src)
	require.Len(t, f.Nodes, 1)
	gen, ok := f.Nodes[0].(*GenericDirectiveNode)
	require.True(t, ok)
	assert.Equal(t, "SecRuleEngine", gen.Name)
	require.Len(t, gen.Args, 1)
	assert.Equal(t, "DetectionOnly", gen.Args[0])
}

func TestParse_MultipleRules(t *testing.T) {
	t.Parallel()
	src := "# Config\nSecRuleEngine On\nSecRule ARGS \"@rx test\" \"id:1,phase:2,deny\"\nSecMarker END"
	f := Parse("", src)
	assert.Len(t, f.Nodes, 4)
}

func TestParse_NodeRangesBasic(t *testing.T) {
	t.Parallel()
	src := "SecRuleEngine On"
	f := Parse("", src)
	require.Len(t, f.Nodes, 1)
	r := f.Nodes[0].GetRange()
	assert.Equal(t, 0, r.Start.Line)
	assert.Equal(t, 0, r.Start.Character)
}

func TestParse_AllRules(t *testing.T) {
	t.Parallel()
	src := "SecAction \"id:1,phase:1,pass\"\nSecRule ARGS \"@rx x\" \"id:2,phase:2,deny\"\nSecDefaultAction \"phase:2,deny\""
	f := Parse("", src)
	rules := f.AllRules()
	assert.Len(t, rules, 3)
}

func TestParse_AllMarkers(t *testing.T) {
	t.Parallel()
	src := "SecMarker BEGIN\nSecRule ARGS \"@rx x\" \"id:1,phase:2,deny\"\nSecMarker END"
	f := Parse("", src)
	markers := f.AllMarkers()
	assert.Len(t, markers, 2)
	assert.Equal(t, "BEGIN", markers[0].MarkerID)
	assert.Equal(t, "END", markers[1].MarkerID)
}

func TestParse_FindMarker(t *testing.T) {
	t.Parallel()
	src := "SecMarker BEGIN_CHECKS\nSecMarker END_CHECKS"
	f := Parse("", src)
	m := f.FindMarker("BEGIN_CHECKS")
	require.NotNil(t, m)
	assert.Equal(t, "BEGIN_CHECKS", m.MarkerID)

	assert.Nil(t, f.FindMarker("NONEXISTENT"))
}

func TestParse_NodeAtPosition(t *testing.T) {
	t.Parallel()
	src := "SecRuleEngine On\nSecRequestBodyAccess On"
	f := Parse("", src)
	// Position on line 1 should find the second directive.
	node := f.NodeAtPosition(1, 0)
	require.NotNil(t, node)
	gen := node.(*GenericDirectiveNode)
	assert.Equal(t, "SecRequestBodyAccess", gen.Name)
}

func TestParse_ContinuationLines(t *testing.T) {
	t.Parallel()
	src := "SecRule ARGS \\\n\"@rx test\" \\\n\"id:1,phase:2,deny\""
	f := Parse("", src)
	require.Len(t, f.Nodes, 1)
	rule, ok := f.Nodes[0].(*RuleNode)
	require.True(t, ok)
	require.NotNil(t, rule.Operator)
	assert.Equal(t, "rx", rule.Operator.Name)
}

func TestParse_ToleratesPartialInput(t *testing.T) {
	t.Parallel()
	// Incomplete SecRule should not panic; should produce a node (possibly partial).
	src := "SecRule "
	f := Parse("", src)
	assert.NotNil(t, f)
	// No panics — that's the key requirement.
}

func TestParse_ToleratesBadLine(t *testing.T) {
	t.Parallel()
	// A bad line followed by a good one — the good one should parse correctly.
	src := "BrokenDirective\nSecRuleEngine On"
	f := Parse("", src)
	assert.Len(t, f.Nodes, 2)
	gen := f.Nodes[1].(*GenericDirectiveNode)
	assert.Equal(t, "SecRuleEngine", gen.Name)
}

// ----------------------------------------------------------------------------
// Group 1: SecRule wrong argument counts
// Why: users forget args, reorder them, or paste extras. The parser must
// tolerate every count gracefully — no panics, defined behavior for each case.
// ----------------------------------------------------------------------------

func TestParse_SecRuleArgumentCounts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		src           string
		wantVars      bool // expect variables parsed
		wantOp        bool // expect operator parsed
		wantActions   bool // expect actions parsed
		wantParseErr  bool // expect a parse error
	}{
		{
			// 0 args: just the directive keyword
			name:        "0 args — only directive",
			src:         "SecRule",
			wantVars:    false,
			wantOp:      false,
			wantActions: false,
		},
		{
			// 1 arg: variable list only, no operator or actions
			name:        "1 arg — variables only",
			src:         "SecRule ARGS",
			wantVars:    true,
			wantOp:      false,
			wantActions: false,
		},
		{
			// 2 args: variable + operator but no action list
			name:        "2 args — variables and operator, no actions",
			src:         `SecRule ARGS "@rx test"`,
			wantVars:    true,
			wantOp:      true,
			wantActions: false,
		},
		{
			// 4th arg is a properly closed quoted string — silently ignored,
			// no parse error, the rule parses correctly from args 0-2.
			name:        "4 args — extra closed quoted arg is silently ignored",
			src:         `SecRule ARGS "@rx test" "id:1,phase:2,deny" "extra"`,
			wantVars:    true,
			wantOp:      true,
			wantActions: true,
			wantParseErr: false,
		},
		{
			// 4th arg is an UNCLOSED quoted string — the pre-scan catches it
			// and fires a parse error even though it's beyond arg[2].
			name:        "4 args — extra unclosed quoted arg fires parse-error",
			src:         `SecRule ARGS "@rx test" "id:1,phase:2,deny" "extra`,
			wantVars:    true,
			wantOp:      true,
			wantActions: true,
			wantParseErr: true,
		},
		{
			// 4th arg is an unquoted word — silently ignored (word beyond arg[2]).
			name:        "4 args — extra unquoted word is silently ignored",
			src:         `SecRule ARGS "@rx test" "id:1,phase:2,deny" extra_word`,
			wantVars:    true,
			wantOp:      true,
			wantActions: true,
			wantParseErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := Parse("", tt.src)
			require.Len(t, f.Nodes, 1, "should always produce exactly one node")
			rule, ok := f.Nodes[0].(*RuleNode)
			require.True(t, ok)

			if tt.wantVars {
				assert.NotEmpty(t, rule.Variables, "expected variables to be parsed")
			} else {
				assert.Empty(t, rule.Variables, "expected no variables")
			}
			if tt.wantOp {
				assert.NotNil(t, rule.Operator, "expected operator to be parsed")
			} else {
				assert.Nil(t, rule.Operator, "expected no operator")
			}
			if tt.wantActions {
				assert.NotNil(t, rule.Actions, "expected actions to be parsed")
			} else {
				assert.Nil(t, rule.Actions, "expected no actions")
			}
			if tt.wantParseErr {
				assert.NotEmpty(t, rule.ParseErrors, "expected a parse error")
			} else {
				assert.Empty(t, rule.ParseErrors, "expected no parse errors")
			}
		})
	}
}

// ----------------------------------------------------------------------------
// Group 2: Operator edge cases
// Why: @ is an easy typo target — users forget the name, add spaces after @,
// or write just ! without @. The operator parser must report errors precisely.
// ----------------------------------------------------------------------------

func TestParse_OperatorEdgeCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		src          string
		wantParseErr bool
		wantOpName   string // expected operator name when no error
		wantNegated  bool
		wantArgument string
	}{
		{
			// @ alone — no operator name follows
			name:         "@ alone — expected operator name after @",
			src:          `SecRule ARGS "@" "id:1,phase:2,deny"`,
			wantParseErr: true,
		},
		{
			// Space immediately after @ — operator name is empty
			name:         "@ followed by space — empty operator name",
			src:          `SecRule ARGS "@ rx test" "id:1,phase:2,deny"`,
			wantParseErr: true,
		},
		{
			// !@ with no name — negated but no operator name
			name:         "!@ alone — expected operator name after @",
			src:          `SecRule ARGS "!@" "id:1,phase:2,deny"`,
			wantParseErr: true,
		},
		{
			// Just ! with no @ — treated as implicit @rx with negated flag
			// The ! is consumed as negation; remaining argument string is empty.
			name:         "! alone — implicit @rx negated, empty argument",
			src:          `SecRule ARGS "!" "id:1,phase:2,deny"`,
			wantParseErr: false,
			wantOpName:   "rx",
			wantNegated:  true,
			wantArgument: "",
		},
		{
			// Unknown operator name — Stage 1 does not validate operator names,
			// only Coraza (Stage 2) does. So this must parse without errors.
			name:         "unknown operator name — no parse error at Stage 1",
			src:          `SecRule ARGS "@unknownOp test" "id:1,phase:2,deny"`,
			wantParseErr: false,
			wantOpName:   "unknownOp",
			wantArgument: "test",
		},
		{
			// Valid operator with argument — sanity check
			name:         "valid @rx operator",
			src:          `SecRule ARGS "@rx test" "id:1,phase:2,deny"`,
			wantParseErr: false,
			wantOpName:   "rx",
			wantArgument: "test",
		},
		{
			// Negated valid operator
			name:         "negated !@rx operator",
			src:          `SecRule ARGS "!@rx test" "id:1,phase:2,deny"`,
			wantParseErr: false,
			wantOpName:   "rx",
			wantNegated:  true,
			wantArgument: "test",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := Parse("", tt.src)
			require.Len(t, f.Nodes, 1)
			rule := f.Nodes[0].(*RuleNode)

			if tt.wantParseErr {
				assert.NotEmpty(t, rule.ParseErrors, "expected a parse error")
			} else {
				assert.Empty(t, rule.ParseErrors, "expected no parse errors")
				if tt.wantOpName != "" {
					require.NotNil(t, rule.Operator)
					assert.Equal(t, tt.wantOpName, rule.Operator.Name)
					assert.Equal(t, tt.wantNegated, rule.Operator.Negated)
					assert.Equal(t, tt.wantArgument, rule.Operator.Argument)
				}
			}
		})
	}
}

// ----------------------------------------------------------------------------
// Group 3: Variable list edge cases
// Why: pipe-separated lists have degenerate forms (leading, trailing, doubled
// pipes) and bare prefix characters (!, &) that must not crash or panic.
// ----------------------------------------------------------------------------

func TestParse_VariableListEdgeCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		varStr       string  // variable string passed to parseVariables
		wantCount    int     // number of VariableExpr expected
		wantErrPart  string  // substring of expected parse error, or "" for none
	}{
		{
			// Trailing pipe — empty segment at end is silently skipped
			name:      "trailing pipe — one variable",
			varStr:    "ARGS|",
			wantCount: 1,
		},
		{
			// Leading pipe — empty segment at start is silently skipped
			name:      "leading pipe — one variable",
			varStr:    "|ARGS",
			wantCount: 1,
		},
		{
			// Double pipe — empty middle segment skipped, two variables remain
			name:      "double pipe — two variables",
			varStr:    "ARGS||FILES",
			wantCount: 2,
		},
		{
			// Bare ! with no variable name — should produce parse error
			name:        "bare ! — expected variable name after prefix",
			varStr:      "!",
			wantCount:   0,
			wantErrPart: "expected variable name after prefix",
		},
		{
			// Bare & with no variable name — same error
			name:        "bare & — expected variable name after prefix",
			varStr:      "&",
			wantCount:   0,
			wantErrPart: "expected variable name after prefix",
		},
		{
			// !&ARGS — both negation and count prefixes on the same variable.
			// The parser accepts this syntactically; semantic validity is Coraza's job.
			name:      "!&ARGS — both prefixes accepted",
			varStr:    "!&ARGS",
			wantCount: 1,
		},
		{
			// Multiple variables with a bare prefix in the middle
			name:        "ARGS|!|FILES — bare ! in middle yields error and skips that segment",
			varStr:      "ARGS|!|FILES",
			wantCount:   2,  // ARGS and FILES parsed; ! segment errors
			wantErrPart: "expected variable name after prefix",
		},
		{
			// Regex key with no closing / — user forgot the trailing slash.
			// Must report a parse error instead of silently treating /xxx as a
			// literal key. (Silently ignoring it would hide the bug and let
			// Coraza produce a confusing error about an unknown variable name.)
			name:        "ARGS:/xxx — unclosed regex key",
			varStr:      "ARGS:/xxx",
			wantCount:   0,
			wantErrPart: "unclosed regex in variable key",
		},
		{
			// Just / with no pattern and no closing / — same error.
			name:        "ARGS:/ — bare opening slash",
			varStr:      "ARGS:/",
			wantCount:   0,
			wantErrPart: "unclosed regex in variable key",
		},
		{
			// Valid regex key — must still work correctly.
			name:      "ARGS:/xxx/ — valid closed regex key",
			varStr:    "ARGS:/xxx/",
			wantCount: 1,
		},
		{
			// Multiple variables where one has an unclosed regex.
			// The erroneous segment is skipped; the others are still parsed.
			name:        "ARGS|ARGS:/xxx|FILES — unclosed regex in middle segment",
			varStr:      "ARGS|ARGS:/xxx|FILES",
			wantCount:   2, // ARGS and FILES; ARGS:/xxx errors
			wantErrPart: "unclosed regex in variable key",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			vars, errs := ParseVariables(tt.varStr, Position{Line: 0, Character: 0})
			assert.Len(t, vars, tt.wantCount)
			if tt.wantErrPart == "" {
				assert.Empty(t, errs, "expected no parse errors")
			} else {
				require.NotEmpty(t, errs, "expected at least one parse error")
				var found bool
				for _, e := range errs {
					if strings.Contains(e.Message, tt.wantErrPart) {
						found = true
						break
					}
				}
				assert.True(t, found, "expected error containing %q, got: %v", tt.wantErrPart, errs)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// Group 4: Action list edge cases
// Why: commas and single-quoted strings inside the action list have many
// degenerate forms — leading/trailing/doubled commas, unclosed single quotes.
// The action parser is tolerant; it must not crash on any of these.
// ----------------------------------------------------------------------------

func TestParse_ActionListEdgeCases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		actionStr   string // content inside the outer double quotes
		wantCount   int    // expected number of ActionExpr
	}{
		{
			// Empty action list — zero actions, not an error at the parser level.
			name:      "empty action list",
			actionStr: "",
			wantCount: 0,
		},
		{
			// Trailing comma — empty segment at end is skipped
			name:      "trailing comma",
			actionStr: "id:1,phase:2,deny,",
			wantCount: 3,
		},
		{
			// Leading comma — empty segment at start is skipped
			name:      "leading comma",
			actionStr: ",id:1,phase:2,deny",
			wantCount: 3,
		},
		{
			// Double comma in the middle — empty segment skipped
			name:      "double comma in middle",
			actionStr: "id:1,phase:2,,deny",
			wantCount: 3,
		},
		{
			// Single-quoted value with a comma inside — must NOT be split
			name:      "comma inside single-quoted msg",
			actionStr: "id:1,phase:2,msg:'hello, world',deny",
			wantCount: 4,
		},
		{
			// Unclosed single quote inside action value — parser is tolerant,
			// the value is returned as-is (no Stage 1 parse error; Coraza catches it).
			name:      "unclosed single quote in msg value — tolerant parse",
			actionStr: "id:1,phase:2,msg:'unclosed",
			wantCount: 3,
		},
		{
			// Action with no value (e.g. deny, log, pass)
			name:      "valueless actions",
			actionStr: "deny,log,pass",
			wantCount: 3,
		},
		{
			// Escaped single quote inside value
			name:      "escaped single quote in msg",
			actionStr: `id:1,phase:2,msg:'it\'s fine'`,
			wantCount: 3,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			actions, errs := parseActions(tt.actionStr, Token{Line: 0, StartChar: -1})
			assert.Empty(t, errs, "action parser should never return errors (it is tolerant)")
			assert.Len(t, actions, tt.wantCount)
		})
	}
}

// ----------------------------------------------------------------------------
// Group 5: Continuation line edge cases
// Why: backslash continuation is the #1 source of positional bugs. These cases
// verify that the parser handles continuation at various positions without panic
// and produces the correct AST nodes.
// ----------------------------------------------------------------------------

func TestParse_ContinuationEdgeCases(t *testing.T) {
	t.Parallel()

	t.Run("continuation after directive name before first arg", func(t *testing.T) {
		t.Parallel()
		// \n after SecRule before ARGS — still produces a valid rule
		src := "SecRule \\\nARGS \"@rx test\" \"id:1,phase:2,deny\""
		f := Parse("", src)
		require.Len(t, f.Nodes, 1)
		rule := f.Nodes[0].(*RuleNode)
		assert.Empty(t, rule.ParseErrors)
		require.Len(t, rule.Variables, 1)
		assert.Equal(t, "ARGS", rule.Variables[0].Name)
		assert.NotNil(t, rule.Operator)
		assert.NotEmpty(t, rule.Actions)
	})

	t.Run("file ends with continuation backslash — no panic", func(t *testing.T) {
		t.Parallel()
		// The file ends mid-continuation. Parser must not panic; it produces a
		// partial rule with whatever args were present before EOF.
		src := "SecRule ARGS \\"
		f := Parse("", src)
		assert.NotNil(t, f)
		assert.Len(t, f.Nodes, 1)
	})

	t.Run("action list spanning two continuation lines", func(t *testing.T) {
		t.Parallel()
		src := "SecRule ARGS \"@rx test\" \"id:1001,phase:2,deny,nolog\\\n,msg:'ok'\""
		f := Parse("", src)
		require.Len(t, f.Nodes, 1)
		rule := f.Nodes[0].(*RuleNode)
		assert.Empty(t, rule.ParseErrors)
		msgAction := rule.FindAction("msg")
		require.NotNil(t, msgAction)
		assert.Equal(t, "ok", msgAction.Value)
	})

	t.Run("three-way continuation — all three lines joined", func(t *testing.T) {
		t.Parallel()
		src := "SecRule \\\nARGS \\\n\"@rx test\" \\\n\"id:1,phase:2,deny\""
		f := Parse("", src)
		require.Len(t, f.Nodes, 1)
		rule := f.Nodes[0].(*RuleNode)
		assert.Empty(t, rule.ParseErrors)
		assert.NotNil(t, rule.Operator)
		assert.NotEmpty(t, rule.Actions)
	})

	t.Run("unclosed string on continuation line — parse error fires", func(t *testing.T) {
		t.Parallel()
		// The closing " is missing from the last continuation line.
		src := "SecRule ARGS \"@rx test\" \"id:1001,phase:2,deny\\\n,msg:'ok'"
		f := Parse("", src)
		require.Len(t, f.Nodes, 1)
		rule := f.Nodes[0].(*RuleNode)
		assert.NotEmpty(t, rule.ParseErrors, "unclosed action list should produce a parse error")
	})
}

// ----------------------------------------------------------------------------
// Group 9: Case-insensitive directive matching
// Why: SecLang is case-insensitive. SECRULE, secrule, SecRuLe must all parse
// identically and pass Stage 1 semantic checks without false positives.
// ----------------------------------------------------------------------------

func TestParse_CaseInsensitiveDirectives(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		src       string
		wantKind  NodeKind
	}{
		{
			name:     "SECRULE uppercase — parsed as SecRule",
			src:      `SECRULE ARGS "@rx x" "id:1,phase:2,deny"`,
			wantKind: NodeKindSecRule,
		},
		{
			name:     "secrule lowercase — parsed as SecRule",
			src:      `secrule ARGS "@rx x" "id:1,phase:2,deny"`,
			wantKind: NodeKindSecRule,
		},
		{
			name:     "SecRuLe mixed case — parsed as SecRule",
			src:      `SecRuLe ARGS "@rx x" "id:1,phase:2,deny"`,
			wantKind: NodeKindSecRule,
		},
		{
			name:     "SECACTION uppercase",
			src:      `SECACTION "id:1,phase:1,pass"`,
			wantKind: NodeKindSecAction,
		},
		{
			name:     "secdefaultaction lowercase",
			src:      `secdefaultaction "phase:2,deny,log"`,
			wantKind: NodeKindSecDefaultAction,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := Parse("", tt.src)
			require.Len(t, f.Nodes, 1)
			rule, ok := f.Nodes[0].(*RuleNode)
			require.True(t, ok)
			assert.Equal(t, tt.wantKind, rule.GetKind())
			assert.Empty(t, rule.ParseErrors)
		})
	}
}

func TestActionSplitWithCommaInSingleQuotes(t *testing.T) {
	t.Parallel()
	actions, _ := parseActions("id:1,msg:'hello, world',phase:2", Token{Line: 0, StartChar: -1})
	require.Len(t, actions, 3)
	assert.Equal(t, "hello, world", actions[1].Value)
}

func TestVariableParsing_RegexKey(t *testing.T) {
	t.Parallel()
	vars, errs := ParseVariables("ARGS:/^id_/", Position{Line: 0, Character: 0})
	assert.Empty(t, errs)
	require.Len(t, vars, 1)
	assert.Equal(t, "ARGS", vars[0].Name)
	assert.Equal(t, "^id_", vars[0].Key)
	assert.True(t, vars[0].KeyIsRegex)
}

func TestVariableParsing_MultipleWithNegation(t *testing.T) {
	t.Parallel()
	vars, errs := ParseVariables("ARGS|!ARGS:foo|&FILES", Position{Line: 0, Character: 0})
	assert.Empty(t, errs)
	require.Len(t, vars, 3)
	assert.False(t, vars[0].Negated)
	assert.True(t, vars[1].Negated)
	assert.Equal(t, "foo", vars[1].Key)
	assert.True(t, vars[2].Count)
}

// TestParse_UnclosedRegexInVariableList is the regression test for the
// user-reported case where ARGS:/xxx (missing closing /) was silently accepted
// as a literal key instead of producing a parse error.
func TestParse_UnclosedRegexInVariableList(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		src         string
		wantErrPart string
	}{
		{
			// Exact user-reported case: mixed variable list, one has unclosed regex.
			name:        "user-reported: ARGS|ARGS:/xxx|ARGS.yyy|AR",
			src:         `SecRule ARGS|ARGS:/xxx|ARGS.yyy|AR "@rx <script>" "id:1001,phase:2,deny,t:lowercase,msg:'XSS'"`,
			wantErrPart: "unclosed regex in variable key",
		},
		{
			// Single unclosed regex variable.
			name:        "single unclosed regex key",
			src:         `SecRule ARGS:/pattern "@rx test" "id:1,phase:2,deny"`,
			wantErrPart: "unclosed regex in variable key",
		},
		{
			// Unclosed regex in second variable — first variable still parses.
			name:        "valid first var then unclosed regex",
			src:         `SecRule ARGS|REQUEST_HEADERS:/unclosed "@rx test" "id:1,phase:2,deny"`,
			wantErrPart: "unclosed regex in variable key",
		},
		{
			// Bare opening slash only.
			name:        "ARGS:/ — bare slash",
			src:         `SecRule ARGS:/ "@rx test" "id:1,phase:2,deny"`,
			wantErrPart: "unclosed regex in variable key",
		},
		{
			// Valid closed regex — must NOT produce an error.
			name:        "valid closed regex key — no error",
			src:         `SecRule ARGS:/pattern/ "@rx test" "id:1,phase:2,deny"`,
			wantErrPart: "",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := Parse("test.conf", tt.src)
			if tt.wantErrPart == "" {
				assert.Empty(t, f.Errors, "expected no parse errors")
			} else {
				require.NotEmpty(t, f.Errors, "expected at least one parse error")
				var found bool
				for _, e := range f.Errors {
					if strings.Contains(e.Message, tt.wantErrPart) {
						found = true
						break
					}
				}
				assert.True(t, found, "expected error containing %q, got: %v", tt.wantErrPart, f.Errors)
			}
		})
	}
}

func TestParse_ExtraTrailingQuote(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		src         string
		wantErrPart string
	}{
		{
			// Exact user-reported case: continuation line ends with extra ""
			name: "trailing double-quote after closed action list on continuation",
			src: "SecRule REQUEST_HEADERS:Content-Type \"@rx ^multipart\" \"id:1002,phase:1,pass,nolog\\\n" +
				",msg:'Multipart request detected'\"\"",
			wantErrPart: "unclosed string literal",
		},
		{
			// Single trailing " after a normally closed action list
			name: "single trailing quote after closed action list",
			src:  `SecRule ARGS "@rx test" "id:1001,phase:2,deny"` + `"`,
			wantErrPart: "unclosed string literal",
		},
		{
			// Extra trailing " on SecAction
			name: "trailing quote after SecAction",
			src:  `SecAction "id:1000,phase:1,pass,nolog"` + `"`,
			wantErrPart: "unclosed string literal",
		},
		{
			// Double closing quotes on SecDefaultAction
			name: "double closing quotes on SecDefaultAction",
			src:  `SecDefaultAction "phase:2,deny,log""`,
			wantErrPart: "unclosed string literal",
		},
		{
			// Properly formed rule — no extra quote, no error
			name:        "valid continuation — no error",
			src:         "SecRule ARGS \"@rx test\" \"id:1001,phase:2,deny,nolog\\\n,msg:'ok'\"",
			wantErrPart: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := Parse("test.conf", tt.src)
			if tt.wantErrPart == "" {
				assert.Empty(t, f.Errors, "expected no parse errors")
			} else {
				require.NotEmpty(t, f.Errors, "expected at least one parse error")
				var found bool
				for _, e := range f.Errors {
					if strings.Contains(e.Message, tt.wantErrPart) {
						found = true
						break
					}
				}
				assert.True(t, found, "expected error containing %q, got: %v", tt.wantErrPart, f.Errors)
			}
		})
	}
}

func TestParse_UnclosedString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		src         string
		wantErrPart string
	}{
		{
			name:        "unclosed action list in SecRule",
			src:         `SecRule ARGS "@rx test" "id:1001,phase:2,deny`,
			wantErrPart: `unclosed string literal`,
		},
		{
			name:        "unclosed operator in SecRule",
			src:         `SecRule ARGS "@rx test`,
			wantErrPart: `unclosed string literal`,
		},
		{
			name:        "unclosed action list in SecAction",
			src:         `SecAction "id:1000,phase:1,pass`,
			wantErrPart: `unclosed string literal`,
		},
		{
			name:        "unclosed action list in SecDefaultAction",
			src:         `SecDefaultAction "phase:2,deny`,
			wantErrPart: `unclosed string literal`,
		},
		{
			name:        "closed string produces no error",
			src:         `SecRule ARGS "@rx test" "id:1001,phase:2,deny"`,
			wantErrPart: "",
		},
		{
			name:        "empty quoted string is valid",
			src:         `SecAction ""`,
			wantErrPart: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := Parse("test.conf", tt.src)
			if tt.wantErrPart == "" {
				assert.Empty(t, f.Errors, "expected no parse errors")
			} else {
				require.NotEmpty(t, f.Errors, "expected at least one parse error")
				var found bool
				for _, e := range f.Errors {
					if strings.Contains(e.Message, tt.wantErrPart) {
						found = true
						break
					}
				}
				assert.True(t, found, "expected parse error containing %q, got: %v", tt.wantErrPart, f.Errors)
			}
		})
	}
}

// filterActionsByName returns all actions with the given name.
func filterActionsByName(actions []ActionExpr, name string) []ActionExpr {
	var result []ActionExpr
	for _, a := range actions {
		if a.LowerName() == name {
			result = append(result, a)
		}
	}
	return result
}

// TestParse_ChainRules verifies that chain rule relationships are resolved
// correctly by the post-processing pass. Chained SecRules must have IsChained=true;
// base rules and non-chained rules must have IsChained=false.
func TestParse_ChainRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		src        string
		wantChains []bool // IsChained for each RuleNode in order
	}{
		{
			name: "single rule — not chained",
			src:  `SecRule ARGS "@rx x" "id:1,phase:2,deny"`,
			wantChains: []bool{false},
		},
		{
			name: "base rule with chain — second rule is chained",
			src: "SecRule ARGS \"@rx x\" \"id:1,phase:2,pass,chain\"\n" +
				"SecRule ARGS \"@rx y\" \"t:lowercase\"",
			wantChains: []bool{false, true},
		},
		{
			name: "three-level chain",
			src: "SecRule ARGS \"@rx a\" \"id:1,phase:1,pass,chain\"\n" +
				"SecRule ARGS \"@rx b\" \"chain\"\n" +
				"SecRule ARGS \"@rx c\" \"t:none\"",
			wantChains: []bool{false, true, true},
		},
		{
			name: "chain followed by independent rule",
			src: "SecRule ARGS \"@rx a\" \"id:1,phase:1,pass,chain\"\n" +
				"SecRule ARGS \"@rx b\" \"t:lowercase\"\n" +
				"SecRule ARGS \"@rx c\" \"id:2,phase:2,deny\"",
			wantChains: []bool{false, true, false},
		},
		{
			name: "comment between chain links does not break chain",
			src: "SecRule ARGS \"@rx a\" \"id:1,phase:1,pass,chain\"\n" +
				"# this is a comment in the chain\n" +
				"SecRule ARGS \"@rx b\" \"t:lowercase\"",
			wantChains: []bool{false, true},
		},
		{
			name: "non-rule directive breaks chain",
			src: "SecRule ARGS \"@rx a\" \"id:1,phase:1,pass,chain\"\n" +
				"SecRuleEngine On\n" +
				"SecRule ARGS \"@rx c\" \"id:2,phase:2,deny\"",
			wantChains: []bool{false, false},
		},
		{
			name: "continuation-line chain rule",
			src: "SecRule ARGS \"@rx a\" \\\n" +
				"    \"id:1,phase:1,pass,chain\"\n" +
				"    SecRule ARGS \"@rx b\" \\\n" +
				"        \"t:lowercase\"",
			wantChains: []bool{false, true},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := Parse("test.conf", tt.src)
			var got []bool
			for _, n := range f.Nodes {
				if r, ok := n.(*RuleNode); ok {
					got = append(got, r.IsChained)
				}
			}
			assert.Equal(t, tt.wantChains, got)
		})
	}
}

// TestParse_XMLXPathKey verifies that XML:/* and other XPath-style keys are
// accepted without a parse error. The / in XML collection keys is an XPath
// path separator, not a regex delimiter, so it must not trigger the
// "unclosed regex" detection.
func TestParse_XMLXPathKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		src     string
		wantKey string
		wantErr bool
	}{
		{
			name:    "XML:/* — all nodes",
			src:     `SecRule XML:/* "@rx test" "id:1,phase:2,deny"`,
			wantKey: "/*",
			wantErr: false,
		},
		{
			name:    "XML://body//* — deep path",
			src:     `SecRule XML://body//* "@rx test" "id:1,phase:2,deny"`,
			wantKey: "//body//*",
			wantErr: false,
		},
		{
			name:    "XML:/foo — single-slash path without closing",
			src:     `SecRule XML:/foo "@rx test" "id:1,phase:2,deny"`,
			wantKey: "/foo",
			wantErr: false,
		},
		{
			name:    "XML:/pattern/ — looks like regex but treated as XPath",
			src:     `SecRule XML:/pattern/ "@rx test" "id:1,phase:2,deny"`,
			wantKey: "/pattern/",
			wantErr: false,
		},
		{
			name:    "ARGS:/regex/ — valid regex key for non-XML",
			src:     `SecRule ARGS:/pattern/ "@rx test" "id:1,phase:2,deny"`,
			wantKey: "pattern",
			wantErr: false,
		},
		{
			name:    "ARGS:/unclosed — unclosed regex still errors for non-XML",
			src:     `SecRule ARGS:/unclosed "@rx test" "id:1,phase:2,deny"`,
			wantErr: true,
		},
		{
			name:    "pipe list with XML:/*",
			src:     `SecRule ARGS|XML:/* "@rx test" "id:1,phase:2,deny"`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := Parse("test.conf", tt.src)
			if tt.wantErr {
				assert.NotEmpty(t, f.Errors, "expected parse error")
				return
			}
			assert.Empty(t, f.Errors, "unexpected parse errors: %v", f.Errors)
			if tt.wantKey != "" {
				require.Len(t, f.Nodes, 1)
				rule := f.Nodes[0].(*RuleNode)
				// Find variable with non-empty key.
				var found bool
				for _, v := range rule.Variables {
					if v.Key == tt.wantKey {
						found = true
						break
					}
				}
				assert.True(t, found, "expected variable with key %q; variables: %v", tt.wantKey, rule.Variables)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// Variable wildcard syntax: COLLECTION*
// Why: ModSecurity supports ARGS*, REQUEST_COOKIES*, etc. as a shorthand for
// the wildcard-key form COLLECTION:*. The parser must accept them without
// error and set Key="*" on the resulting VariableExpr so that the diagnostics
// layer can look up the base collection name in the knowledge base.
// ----------------------------------------------------------------------------

func TestParse_VariableWildcard(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		src        string
		wantName   string
		wantKey    string
		wantErr    bool
	}{
		{
			name:     "REQUEST_COOKIES* — wildcard no colon",
			src:      `SecRule REQUEST_COOKIES* "@rx test" "id:1,phase:2,deny"`,
			wantName: "REQUEST_COOKIES",
			wantKey:  "*",
		},
		{
			name:     "ARGS* — short collection wildcard",
			src:      `SecRule ARGS* "@rx test" "id:1,phase:2,deny"`,
			wantName: "ARGS",
			wantKey:  "*",
		},
		{
			name:     "REQUEST_HEADERS* — wildcard",
			src:      `SecRule REQUEST_HEADERS* "@rx test" "id:1,phase:2,deny"`,
			wantName: "REQUEST_HEADERS",
			wantKey:  "*",
		},
		{
			name:     "negated wildcard: !ARGS*",
			src:      `SecRule !ARGS* "@rx test" "id:1,phase:2,deny"`,
			wantName: "ARGS",
			wantKey:  "*",
		},
		{
			name:     "count wildcard: &REQUEST_HEADERS*",
			src:      `SecRule &REQUEST_HEADERS* "@gt 0" "id:1,phase:2,deny"`,
			wantName: "REQUEST_HEADERS",
			wantKey:  "*",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := Parse("test.conf", tt.src)
			assert.Empty(t, f.Errors, "unexpected parse errors: %v", f.Errors)
			require.Len(t, f.Nodes, 1)
			rule := f.Nodes[0].(*RuleNode)
			require.NotEmpty(t, rule.Variables, "expected at least one variable")
			v := rule.Variables[0]
			assert.Equal(t, tt.wantName, v.Name)
			assert.Equal(t, tt.wantKey, v.Key)
		})
	}
}

func TestParse_VariableWildcardInPipeList(t *testing.T) {
	t.Parallel()
	// This is the exact pattern from CRS rule 932100.
	src := `SecRule REQUEST_COOKIES*|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx test" "id:1,phase:2,deny"`
	f := Parse("test.conf", src)
	assert.Empty(t, f.Errors, "unexpected parse errors: %v", f.Errors)
	require.Len(t, f.Nodes, 1)
	rule := f.Nodes[0].(*RuleNode)
	require.Len(t, rule.Variables, 5)

	assert.Equal(t, "REQUEST_COOKIES", rule.Variables[0].Name)
	assert.Equal(t, "*", rule.Variables[0].Key)

	assert.Equal(t, "REQUEST_COOKIES_NAMES", rule.Variables[1].Name)
	assert.Equal(t, "", rule.Variables[1].Key)

	assert.Equal(t, "ARGS_NAMES", rule.Variables[2].Name)
	assert.Equal(t, "ARGS", rule.Variables[3].Name)

	assert.Equal(t, "XML", rule.Variables[4].Name)
	assert.Equal(t, "/*", rule.Variables[4].Key)
}

func TestParse_VariableWildcardRanges(t *testing.T) {
	t.Parallel()
	// Verify that wildcard variables have correct character ranges so that
	// hover and diagnostics point at the right position in the source.
	src := `SecRule REQUEST_COOKIES*|ARGS "@rx test" "id:1,phase:2,deny"`
	f := Parse("test.conf", src)
	assert.Empty(t, f.Errors)
	rule := f.Nodes[0].(*RuleNode)
	require.Len(t, rule.Variables, 2)

	// "SecRule " = 8 chars; REQUEST_COOKIES* starts at char 8
	wc := rule.Variables[0]
	assert.Equal(t, 8, wc.Range.Start.Character, "REQUEST_COOKIES* start char")
	// "REQUEST_COOKIES*" = 16 chars
	assert.Equal(t, 24, wc.Range.End.Character, "REQUEST_COOKIES* end char")

	// ARGS starts at char 25 (8 + 16 + 1 for the pipe)
	args := rule.Variables[1]
	assert.Equal(t, 25, args.Range.Start.Character, "ARGS start char")
}

// TestToken_PhysPos_RuneColumns is a regression test for FIX 3: PhysPos takes a
// BYTE offset into Token.Value but must return a RUNE column. A multibyte value
// earlier in the token must not shift later positions by (bytes - runes).
func TestToken_PhysPos_RuneColumns(t *testing.T) {
	t.Parallel()
	// Value "café X": é is 2 bytes. Byte offset 5 ("café " then X) is rune index 5.
	tok := Token{
		Type:      TokenQuoted,
		Value:     "café X",
		Line:      0,
		StartChar: 0, // opening quote at column 0, value begins at column 1
	}
	// Byte offset of "X" within Value: c(0)a(1)f(2)é(3,4) (5)X = byte 6.
	line, char := tok.PhysPos(6)
	assert.Equal(t, 0, line)
	// Value starts at column StartChar+1 = 1; "X" is rune index 5 in the value,
	// so its column is 1+5 = 6 (NOT byte-shifted to 7).
	assert.Equal(t, 6, char)
}

// TestParse_ActionRangeNotByteShifted is the end-to-end FIX 3 regression: the
// "id" action after a multibyte msg value must report its true rune column.
func TestParse_ActionRangeNotByteShifted(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx x" "msg:'café',id:1,deny"`
	f := Parse("test.conf", src)
	require.Len(t, f.Nodes, 1)
	rule, ok := f.Nodes[0].(*RuleNode)
	require.True(t, ok)
	idAction := rule.FindAction("id")
	require.NotNil(t, idAction)

	// Compute the true rune column of "id" in the source line.
	idx := strings.Index(src, ",id:1,") + 1 // +1 to point at 'i'
	wantCol := len([]rune(src[:idx]))
	assert.Equal(t, 0, idAction.Range.Start.Line)
	assert.Equal(t, wantCol, idAction.Range.Start.Character)
}

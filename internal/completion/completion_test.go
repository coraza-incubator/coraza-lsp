// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package completion

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	protocol_3_16 "github.com/tliron/glsp/protocol_3_16"

	"github.com/coraza-incubator/coraza-lsp/internal/parser"
)

// --- Context detection tests ---

func TestDetectContext_Comment(t *testing.T) {
	t.Parallel()
	ctx, _ := DetectContext("# this is a comment", 10)
	assert.Equal(t, ContextUnknown, ctx)
}

func TestDetectContext_EmptyLine(t *testing.T) {
	t.Parallel()
	ctx, prefix := DetectContext("", 0)
	assert.Equal(t, ContextDirectiveName, ctx)
	assert.Equal(t, "", prefix)
}

func TestDetectContext_PartialDirective(t *testing.T) {
	t.Parallel()
	ctx, prefix := DetectContext("SecRul", 6)
	assert.Equal(t, ContextDirectiveName, ctx)
	assert.Equal(t, "SecRul", prefix)
}

func TestDetectContext_DirectiveCompleteBeforeSecondArg(t *testing.T) {
	t.Parallel()
	ctx, _ := DetectContext("SecRule ", 8)
	assert.Equal(t, ContextVariableList, ctx)
}

func TestDetectContext_VariableList(t *testing.T) {
	t.Parallel()
	ctx, prefix := DetectContext("SecRule ARGS", 12)
	assert.Equal(t, ContextVariableList, ctx)
	assert.Equal(t, "ARGS", prefix)
}

func TestDetectContext_VariableListAfterPipe(t *testing.T) {
	t.Parallel()
	ctx, prefix := DetectContext("SecRule ARGS|REQ", 16)
	assert.Equal(t, ContextVariableList, ctx)
	assert.Equal(t, "REQ", prefix)
}

func TestDetectContext_OperatorContext(t *testing.T) {
	t.Parallel()
	ctx, prefix := DetectContext(`SecRule ARGS "@rx`, 17)
	assert.Equal(t, ContextOperator, ctx)
	assert.Equal(t, "rx", prefix)
}

func TestDetectContext_ActionList(t *testing.T) {
	t.Parallel()
	ctx, _ := DetectContext(`SecRule ARGS "@rx x" "id:1,ph`, 29)
	assert.Equal(t, ContextActionList, ctx)
}

func TestDetectContext_TransformationContext(t *testing.T) {
	t.Parallel()
	ctx, prefix := DetectContext(`SecRule ARGS "@rx x" "id:1,phase:2,t:low`, 41)
	assert.Equal(t, ContextTransformation, ctx)
	assert.Equal(t, "low", prefix)
}

func TestDetectContext_PhaseValue(t *testing.T) {
	t.Parallel()
	ctx, prefix := DetectContext(`SecRule ARGS "@rx x" "id:1,phase:`, 33)
	assert.Equal(t, ContextPhaseValue, ctx)
	assert.Equal(t, "", prefix)
}

func TestDetectContext_SecActionActionList(t *testing.T) {
	t.Parallel()
	ctx, _ := DetectContext(`SecAction "id:1,ph`, 18)
	assert.Equal(t, ContextActionList, ctx)
}

func TestDetectContext_SecActionEmptyActionList(t *testing.T) {
	t.Parallel()
	// Cursor right after the opening " with nothing typed yet.
	ctx, prefix := DetectContext(`SecAction "`, 11)
	assert.Equal(t, ContextActionList, ctx)
	assert.Equal(t, "", prefix)
}

func TestDetectContext_SecRuleEmptySecondArg(t *testing.T) {
	t.Parallel()
	// Cursor right after the second opening " (action list) with nothing typed.
	ctx, prefix := DetectContext(`SecRule ARGS "@rx test" "`, 25)
	assert.Equal(t, ContextActionList, ctx)
	assert.Equal(t, "", prefix)
}

func TestDetectContext_SecRuleEmptyFirstArg(t *testing.T) {
	t.Parallel()
	// Cursor right after the first opening " (operator position) with nothing typed.
	ctx, prefix := DetectContext(`SecRule ARGS "`, 14)
	assert.Equal(t, ContextOperator, ctx)
	assert.Equal(t, "", prefix)
}

func TestDetectContext_ActionListCommaInSingleQuote(t *testing.T) {
	t.Parallel()
	// Cursor inside a msg value that contains a comma — must not split on the inner comma.
	ctx, prefix := DetectContext(`SecRule ARGS "@rx x" "id:1,phase:2,msg:'A,B',t:low`, 51)
	assert.Equal(t, ContextTransformation, ctx)
	assert.Equal(t, "low", prefix)
}

func TestDetectContext_ActionListAfterSingleQuotedMsg(t *testing.T) {
	t.Parallel()
	// After a correctly-closed msg value with comma, the next action should complete.
	ctx, prefix := DetectContext(`SecRule ARGS "@rx x" "id:1,phase:2,msg:'text',den`, 50)
	assert.Equal(t, ContextActionList, ctx)
	assert.Equal(t, "den", prefix)
}

func TestDetectContext_IncludePath(t *testing.T) {
	t.Parallel()
	ctx, _ := DetectContext("Include /etc/coraza", 19)
	assert.Equal(t, ContextIncludePath, ctx)
}

func TestDetectContext_RuleEngineValue(t *testing.T) {
	t.Parallel()
	ctx, prefix := DetectContext("SecRuleEngine Det", 17)
	assert.Equal(t, ContextRuleEngineValue, ctx)
	assert.Equal(t, "Det", prefix)
}

func TestDetectContext_SeverityValue(t *testing.T) {
	t.Parallel()
	ctx, prefix := DetectContext(`SecRule ARGS "@rx x" "id:1,phase:2,deny,severity:CRIT`, 53)
	assert.Equal(t, ContextSeverityValue, ctx)
	assert.Equal(t, "CRIT", prefix)
}

// --- Completion provider tests ---

func TestGetCompletions_DirectiveName_Empty(t *testing.T) {
	t.Parallel()
	items := GetCompletions(ContextDirectiveName, "")
	require.NotEmpty(t, items)
	labels := itemLabels(items)
	assert.Contains(t, labels, "SecRule")
	assert.Contains(t, labels, "SecAction")
}

func TestGetCompletions_DirectiveName_Prefix(t *testing.T) {
	t.Parallel()
	items := GetCompletions(ContextDirectiveName, "SecR")
	for _, item := range items {
		assert.True(t, strings.HasPrefix(strings.ToLower(item.Label), "secr"),
			"label %q should start with 'SecR'", item.Label)
	}
}

func TestGetCompletions_DirectiveName_SecRuleHasSnippet(t *testing.T) {
	t.Parallel()
	items := GetCompletions(ContextDirectiveName, "SecRule")
	require.NotEmpty(t, items)
	for _, item := range items {
		if item.Label == "SecRule" {
			require.NotNil(t, item.InsertText)
			assert.Contains(t, *item.InsertText, "${1:VARIABLES}")
			return
		}
	}
	t.Fatal("SecRule not found in completions")
}

func TestGetCompletions_Variables_Empty(t *testing.T) {
	t.Parallel()
	items := GetCompletions(ContextVariableList, "")
	require.NotEmpty(t, items)
	labels := itemLabels(items)
	assert.Contains(t, labels, "ARGS")
	assert.Contains(t, labels, "REQUEST_HEADERS")
}

func TestGetCompletions_Variables_Prefix(t *testing.T) {
	t.Parallel()
	items := GetCompletions(ContextVariableList, "REQUEST_")
	require.NotEmpty(t, items)
	for _, item := range items {
		assert.True(t, strings.HasPrefix(strings.ToLower(item.Label), "request_"),
			"variable %q should start with REQUEST_", item.Label)
	}
}

func TestGetCompletions_Operators_AtPrefix(t *testing.T) {
	t.Parallel()
	items := GetCompletions(ContextOperator, "rx")
	require.NotEmpty(t, items)
	for _, item := range items {
		if item.Label == "rx" {
			require.NotNil(t, item.InsertText)
			assert.Equal(t, "@rx", *item.InsertText)
			return
		}
	}
	t.Fatal("rx operator not found")
}

func TestGetCompletions_Operators_DetectSQLi(t *testing.T) {
	t.Parallel()
	items := GetCompletions(ContextOperator, "detect")
	labels := itemLabels(items)
	assert.Contains(t, labels, "detectSQLi")
	assert.Contains(t, labels, "detectXSS")
}

func TestGetCompletions_Actions_Empty(t *testing.T) {
	t.Parallel()
	items := GetCompletions(ContextActionList, "")
	require.NotEmpty(t, items)
	labels := itemLabels(items)
	assert.Contains(t, labels, "id")
	assert.Contains(t, labels, "phase")
	assert.Contains(t, labels, "deny")
}

func TestGetCompletions_Actions_PhaseSnippet(t *testing.T) {
	t.Parallel()
	items := GetCompletions(ContextActionList, "phase")
	for _, item := range items {
		if item.Label == "phase" {
			require.NotNil(t, item.InsertText)
			assert.Contains(t, *item.InsertText, "phase:")
			return
		}
	}
	t.Fatal("phase action not found")
}

func TestGetCompletions_Transformations(t *testing.T) {
	t.Parallel()
	items := GetCompletions(ContextTransformation, "")
	require.NotEmpty(t, items)
	labels := itemLabels(items)
	assert.Contains(t, labels, "lowercase")
	assert.Contains(t, labels, "urlDecode")
	assert.Contains(t, labels, "none")
}

func TestGetCompletions_Transformations_Prefix(t *testing.T) {
	t.Parallel()
	items := GetCompletions(ContextTransformation, "url")
	require.NotEmpty(t, items)
	for _, item := range items {
		assert.True(t, strings.HasPrefix(strings.ToLower(item.Label), "url"),
			"transformation %q should start with 'url'", item.Label)
	}
}

func TestGetCompletions_PhaseValues(t *testing.T) {
	t.Parallel()
	items := GetCompletions(ContextPhaseValue, "")
	labels := itemLabels(items)
	for _, want := range []string{"1", "2", "3", "4", "5"} {
		assert.Contains(t, labels, want)
	}
}

func TestGetCompletions_RuleEngineValues(t *testing.T) {
	t.Parallel()
	items := GetCompletions(ContextRuleEngineValue, "")
	labels := itemLabels(items)
	assert.Contains(t, labels, "On")
	assert.Contains(t, labels, "Off")
	assert.Contains(t, labels, "DetectionOnly")
}

func TestGetCompletions_SeverityValues(t *testing.T) {
	t.Parallel()
	items := GetCompletions(ContextSeverityValue, "")
	labels := itemLabels(items)
	assert.Contains(t, labels, "CRITICAL")
	assert.Contains(t, labels, "WARNING")
}

func TestGetCompletions_Unknown(t *testing.T) {
	t.Parallel()
	items := GetCompletions(ContextUnknown, "")
	assert.Nil(t, items)
}

func TestGetCompletions_NonexistentPrefix(t *testing.T) {
	t.Parallel()
	items := GetCompletions(ContextDirectiveName, "zzznomatch")
	assert.Empty(t, items)
}

func TestGetCompletions_AllItemsHaveDocumentation(t *testing.T) {
	t.Parallel()
	contexts := []CompletionContext{
		ContextDirectiveName, ContextVariableList, ContextOperator,
		ContextActionList, ContextTransformation,
	}
	for _, ctx := range contexts {
		items := GetCompletions(ctx, "")
		for _, item := range items {
			assert.NotNil(t, item.Documentation, "item %q should have documentation", item.Label)
		}
	}
}

func TestTokenisePartial(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input    string
		expected []string
	}{
		{"SecRule", []string{"SecRule"}},
		{"SecRule ARGS", []string{"SecRule", "ARGS"}},
		{`SecRule ARGS "@rx x"`, []string{"SecRule", "ARGS", "@rx x"}},
		{"  ", nil},
	}
	for _, tc := range cases {
		got := tokenisePartial(tc.input)
		if len(tc.expected) == 0 {
			assert.Empty(t, got, "input: %q", tc.input)
		} else {
			assert.Equal(t, tc.expected, got, "input: %q", tc.input)
		}
	}
}

// itemLabels extracts all Label strings from completion items.
func itemLabels(items []protocol_3_16.CompletionItem) []string {
	labels := make([]string, len(items))
	for i, item := range items {
		labels[i] = item.Label
	}
	return labels
}

// --- ctl context detection tests ---

func TestDetectContext_CtlKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		line       string
		cursor     int
		wantCtx    CompletionContext
		wantPrefix string
	}{
		{
			// ctl: with no key typed yet
			line:       `SecRule ARGS "@rx x" "id:1,phase:2,pass,ctl:`,
			cursor:     44,
			wantCtx:    ContextCtlKey,
			wantPrefix: "",
		},
		{
			// ctl: with partial key
			line:       `SecRule ARGS "@rx x" "id:1,phase:2,pass,ctl:ruleEng`,
			cursor:     51,
			wantCtx:    ContextCtlKey,
			wantPrefix: "ruleEng",
		},
		{
			// SecAction ctl: key
			line:       `SecAction "id:1,phase:1,pass,ctl:req`,
			cursor:     36,
			wantCtx:    ContextCtlKey,
			wantPrefix: "req",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.line, func(t *testing.T) {
			t.Parallel()
			ctx, prefix := DetectContext(tt.line, tt.cursor)
			assert.Equal(t, tt.wantCtx, ctx)
			assert.Equal(t, tt.wantPrefix, prefix)
		})
	}
}

func TestDetectContext_CtlValue(t *testing.T) {
	t.Parallel()
	tests := []struct {
		line       string
		cursor     int
		wantCtx    CompletionContext
		wantPrefix string
	}{
		{
			// ctl:ruleEngine= with no value yet
			line:       `SecAction "id:1,phase:1,pass,ctl:ruleEngine=`,
			cursor:     44,
			wantCtx:    ContextCtlValue,
			wantPrefix: "ruleEngine=",
		},
		{
			// ctl:ruleEngine=On typed partially
			line:       `SecAction "id:1,phase:1,pass,ctl:ruleEngine=On`,
			cursor:     46,
			wantCtx:    ContextCtlValue,
			wantPrefix: "ruleEngine=On",
		},
		{
			// ctl:requestBodyProcessor=
			line:       `SecAction "id:1,phase:1,pass,ctl:requestBodyProcessor=`,
			cursor:     54,
			wantCtx:    ContextCtlValue,
			wantPrefix: "requestBodyProcessor=",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.line, func(t *testing.T) {
			t.Parallel()
			ctx, prefix := DetectContext(tt.line, tt.cursor)
			assert.Equal(t, tt.wantCtx, ctx)
			assert.Equal(t, tt.wantPrefix, prefix)
		})
	}
}

// --- ctl completion provider tests ---

func TestGetCompletions_CtlKey_Empty(t *testing.T) {
	t.Parallel()
	items := GetCompletions(ContextCtlKey, "")
	require.NotEmpty(t, items)
	labels := itemLabels(items)
	assert.Contains(t, labels, "ruleEngine")
	assert.Contains(t, labels, "requestBodyProcessor")
	// ruleRemoveByMsg / ruleRemoveTargetByMsg are real Coraza v3.5.0 ctl
	// sub-options used by CRS; they must be offered for completion.
	assert.Contains(t, labels, "ruleRemoveByMsg")
	assert.Contains(t, labels, "ruleRemoveTargetByMsg")
	// `noAuditLog` is NOT a Coraza ctl sub-option and must NOT be offered.
	assert.NotContains(t, labels, "noAuditLog")
}

func TestGetCompletions_CtlKey_Prefix(t *testing.T) {
	t.Parallel()
	items := GetCompletions(ContextCtlKey, "rule")
	require.NotEmpty(t, items)
	for _, item := range items {
		assert.True(t, strings.HasPrefix(strings.ToLower(item.Label), "rule"),
			"key %q should start with 'rule'", item.Label)
	}
}

func TestGetCompletions_CtlKey_InsertTextHasEquals(t *testing.T) {
	t.Parallel()
	// Keys that take a value should insert "KEY=" so the cursor lands after the =.
	items := GetCompletions(ContextCtlKey, "ruleEngine")
	for _, item := range items {
		if item.Label == "ruleEngine" {
			require.NotNil(t, item.InsertText)
			assert.Equal(t, "ruleEngine=", *item.InsertText)
			return
		}
	}
	t.Fatal("ruleEngine not found in ctl key completions")
}

func TestGetCompletions_CtlKey_NoValueOptionHasNoEquals(t *testing.T) {
	t.Parallel()
	// Coraza v3.5.0 has no value-less ctl sub-options (the former `noAuditLog`
	// entry was removed because Coraza does not register it). This test now
	// guards the inverse invariant: every offered ctl key that is NOT a
	// NoValue option must insert "KEY=" so the cursor lands after the '='.
	items := GetCompletions(ContextCtlKey, "")
	require.NotEmpty(t, items)
	for _, item := range items {
		require.NotNil(t, item.InsertText, "ctl key %q must have InsertText", item.Label)
		assert.Equal(t, item.Label+"=", *item.InsertText,
			"value-taking ctl key %q should insert %q=", item.Label, item.Label)
	}
}

func TestGetCompletions_CtlValue_RuleEngine(t *testing.T) {
	t.Parallel()
	items := GetCompletions(ContextCtlValue, "ruleEngine=")
	require.NotEmpty(t, items)
	labels := itemLabels(items)
	assert.Contains(t, labels, "On")
	assert.Contains(t, labels, "Off")
	assert.Contains(t, labels, "DetectionOnly")
}

func TestGetCompletions_CtlValue_RuleEnginePrefix(t *testing.T) {
	t.Parallel()
	items := GetCompletions(ContextCtlValue, "ruleEngine=Det")
	require.NotEmpty(t, items)
	assert.Equal(t, "DetectionOnly", items[0].Label)
}

func TestGetCompletions_CtlValue_RequestBodyProcessor(t *testing.T) {
	t.Parallel()
	items := GetCompletions(ContextCtlValue, "requestBodyProcessor=")
	labels := itemLabels(items)
	assert.Contains(t, labels, "URLENCODED")
	assert.Contains(t, labels, "JSON")
	assert.Contains(t, labels, "XML")
	assert.Contains(t, labels, "MULTIPART")
}

func TestGetCompletions_CtlValue_FreeForm_NoSuggestions(t *testing.T) {
	t.Parallel()
	// ruleRemoveById takes a free-form value — no completions expected.
	items := GetCompletions(ContextCtlValue, "ruleRemoveById=")
	assert.Empty(t, items)
}

func TestGetCompletions_CtlValue_UnknownKey_NoSuggestions(t *testing.T) {
	t.Parallel()
	items := GetCompletions(ContextCtlValue, "notAKey=")
	assert.Empty(t, items)
}

func TestGetCompletions_CtlValue_MissingEquals_NoSuggestions(t *testing.T) {
	t.Parallel()
	// No = in the string — ctlValueCompletions should return nil.
	items := GetCompletions(ContextCtlValue, "ruleEngine")
	assert.Empty(t, items)
}

// --- TX variable auto-completion tests ---

func TestCollectTXKeys_Empty(t *testing.T) {
	t.Parallel()
	f := parser.Parse("", "SecRule ARGS \"@rx x\" \"id:1,phase:2,deny\"")
	keys := CollectTXKeys(f)
	assert.Empty(t, keys)
}

func TestCollectTXKeys_NilFile(t *testing.T) {
	t.Parallel()
	assert.Nil(t, CollectTXKeys(nil))
}

func TestCollectTXKeys_SingleSetvar(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx x" "id:1,phase:2,pass,setvar:tx.score=+1"`
	f := parser.Parse("", src)
	keys := CollectTXKeys(f)
	assert.Contains(t, keys, "score")
}

func TestCollectTXKeys_MultipleKeys(t *testing.T) {
	t.Parallel()
	src := "SecRule ARGS \"@rx x\" \"id:1,phase:2,pass,setvar:tx.score=+1,setvar:tx.level=5\""
	f := parser.Parse("", src)
	keys := CollectTXKeys(f)
	assert.Contains(t, keys, "score")
	assert.Contains(t, keys, "level")
}

func TestCollectTXKeys_Deduplicated(t *testing.T) {
	t.Parallel()
	src := "SecRule ARGS \"@rx x\" \"id:1,phase:2,pass,setvar:tx.score=+1\"\n" +
		"SecRule ARGS \"@rx y\" \"id:2,phase:2,pass,setvar:tx.score=+2\""
	f := parser.Parse("", src)
	keys := CollectTXKeys(f)
	count := 0
	for _, k := range keys {
		if k == "score" {
			count++
		}
	}
	assert.Equal(t, 1, count, "duplicate TX keys should be deduplicated")
}

func TestCollectTXKeys_NonTxIgnored(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx x" "id:1,phase:2,pass,setvar:ip.score=+1"`
	f := parser.Parse("", src)
	keys := CollectTXKeys(f)
	assert.Empty(t, keys)
}

func TestGetCompletions_TXVariables_WithPrefix(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx x" "id:1,phase:2,pass,setvar:tx.anomaly_score=+1,setvar:tx.inbound_score=+5"`
	f := parser.Parse("", src)
	require.NotEmpty(t, CollectTXKeys(f))

	items := GetCompletions(ContextVariableList, "TX:", f)
	labels := itemLabels(items)
	assert.Contains(t, labels, "TX:anomaly_score")
	assert.Contains(t, labels, "TX:inbound_score")
}

func TestGetCompletions_TXVariables_PrefixFilter(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx x" "id:1,phase:2,pass,setvar:tx.anomaly_score=+1,setvar:tx.inbound_score=+5"`
	f := parser.Parse("", src)

	items := GetCompletions(ContextVariableList, "TX:anom", f)
	labels := itemLabels(items)
	assert.Contains(t, labels, "TX:anomaly_score")
	assert.NotContains(t, labels, "TX:inbound_score")
}

func TestGetCompletions_TXVariables_NoTxPrefix_NotInjected(t *testing.T) {
	t.Parallel()
	// Without "TX:" prefix, file-local TX keys should not appear.
	src := `SecRule ARGS "@rx x" "id:1,phase:2,pass,setvar:tx.score=+1"`
	f := parser.Parse("", src)

	items := GetCompletions(ContextVariableList, "ARGS", f)
	labels := itemLabels(items)
	assert.NotContains(t, labels, "TX:score")
}

func TestGetCompletions_TXVariables_NoFileNoInjection(t *testing.T) {
	t.Parallel()
	// Without file context, GetCompletions should still work normally.
	items := GetCompletions(ContextVariableList, "TX:")
	// Should not panic and return the static TX variable (if any).
	_ = items
}

// --- SecMarker skipAfter auto-completion tests ---

func TestCollectMarkerIDs_Empty(t *testing.T) {
	t.Parallel()
	f := parser.Parse("", "SecRule ARGS \"@rx x\" \"id:1,phase:2,deny\"")
	assert.Empty(t, CollectMarkerIDs(f))
}

func TestCollectMarkerIDs_NilFile(t *testing.T) {
	t.Parallel()
	assert.Nil(t, CollectMarkerIDs(nil))
}

func TestCollectMarkerIDs_Single(t *testing.T) {
	t.Parallel()
	src := "SecMarker END_CHECK\nSecRule ARGS \"@rx x\" \"id:1,phase:2,deny\""
	f := parser.Parse("", src)
	ids := CollectMarkerIDs(f)
	assert.Contains(t, ids, "END_CHECK")
}

func TestCollectMarkerIDs_Multiple(t *testing.T) {
	t.Parallel()
	src := "SecMarker BEGIN_CHECK\nSecMarker END_CHECK"
	f := parser.Parse("", src)
	ids := CollectMarkerIDs(f)
	assert.Contains(t, ids, "BEGIN_CHECK")
	assert.Contains(t, ids, "END_CHECK")
}

func TestCollectMarkerIDs_Deduplicated(t *testing.T) {
	t.Parallel()
	src := "SecMarker END_CHECK\nSecMarker END_CHECK"
	f := parser.Parse("", src)
	ids := CollectMarkerIDs(f)
	count := 0
	for _, id := range ids {
		if id == "END_CHECK" {
			count++
		}
	}
	assert.Equal(t, 1, count)
}

func TestDetectContext_SkipAfterValue(t *testing.T) {
	t.Parallel()
	ctx, prefix := DetectContext(`SecRule ARGS "@rx x" "id:1,phase:2,pass,skipAfter:END`, 53)
	assert.Equal(t, ContextSkipAfterValue, ctx)
	assert.Equal(t, "END", prefix)
}

func TestGetCompletions_SkipAfter_WithMarkers(t *testing.T) {
	t.Parallel()
	src := "SecMarker END_CHECK\nSecMarker BEGIN_BLOCK\nSecRule ARGS \"@rx x\" \"id:1,phase:2,pass,skipAfter:\""
	f := parser.Parse("", src)
	require.NotEmpty(t, CollectMarkerIDs(f))

	items := GetCompletions(ContextSkipAfterValue, "", f)
	labels := itemLabels(items)
	assert.Contains(t, labels, "END_CHECK")
	assert.Contains(t, labels, "BEGIN_BLOCK")
}

func TestGetCompletions_SkipAfter_PrefixFilter(t *testing.T) {
	t.Parallel()
	src := "SecMarker END_CHECK\nSecMarker BEGIN_BLOCK\nSecRule ARGS \"@rx x\" \"id:1,phase:2,pass,skipAfter:\""
	f := parser.Parse("", src)

	items := GetCompletions(ContextSkipAfterValue, "END", f)
	labels := itemLabels(items)
	assert.Contains(t, labels, "END_CHECK")
	assert.NotContains(t, labels, "BEGIN_BLOCK")
}

func TestGetCompletions_SkipAfter_NoFile_ReturnsNil(t *testing.T) {
	t.Parallel()
	items := GetCompletions(ContextSkipAfterValue, "")
	assert.Nil(t, items)
}

// --- Macro expansion auto-completion tests ---

func TestDetectContext_MacroExpansion_InSetvar(t *testing.T) {
	t.Parallel()
	line := `SecRule ARGS "@rx x" "id:1,phase:2,pass,setvar:tx.score=+%{TX.`
	ctx, prefix := DetectContext(line, len(line))
	assert.Equal(t, ContextMacroExpansion, ctx)
	assert.Equal(t, "TX.", prefix)
}

func TestDetectContext_MacroExpansion_InMsg(t *testing.T) {
	t.Parallel()
	line := `SecRule ARGS "@rx x" "id:1,phase:2,deny,msg:'Matched %{MATCHED`
	ctx, prefix := DetectContext(line, len(line))
	assert.Equal(t, ContextMacroExpansion, ctx)
	assert.Equal(t, "MATCHED", prefix)
}

func TestDetectContext_MacroExpansion_EmptyPrefix(t *testing.T) {
	t.Parallel()
	line := `SecRule ARGS "@rx x" "id:1,phase:2,deny,msg:'value is %{`
	ctx, prefix := DetectContext(line, len(line))
	assert.Equal(t, ContextMacroExpansion, ctx)
	assert.Equal(t, "", prefix)
}

func TestDetectContext_MacroExpansion_ClosedMacro_NoContext(t *testing.T) {
	t.Parallel()
	// After a closed %{TX.score}, cursor is back to normal action value context.
	line := `SecRule ARGS "@rx x" "id:1,phase:2,deny,msg:'value is %{TX.score} and `
	ctx, _ := DetectContext(line, len(line))
	assert.NotEqual(t, ContextMacroExpansion, ctx)
}

func TestDetectContext_MacroExpansion_TXPrefix(t *testing.T) {
	t.Parallel()
	line := `SecRule ARGS "@rx x" "id:1,phase:2,pass,setvar:tx.s=+%{TX.anom`
	ctx, prefix := DetectContext(line, len(line))
	assert.Equal(t, ContextMacroExpansion, ctx)
	assert.Equal(t, "TX.anom", prefix)
}

func TestGetCompletions_Macro_StaticVariables(t *testing.T) {
	t.Parallel()
	items := GetCompletions(ContextMacroExpansion, "")
	require.NotEmpty(t, items)
	labels := itemLabels(items)
	assert.Contains(t, labels, "ARGS")
	assert.Contains(t, labels, "REQUEST_HEADERS")
}

func TestGetCompletions_Macro_StaticPrefix(t *testing.T) {
	t.Parallel()
	items := GetCompletions(ContextMacroExpansion, "REQUEST")
	require.NotEmpty(t, items)
	for _, item := range items {
		assert.True(t, strings.HasPrefix(strings.ToUpper(item.Label), "REQUEST"),
			"label %q should start with REQUEST", item.Label)
	}
}

func TestGetCompletions_Macro_TXKeys(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx x" "id:1,phase:2,pass,setvar:tx.anomaly_score=+1,setvar:tx.inbound_score=+5"`
	f := parser.Parse("", src)

	items := GetCompletions(ContextMacroExpansion, "TX.", f)
	labels := itemLabels(items)
	assert.Contains(t, labels, "TX.anomaly_score")
	assert.Contains(t, labels, "TX.inbound_score")
}

func TestGetCompletions_Macro_TXKeysFiltered(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx x" "id:1,phase:2,pass,setvar:tx.anomaly_score=+1,setvar:tx.inbound_score=+5"`
	f := parser.Parse("", src)

	items := GetCompletions(ContextMacroExpansion, "TX.anom", f)
	labels := itemLabels(items)
	assert.Contains(t, labels, "TX.anomaly_score")
	assert.NotContains(t, labels, "TX.inbound_score")
}

func TestGetCompletions_Macro_TXDotNotation_NotColonNotation(t *testing.T) {
	t.Parallel()
	// Macro expansions use TX.key (dot), not TX:key (colon used in variable lists).
	src := `SecRule ARGS "@rx x" "id:1,phase:2,pass,setvar:tx.score=+1"`
	f := parser.Parse("", src)

	items := GetCompletions(ContextMacroExpansion, "TX.", f)
	labels := itemLabels(items)
	// Dot notation present
	assert.Contains(t, labels, "TX.score")
	// Colon notation must NOT appear
	for _, l := range labels {
		assert.False(t, strings.HasPrefix(l, "TX:"), "colon notation %q should not appear in macro completions", l)
	}
}

// --- Multi-line continuation line context tests ---

func TestDetectContextInActionList_ActionName(t *testing.T) {
	t.Parallel()
	// Continuation line: "    block" — cursor at end of "block"
	ctx, prefix := DetectContextInActionList("    block")
	assert.Equal(t, ContextActionList, ctx)
	assert.Equal(t, "block", prefix)
}

func TestDetectContextInActionList_ActionNameAfterComma(t *testing.T) {
	t.Parallel()
	ctx, prefix := DetectContextInActionList("    t:none,t:urlDecodeUni,den")
	assert.Equal(t, ContextActionList, ctx)
	assert.Equal(t, "den", prefix)
}

func TestDetectContextInActionList_PhaseValue(t *testing.T) {
	t.Parallel()
	ctx, prefix := DetectContextInActionList("    phase:")
	assert.Equal(t, ContextPhaseValue, ctx)
	assert.Equal(t, "", prefix)
}

func TestDetectContextInActionList_Transformation(t *testing.T) {
	t.Parallel()
	ctx, prefix := DetectContextInActionList("    t:none,t:urlDecodeUni,t:")
	assert.Equal(t, ContextTransformation, ctx)
	assert.Equal(t, "", prefix)
}

func TestDetectContextInActionList_TransformationPrefix(t *testing.T) {
	t.Parallel()
	ctx, prefix := DetectContextInActionList("    t:lower")
	assert.Equal(t, ContextTransformation, ctx)
	assert.Equal(t, "lower", prefix)
}

func TestDetectContextInActionList_FirstContinuationLineWithQuote(t *testing.T) {
	t.Parallel()
	// First continuation line starts with indentation + opening quote.
	ctx, prefix := DetectContextInActionList(`    "id:944152,phase:`)
	assert.Equal(t, ContextPhaseValue, ctx)
	assert.Equal(t, "", prefix)
}

func TestDetectContextInActionList_WithBackslash(t *testing.T) {
	t.Parallel()
	// Line ending with backslash continuation marker.
	ctx, prefix := DetectContextInActionList(`    t:none,t:urlDecodeUni,t:\`)
	assert.Equal(t, ContextTransformation, ctx)
	assert.Equal(t, "", prefix)
}

func TestDetectContextInActionList_MacroExpansion(t *testing.T) {
	t.Parallel()
	ctx, prefix := DetectContextInActionList(`    setvar:'tx.score=+%{TX.`)
	assert.Equal(t, ContextMacroExpansion, ctx)
	assert.Equal(t, "TX.", prefix)
}

func TestDetectContextInActionList_Severity(t *testing.T) {
	t.Parallel()
	ctx, prefix := DetectContextInActionList("    severity:'CRIT")
	assert.Equal(t, ContextSeverityValue, ctx)
	assert.Equal(t, "'CRIT", prefix)
}

func TestExtractMacroPrefix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input  string
		prefix string
		ok     bool
	}{
		{"tx.score=+%{TX.anom", "TX.anom", true},
		{"tx.score=+%{", "", true},
		{"tx.score=+%{TX.score}", "", false}, // closed macro
		{"no macro here", "", false},
		{"%{A}%{B.c", "B.c", true}, // rightmost open macro wins
	}
	for _, tc := range cases {
		got, ok := extractMacroPrefix(tc.input)
		assert.Equal(t, tc.ok, ok, "input: %q", tc.input)
		if tc.ok {
			assert.Equal(t, tc.prefix, got, "input: %q", tc.input)
		}
	}
}

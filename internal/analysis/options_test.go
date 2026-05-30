// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	protocol_3_16 "github.com/tliron/glsp/protocol_3_16"

	"github.com/coraza-incubator/coraza-lsp/internal/config"
	"github.com/coraza-incubator/coraza-lsp/internal/parser"
)

// TestAnalyzeWith_SeverityPromotion verifies that `diagnostics` maps a
// code to a stronger severity. "skipafter-not-found" ships as Information;
// users who treat cross-file references as errors can escalate.
func TestAnalyzeWith_SeverityPromotion(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx x" "id:1,phase:2,pass,skipAfter:NOWHERE"`
	f := parser.Parse("", src)

	opts := Options{SeverityOverrides: map[string]config.Severity{
		CodeSkipAfterNotFound: config.SeverityError,
	}}
	diags := AnalyzeWith(f, opts)

	var found bool
	for _, d := range diags {
		if code, ok := codeOf(d); ok && code == CodeSkipAfterNotFound {
			found = true
			assert.Equal(t, protocol_3_16.DiagnosticSeverityError, *d.Severity)
		}
	}
	assert.True(t, found, "expected skipafter-not-found diagnostic to appear")
}

// TestAnalyzeWith_SeverityOff verifies that `"off"` suppresses a code entirely.
func TestAnalyzeWith_SeverityOff(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx x" "phase:2,deny"`
	f := parser.Parse("", src)

	// Default run: missing-id fires.
	defaultDiags := Analyze(f)
	var hadID bool
	for _, d := range defaultDiags {
		if c, _ := codeOf(d); c == CodeMissingID {
			hadID = true
		}
	}
	assert.True(t, hadID, "default run should emit missing-id")

	// With off override: suppressed.
	opts := Options{SeverityOverrides: map[string]config.Severity{
		CodeMissingID: config.SeverityOff,
	}}
	for _, d := range AnalyzeWith(f, opts) {
		if c, _ := codeOf(d); c == CodeMissingID {
			t.Fatalf("expected missing-id to be suppressed, got %v", d)
		}
	}
}

// TestApply_DoesNotAliasInput is a regression test for the bug where apply()
// reused the caller's backing array via diags[:0]. When an override drops or
// rewrites an entry, the in-place rewrite corrupted the caller's view of the
// input slice. apply() must return a fresh slice and leave the input intact.
func TestApply_DoesNotAliasInput(t *testing.T) {
	t.Parallel()

	mk := func(code string) protocol_3_16.Diagnostic {
		sev := protocol_3_16.DiagnosticSeverityWarning
		return protocol_3_16.Diagnostic{
			Severity: &sev,
			Code:     &protocol_3_16.IntegerOrString{Value: code},
		}
	}

	// Input: [missing-id, missing-phase]. Override drops missing-id (off), so the
	// output is [missing-phase]. The input slice must NOT be mutated.
	input := []protocol_3_16.Diagnostic{mk(CodeMissingID), mk(CodeMissingPhase)}

	opts := Options{SeverityOverrides: map[string]config.Severity{
		CodeMissingID: config.SeverityOff,
	}}
	out := opts.apply(input)

	// The first input element must still be missing-id (not overwritten).
	c0, _ := codeOf(input[0])
	assert.Equal(t, CodeMissingID, c0, "apply() must not corrupt the caller's input slice")
	c1, _ := codeOf(input[1])
	assert.Equal(t, CodeMissingPhase, c1)

	// And the output must be the single surviving diagnostic.
	require.Len(t, out, 1)
	co, _ := codeOf(out[0])
	assert.Equal(t, CodeMissingPhase, co)
}

// TestAnalyzeWith_NilOptionsMatchesAnalyze ensures AnalyzeWith with a zero
// Options is byte-identical to Analyze.
func TestAnalyzeWith_NilOptionsMatchesAnalyze(t *testing.T) {
	t.Parallel()
	src := "SecRule ARGS \"@rx x\" \"phase:2,deny\"\nSecAction \"id:1,phase:1,pass,ctl:nope=Off\""
	f := parser.Parse("", src)
	a := Analyze(f)
	b := AnalyzeWith(f, DefaultOptions())
	assert.Equal(t, len(a), len(b))
	for i := range a {
		assert.Equal(t, a[i], b[i])
	}
}

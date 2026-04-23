// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"testing"

	"github.com/stretchr/testify/assert"
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

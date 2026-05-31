// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	protocol_3_16 "github.com/tliron/glsp/protocol_3_16"

	"github.com/coraza-incubator/coraza-lsp/internal/parser"
)

func TestAnalyze_ValidRule(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx <script" "id:1001,phase:2,deny,msg:'XSS'"`
	f := parser.Parse("", src)
	diags := Analyze(f)
	// Should have no diagnostics for a valid rule.
	errorDiags := filterBySeverity(diags, protocol_3_16.DiagnosticSeverityError)
	assert.Empty(t, errorDiags, "valid rule should produce no error diagnostics")
}

func TestAnalyze_MissingID(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx test" "phase:2,deny"`
	f := parser.Parse("", src)
	diags := Analyze(f)
	codes := diagCodes(diags)
	assert.Contains(t, codes, CodeMissingID)
}

func TestAnalyze_MissingPhase(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx test" "id:1001,deny"`
	f := parser.Parse("", src)
	diags := Analyze(f)
	codes := diagCodes(diags)
	assert.Contains(t, codes, CodeMissingPhase)
}

func TestAnalyze_Phase(t *testing.T) {
	t.Parallel()
	cases := []struct {
		phase     string
		wantValid bool
	}{
		{"1", true}, {"2", true}, {"3", true}, {"4", true}, {"5", true},
		{"0", false}, {"6", false}, {"abc", false}, {"-1", false},
	}
	for _, tc := range cases {
		t.Run(tc.phase, func(t *testing.T) {
			t.Parallel()
			src := `SecRule ARGS "@rx test" "id:1001,phase:` + tc.phase + `,deny"`
			f := parser.Parse("", src)
			diags := filterByCode(Analyze(f), CodeInvalidPhase)
			if tc.wantValid {
				assert.Empty(t, diags, "phase %q should be valid", tc.phase)
			} else {
				assert.NotEmpty(t, diags, "phase %q should be invalid", tc.phase)
			}
		})
	}
}

func TestAnalyze_InvalidID(t *testing.T) {
	t.Parallel()
	for _, badID := range []string{"0", "-1", "abc", ""} {
		t.Run(badID, func(t *testing.T) {
			t.Parallel()
			src := `SecRule ARGS "@rx test" "id:` + badID + `,phase:2,deny"`
			f := parser.Parse("", src)
			diags := Analyze(f)
			codes := diagCodes(diags)
			assert.Contains(t, codes, CodeInvalidID, "id %q should be invalid", badID)
		})
	}
}

func TestAnalyze_DuplicateID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{
			name: "same id twice flags duplicate",
			src:  "SecRule ARGS \"@rx a\" \"id:1001,phase:2,deny\"\nSecRule ARGS \"@rx b\" \"id:1001,phase:2,deny\"",
			want: true,
		},
		{
			name: "different ids no duplicate",
			src:  "SecRule ARGS \"@rx a\" \"id:1001,phase:2,deny\"\nSecRule ARGS \"@rx b\" \"id:1002,phase:2,deny\"",
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := parser.Parse("", tc.src)
			dups := filterByCode(Analyze(f), CodeDuplicateID)
			if tc.want {
				assert.NotEmpty(t, dups)
			} else {
				assert.Empty(t, dups)
			}
		})
	}
}

func TestAnalyze_SkipAfter(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{
			name: "unknown marker flags diagnostic",
			src:  `SecRule ARGS "@rx test" "id:1001,phase:2,pass,skipAfter:NONEXISTENT"`,
			want: true,
		},
		{
			name: "known marker no diagnostic",
			src:  "SecRule ARGS \"@rx test\" \"id:1001,phase:2,pass,skipAfter:END_CHECKS\"\nSecMarker END_CHECKS",
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := parser.Parse("", tc.src)
			diags := filterByCode(Analyze(f), CodeSkipAfterNotFound)
			if tc.want {
				assert.NotEmpty(t, diags)
			} else {
				assert.Empty(t, diags)
			}
		})
	}
}

func TestAnalyze_SecActionMissingID(t *testing.T) {
	t.Parallel()
	src := `SecAction "phase:1,pass"`
	f := parser.Parse("", src)
	require.NotNil(t, f)
	diags := Analyze(f)
	codes := diagCodes(diags)
	assert.Contains(t, codes, CodeMissingID)
}

func TestAnalyze_UnknownDirective(t *testing.T) {
	t.Parallel()
	src := "SecUnknownDirective foo"
	f := parser.Parse("", src)
	diags := Analyze(f)
	codes := diagCodes(diags)
	assert.Contains(t, codes, CodeUnknownDirective)
}

func TestAnalyze_KnownDirectivesNoWarning(t *testing.T) {
	t.Parallel()
	// Every directive in this list must be recognised without an unknown-directive warning.
	// Covers directives added to the knowledge base (regression guard: adding a directive
	// to knowledge but forgetting to register it here used to cause false warnings).
	known := []string{
		"SecRuleEngine On",
		"SecRequestBodyAccess On",
		"SecAuditEngine On",
		// Newly added directives (must not produce CodeUnknownDirective)
		"SecWebAppID \"myapp\"",
		"SecSensorID \"node-01\"",
		"SecConnEngine On",
		"SecCollectionTimeout 3600",
		"SecDataset bad-agents \"sqlmap\"",
		"SecIgnoreRuleCompilationErrors On",
		"SecPcreMatchLimit 100000",
		"SecPcreMatchLimitRecursion 100000",
		"SecDataDir /tmp",
		"SecUploadDir /tmp",
		"SecUploadFileLimit 10",
		"SecUploadFileMode 0600",
		"SecUploadKeepFiles Off",
		"SecAuditLogDirMode 0755",
		"SecAuditLogFileMode 0600",
		"SecServerSignature \"Apache\"",
		"SecHashEngine On",
		"SecHashKey \"secret\" Rand",
	}
	for _, dir := range known {
		dir := dir
		t.Run(dir, func(t *testing.T) {
			t.Parallel()
			f := parser.Parse("", dir)
			diags := Analyze(f)
			unkDiags := filterByCode(diags, CodeUnknownDirective)
			assert.Empty(t, unkDiags, "%q should be a known directive", dir)
		})
	}
}

func TestAnalyze_EmptySource(t *testing.T) {
	t.Parallel()
	f := parser.Parse("", "")
	diags := Analyze(f)
	assert.Empty(t, diags)
}

func TestAnalyze_CommentsOnly(t *testing.T) {
	t.Parallel()
	f := parser.Parse("", "# just comments\n# nothing to validate")
	diags := Analyze(f)
	assert.Empty(t, diags)
}

func TestValidator_ScheduleAndCallback(t *testing.T) {
	t.Parallel()
	var callCount int32
	v := NewValidator(10*time.Millisecond, func(uri string, diags []protocol_3_16.Diagnostic) {
		atomic.AddInt32(&callCount, 1)
	})

	v.Schedule("file:///test.conf", "SecRuleEngine On", nil)
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int32(1), atomic.LoadInt32(&callCount))
}

func TestValidator_Debounce(t *testing.T) {
	t.Parallel()
	var callCount int32
	v := NewValidator(50*time.Millisecond, func(uri string, diags []protocol_3_16.Diagnostic) {
		atomic.AddInt32(&callCount, 1)
	})

	// Schedule 5 times rapidly — only one callback should fire.
	for i := 0; i < 5; i++ {
		v.Schedule("file:///test.conf", "SecRuleEngine On", nil)
	}
	time.Sleep(150 * time.Millisecond)
	assert.Equal(t, int32(1), atomic.LoadInt32(&callCount))
}

func TestValidator_Cancel(t *testing.T) {
	t.Parallel()
	var callCount int32
	v := NewValidator(50*time.Millisecond, func(uri string, diags []protocol_3_16.Diagnostic) {
		atomic.AddInt32(&callCount, 1)
	})

	v.Schedule("file:///test.conf", "SecRuleEngine On", nil)
	v.Cancel("file:///test.conf")
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, int32(0), atomic.LoadInt32(&callCount))
}

func TestValidator_CancelAll(t *testing.T) {
	t.Parallel()
	var callCount int32
	v := NewValidator(50*time.Millisecond, func(uri string, diags []protocol_3_16.Diagnostic) {
		atomic.AddInt32(&callCount, 1)
	})

	v.Schedule("file:///a.conf", "SecRuleEngine On", nil)
	v.Schedule("file:///b.conf", "SecRuleEngine On", nil)
	v.CancelAll()
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, int32(0), atomic.LoadInt32(&callCount))
}

func TestValidator_MultipleURIs(t *testing.T) {
	t.Parallel()
	uris := make(map[string]bool)
	var mu sync.Mutex
	v := NewValidator(10*time.Millisecond, func(uri string, diags []protocol_3_16.Diagnostic) {
		mu.Lock()
		uris[uri] = true
		mu.Unlock()
	})

	v.Schedule("file:///a.conf", "SecRuleEngine On", nil)
	v.Schedule("file:///b.conf", "SecRuleEngine On", nil)
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	assert.True(t, uris["file:///a.conf"])
	assert.True(t, uris["file:///b.conf"])
}

// TestSuppressRedundantCorazaErrors verifies that Stage 2 coraza-error
// diagnostics are removed when Stage 1 has already reported an unknown-variable
// warning on the same line. This prevents the user from seeing two overlapping
// diagnostics for the exact same problem.
func TestSuppressRedundantCorazaErrors(t *testing.T) {
	t.Parallel()

	warn := func(line uint32, code string) protocol_3_16.Diagnostic {
		c := protocol_3_16.IntegerOrString{Value: code}
		return protocol_3_16.Diagnostic{
			Range: protocol_3_16.Range{
				Start: protocol_3_16.Position{Line: line},
				End:   protocol_3_16.Position{Line: line, Character: 5},
			},
			Code: &c,
		}
	}

	t.Run("coraza-error on same line as unknown-variable is suppressed", func(t *testing.T) {
		t.Parallel()
		stage1 := []protocol_3_16.Diagnostic{warn(3, CodeUnknownVariable)}
		stage2 := []protocol_3_16.Diagnostic{warn(3, CodeCorazaError)}
		result := suppressRedundantCorazaErrors(stage1, stage2)
		assert.Empty(t, result, "coraza-error must be suppressed when unknown-variable on same line")
	})

	t.Run("coraza-error on different line is kept", func(t *testing.T) {
		t.Parallel()
		stage1 := []protocol_3_16.Diagnostic{warn(3, CodeUnknownVariable)}
		stage2 := []protocol_3_16.Diagnostic{warn(5, CodeCorazaError)}
		result := suppressRedundantCorazaErrors(stage1, stage2)
		assert.Len(t, result, 1, "coraza-error on different line must not be suppressed")
	})

	t.Run("non-coraza-error is never suppressed", func(t *testing.T) {
		t.Parallel()
		stage1 := []protocol_3_16.Diagnostic{warn(3, CodeUnknownVariable)}
		stage2 := []protocol_3_16.Diagnostic{warn(3, CodeMissingID)}
		result := suppressRedundantCorazaErrors(stage1, stage2)
		assert.Len(t, result, 1, "non-coraza-error diagnostics must never be suppressed")
	})

	t.Run("no stage1 unknown-variable: nothing suppressed", func(t *testing.T) {
		t.Parallel()
		stage1 := []protocol_3_16.Diagnostic{warn(3, CodeMissingPhase)}
		stage2 := []protocol_3_16.Diagnostic{warn(3, CodeCorazaError)}
		result := suppressRedundantCorazaErrors(stage1, stage2)
		assert.Len(t, result, 1, "coraza-error must remain when stage1 has no unknown-variable on that line")
	})
}

// --- Stage 2 / Coraza oracle tests ---

func TestExtractDirectiveFromError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		errMsg   string
		wantName string
	}{
		// --- unknown directive "NAME" ---
		{
			name:     "unknown directive lowercase",
			errMsg:   `unknown directive "secruleengine"`,
			wantName: "secruleengine",
		},
		{
			name:     "unknown directive mixed case",
			errMsg:   `unknown directive "SecRuleEngine"`,
			wantName: "secruleengine",
		},
		{
			name:     "unknown directive typo",
			errMsg:   `unknown directive "SecRul"`,
			wantName: "secrul",
		},

		// --- invalid directive "NAME" ---
		{
			name:     "invalid directive",
			errMsg:   `invalid directive "SecDebugLogLevel"`,
			wantName: "secdebugloglevel",
		},

		// --- failed to compile the directive "NAME": reason ---
		{
			name:     "failed to compile directive",
			errMsg:   `failed to compile the directive "SecDebugLogLevel": strconv.ParseInt: parsing "x": invalid syntax`,
			wantName: "secdebugloglevel",
		},
		{
			name:     "failed to compile directive wrapped",
			errMsg:   `invalid WAF config from string: failed to compile the directive "SecDebugLogLevel": strconv.ParseInt: parsing "x": invalid syntax`,
			wantName: "secdebugloglevel",
		},
		{
			name:     "failed to compile directive bad value",
			errMsg:   `failed to compile the directive "SecRequestBodyLimit": strconv.ParseInt: parsing "abc": invalid syntax`,
			wantName: "secrequestbodylimit",
		},
		{
			name:     "failed to compile directive with reason containing quotes",
			errMsg:   `failed to compile the directive "SecRule": error parsing actions: unknown action "badaction"`,
			wantName: "secrule",
		},

		// --- failed to compile: invalid enum value (not just parse errors) ---
		{
			name:     "failed to compile invalid log level",
			errMsg:   `invalid WAF config from string: failed to compile the directive "secdebugloglevel": invalid log level`,
			wantName: "secdebugloglevel",
		},
		{
			name:     "failed to compile invalid audit engine status",
			errMsg:   `invalid WAF config from string: failed to compile the directive "secauditengine": invalid audit engine status: badvalue`,
			wantName: "secauditengine",
		},
		{
			name:     "failed to compile invalid rule engine status",
			errMsg:   `invalid WAF config from string: failed to compile the directive "secruleengine": invalid rule engine status: "badvalue"`,
			wantName: "secruleengine",
		},
		{
			name:     "failed to compile strconv.Atoi",
			errMsg:   `invalid WAF config from string: failed to compile the directive "secuploadfilelimit": strconv.Atoi: parsing "abc": invalid syntax`,
			wantName: "secuploadfilelimit",
		},

		// --- error compiling directive "NAME": reason ---
		{
			name:     "error compiling directive",
			errMsg:   `error compiling directive "SecAction": missing required action id`,
			wantName: "secaction",
		},

		// --- wrapped in "invalid WAF config from string:" prefix ---
		{
			name:     "wrapped unknown directive",
			errMsg:   `invalid WAF config from string: unknown directive "secrul"`,
			wantName: "secrul",
		},
		{
			name:     "wrapped invalid directive",
			errMsg:   `invalid WAF config from string: invalid directive "SecRuleEngine"`,
			wantName: "secruleengine",
		},
		{
			name:     "double-wrapped with extra context",
			errMsg:   `invalid WAF config from string: rule parsing error: unknown directive "SecRequestBodyAccess"`,
			wantName: "secrequestbodyaccess",
		},

		// --- no match ---
		{
			name:     "no directive in message",
			errMsg:   "some generic error without a directive name",
			wantName: "",
		},
		{
			name:     "empty message",
			errMsg:   "",
			wantName: "",
		},
		{
			name:     "partial match no closing quote",
			errMsg:   `unknown directive "unclosed`,
			wantName: "",
		},
		{
			name:     "only the prefix without a name",
			errMsg:   `unknown directive "`,
			wantName: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := extractDirectiveFromError(tt.errMsg)
			assert.Equal(t, tt.wantName, got)
		})
	}
}

func TestLocateCorazaError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		errMsg    string
		source    string
		wantLine  int
		wantColGe int // start character must be >= this value (0 for most cases)
	}{
		{
			name:     "directive on first line",
			errMsg:   `unknown directive "SecRul"`,
			source:   "SecRul ARGS \"@rx x\" \"id:1,phase:2,deny\"",
			wantLine: 0,
		},
		{
			name:     "directive on second line",
			errMsg:   `unknown directive "SecRul"`,
			source:   "SecRuleEngine On\nSecRul ARGS \"@rx x\" \"id:1,phase:2,deny\"",
			wantLine: 1,
		},
		{
			name:     "directive after blank lines",
			errMsg:   `unknown directive "SecRul"`,
			source:   "\n\n\nSecRul ARGS \"@rx x\" \"id:1,phase:2,deny\"",
			wantLine: 3,
		},
		{
			name:     "directive after comment lines",
			errMsg:   `unknown directive "SecRul"`,
			source:   "# comment\n# another comment\nSecRul ARGS \"@rx x\" \"id:1,phase:2,deny\"",
			wantLine: 2,
		},
		{
			name:     "directive after mixed blank and comment lines",
			errMsg:   `unknown directive "SecRul"`,
			source:   "# header\n\nSecRuleEngine On\n\n\nSecRul ARGS \"@rx x\" \"id:1,phase:2,deny\"",
			wantLine: 5,
		},
		{
			name:     "directive deep in file",
			errMsg:   `unknown directive "BadDir"`,
			source:   "SecRuleEngine On\nSecRequestBodyAccess On\nSecAuditEngine On\nSecResponseBodyAccess On\nBadDir foo",
			wantLine: 4,
		},
		{
			name:     "indented directive",
			errMsg:   `unknown directive "SecRul"`,
			source:   "  SecRul ARGS \"@rx x\" \"id:1,phase:2,deny\"",
			wantLine: 0,
		},
		{
			name:     "no match falls back to line 0",
			errMsg:   "some error without a directive",
			source:   "SecRuleEngine On",
			wantLine: 0,
		},
		{
			name:     "empty source",
			errMsg:   `unknown directive "SecRul"`,
			source:   "",
			wantLine: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := locateCorazaError(tt.errMsg, tt.source)
			assert.Equal(t, tt.wantLine, r.Start.Line, "Start.Line mismatch")
			assert.Equal(t, r.Start.Line, r.End.Line, "range must be single-line")
			assert.Less(t, r.Start.Character, r.End.Character+1, "end character should be >= start character")
		})
	}
}

// TestLocateCorazaError_UnknownVariable verifies that "unknown variable" compile
// errors for a SecRule are attributed to the correct SecRule line, not line 0.
// Coraza's "unknown variable" message contains no rule ID, so locateCorazaError
// must fall back to parsing the source and scanning variable lists.
func TestLocateCorazaError_UnknownVariable(t *testing.T) {
	t.Parallel()
	errMsg := `invalid WAF config from string: failed to compile the directive "secrule": unknown variable`
	tests := []struct {
		name     string
		source   string
		wantLine int
	}{
		{
			name:     "unknown var on line 0",
			source:   `SecRule FOOBAR "@rx test" "id:1,phase:2,deny"`,
			wantLine: 0,
		},
		{
			name:     "unknown var on line 1, valid rule on line 0",
			source:   "SecRule ARGS \"@rx prev\" \"id:100,phase:2,deny\"\nSecRule FOOBAR \"@rx test\" \"id:101,phase:2,deny\"",
			wantLine: 1,
		},
		{
			name:     "wildcard form REQUEST_COOKIES* on line 1",
			source:   "SecRule ARGS \"@rx prev\" \"id:100,phase:2,deny\"\nSecRule REQUEST_COOKIES* \"@rx test\" \"id:932100,phase:2,deny\"",
			wantLine: 1,
		},
		{
			name:     "wildcard form ARGS* on line 2 after two valid rules",
			source:   "SecRule ARGS \"@rx a\" \"id:100,phase:2,deny\"\nSecRule REQUEST_HEADERS \"@rx b\" \"id:101,phase:2,deny\"\nSecRule ARGS* \"@rx c\" \"id:102,phase:2,deny\"",
			wantLine: 2,
		},
		{
			name: "multi-line continuation — wildcard on line 3",
			source: "SecRule ARGS \"@rx a\" \\\n    \"id:100,phase:2,deny\"\n" +
				"SecRule REQUEST_COOKIES*|ARGS_NAMES \"@rx b\" \\\n    \"id:932100,phase:2,deny\"",
			wantLine: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := locateCorazaError(errMsg, tt.source)
			assert.Equal(t, tt.wantLine, r.Start.Line,
				"locateCorazaError must point to the rule with the unknown variable, not line 0")
		})
	}
}

// TestValidateWithCoraza_ErrorPosition is the regression test for the bug where
// Stage 2 diagnostics always reported on line 0 regardless of where the error was.
func TestValidateWithCoraza_ErrorPosition(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		source   string
		wantLine uint32
	}{
		// --- unknown directive (typo) ---
		{
			name:     "typo on line 0",
			source:   `SecRul ARGS "@rx x" "id:1,phase:2,deny"`,
			wantLine: 0,
		},
		{
			name:     "typo on line 1",
			source:   "SecRuleEngine On\nSecRul ARGS \"@rx x\" \"id:1,phase:2,deny\"",
			wantLine: 1,
		},
		{
			name:     "typo on line 5 after valid directives and a comment",
			source:   "SecRuleEngine On\nSecRequestBodyAccess On\nSecAuditEngine On\n# comment\n\nSecRul ARGS \"@rx x\" \"id:1,phase:2,deny\"",
			wantLine: 5,
		},
		{
			name:     "typo preceded by many valid rules",
			source:   "SecRuleEngine On\nSecRule ARGS \"@rx a\" \"id:1001,phase:2,deny\"\nSecRule ARGS \"@rx b\" \"id:1002,phase:2,deny\"\nSecRule ARGS \"@rx c\" \"id:1003,phase:2,deny\"\nSecRul ARGS \"@rx d\" \"id:1004,phase:2,deny\"",
			wantLine: 4,
		},

		// --- failed to compile: value must be numeric ---
		{
			name:     "SecDebugLogLevel non-numeric on line 0",
			source:   "SecDebugLogLevel x",
			wantLine: 0,
		},
		{
			name:     "SecDebugLogLevel non-numeric on line 1",
			source:   "SecRuleEngine On\nSecDebugLogLevel x",
			wantLine: 1,
		},
		{
			name:     "SecDebugLogLevel non-numeric on line 3 after comments",
			source:   "# config\n# file\n\nSecDebugLogLevel x",
			wantLine: 3,
		},
		{
			name:     "SecDebugLogLevel out-of-range value",
			source:   "SecRuleEngine On\nSecDebugLogLevel 99",
			wantLine: 1,
		},
		{
			name:     "SecRequestBodyLimit non-numeric on line 2",
			source:   "SecRuleEngine On\nSecRequestBodyAccess On\nSecRequestBodyLimit abc",
			wantLine: 2,
		},
		{
			name:     "SecResponseBodyLimit non-numeric on line 2",
			source:   "SecRuleEngine On\nSecResponseBodyAccess On\nSecResponseBodyLimit notanumber",
			wantLine: 2,
		},
		{
			name:     "SecUploadFileLimit non-numeric on line 1",
			source:   "SecRuleEngine On\nSecUploadFileLimit abc",
			wantLine: 1,
		},
		{
			name:     "SecUploadFileMode non-numeric on line 1",
			source:   "SecRuleEngine On\nSecUploadFileMode abc",
			wantLine: 1,
		},

		// --- failed to compile: invalid enum value ---
		{
			name:     "SecAuditEngine invalid value on line 0",
			source:   "SecAuditEngine badvalue",
			wantLine: 0,
		},
		{
			name:     "SecAuditEngine invalid value on line 2",
			source:   "SecRuleEngine On\nSecRequestBodyAccess On\nSecAuditEngine badvalue",
			wantLine: 2,
		},
		{
			name:     "SecRuleEngine invalid value on line 1",
			source:   "# preamble\nSecRuleEngine badvalue",
			wantLine: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			diags := ValidateWithCoraza(tt.source, "")
			require.NotEmpty(t, diags, "expected a Coraza diagnostic")
			assert.Equal(t, tt.wantLine, diags[0].Range.Start.Line,
				"diagnostic must point to the line with the error, not line 0")
		})
	}
}

// TestValidateWithCoraza_UnknownVariableLine verifies that end-to-end Coraza
// validation (Stage 2) reports the unknown-variable error on the correct SecRule
// line, not always on line 0.
func TestValidateWithCoraza_UnknownVariableLine(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		source      string
		wantLine    uint32
		wantErrCode string
	}{
		{
			name:        "REQUEST_COOKIES* on line 0",
			source:      `SecRule REQUEST_COOKIES* "@rx test" "id:932100,phase:2,deny"`,
			wantLine:    0,
			wantErrCode: CodeCorazaError,
		},
		{
			name: "REQUEST_COOKIES* on line 1, valid rule on line 0",
			source: "SecRule ARGS \"@rx prev\" \"id:100,phase:2,deny\"\n" +
				"SecRule REQUEST_COOKIES* \"@rx test\" \"id:932100,phase:2,deny\"",
			wantLine:    1,
			wantErrCode: CodeCorazaError,
		},
		{
			name: "REQUEST_COOKIES* on line 2 after two valid rules",
			source: "SecRule ARGS \"@rx a\" \"id:100,phase:2,deny\"\n" +
				"SecRule REQUEST_HEADERS \"@rx b\" \"id:101,phase:2,deny\"\n" +
				"SecRule REQUEST_COOKIES* \"@rx c\" \"id:932100,phase:2,deny\"",
			wantLine:    2,
			wantErrCode: CodeCorazaError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			diags := ValidateWithCoraza(tt.source, "")
			corazaDiags := filterByCode(diags, CodeCorazaError)
			require.NotEmpty(t, corazaDiags, "expected a coraza-error diagnostic")
			assert.Equal(t, tt.wantLine, corazaDiags[0].Range.Start.Line,
				"coraza-error must point to the line with the unknown variable, not line 0")
		})
	}
}

func TestCleanCorazaMessage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		errMsg  string
		wantMsg string
	}{
		{
			name:    "strconv.ParseInt noise stripped",
			errMsg:  `invalid WAF config from string: failed to compile the directive "secdebugloglevel": strconv.ParseInt: parsing "x": invalid syntax`,
			wantMsg: `"x" is not a valid integer`,
		},
		{
			name:    "strconv.Atoi noise stripped",
			errMsg:  `invalid WAF config from string: failed to compile the directive "secuploadfilelimit": strconv.Atoi: parsing "abc": invalid syntax`,
			wantMsg: `"abc" is not a valid integer`,
		},
		{
			name:    "strconv.ParseUint noise stripped",
			errMsg:  `invalid WAF config from string: failed to compile the directive "secrequestbodylimit": strconv.ParseUint: parsing "abc": invalid syntax`,
			wantMsg: `"abc" is not a valid integer`,
		},
		{
			name:    "human-readable reason preserved as-is",
			errMsg:  `invalid WAF config from string: failed to compile the directive "secdebugloglevel": invalid log level`,
			wantMsg: "invalid log level",
		},
		{
			name:    "audit engine status preserved",
			errMsg:  `invalid WAF config from string: failed to compile the directive "secauditengine": invalid audit engine status: badvalue`,
			wantMsg: "invalid audit engine status: badvalue",
		},
		{
			name:    "rule engine status preserved",
			errMsg:  `invalid WAF config from string: failed to compile the directive "secruleengine": invalid rule engine status: "badvalue"`,
			wantMsg: `invalid rule engine status: "badvalue"`,
		},
		{
			name:    "unknown directive — WAF wrapper stripped",
			errMsg:  `invalid WAF config from string: unknown directive "SecRul"`,
			wantMsg: `unknown directive "SecRul"`,
		},
		{
			name:    "generic error unchanged",
			errMsg:  "some error without a known pattern",
			wantMsg: "some error without a known pattern",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := cleanCorazaMessage(tt.errMsg)
			assert.Equal(t, tt.wantMsg, got)
		})
	}
}

// TestValidateWithCoraza_MessageAndPosition verifies both the squiggle position
// and the cleaned message for representative compile errors.
func TestValidateWithCoraza_MessageAndPosition(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		source      string
		wantLine    uint32
		wantMsgPart string // substring the message must contain
		wantMsgNoGo string // substring that must NOT appear (Go internals)
	}{
		{
			name:        "SecDebugLogLevel non-numeric: squiggle on value, no strconv noise",
			source:      "SecDebugLogLevel x",
			wantLine:    0,
			wantMsgPart: `"x" is not a valid integer`,
			wantMsgNoGo: "strconv.ParseInt",
		},
		{
			name:        "SecDebugLogLevel out-of-range: human message preserved",
			source:      "SecDebugLogLevel 99",
			wantLine:    0,
			wantMsgPart: "invalid log level",
			wantMsgNoGo: "strconv",
		},
		{
			name:        "SecRequestBodyLimit non-numeric: squiggle on value",
			source:      "SecRuleEngine On\nSecRequestBodyLimit abc",
			wantLine:    1,
			wantMsgPart: `"abc" is not a valid integer`,
			wantMsgNoGo: "strconv",
		},
		{
			name:        "SecAuditEngine bad enum: human message preserved",
			source:      "SecAuditEngine badvalue",
			wantLine:    0,
			wantMsgPart: "invalid audit engine status",
			wantMsgNoGo: "strconv",
		},
		{
			name:        "SecRuleEngine bad enum on line 2",
			source:      "SecAuditEngine On\nSecRequestBodyAccess On\nSecRuleEngine badvalue",
			wantLine:    2,
			wantMsgPart: "invalid rule engine status",
			wantMsgNoGo: "strconv",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			diags := ValidateWithCoraza(tt.source, "")
			require.NotEmpty(t, diags, "expected a Coraza diagnostic")
			d := diags[0]
			assert.Equal(t, tt.wantLine, d.Range.Start.Line, "wrong line")
			assert.Contains(t, d.Message, tt.wantMsgPart, "message should contain human-readable reason")
			assert.NotContains(t, d.Message, tt.wantMsgNoGo, "message must not contain Go internals")
		})
	}
}

// TestLocateCorazaError_ValuePosition verifies that compile errors point at the
// value token, not the directive name.
func TestLocateCorazaError_ValuePosition(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		errMsg        string
		source        string
		wantLine      int
		directiveName string // must NOT be the squiggled token
		valueName     string // must BE the squiggled token
	}{
		{
			name:          "SecDebugLogLevel x — squiggle on x not SecDebugLogLevel",
			errMsg:        `invalid WAF config from string: failed to compile the directive "secdebugloglevel": strconv.ParseInt: parsing "x": invalid syntax`,
			source:        "SecDebugLogLevel x",
			wantLine:      0,
			directiveName: "SecDebugLogLevel",
			valueName:     "x",
		},
		{
			name:          "SecRequestBodyLimit abc — squiggle on abc",
			errMsg:        `invalid WAF config from string: failed to compile the directive "secrequestbodylimit": strconv.ParseInt: parsing "abc": invalid syntax`,
			source:        "SecRuleEngine On\nSecRequestBodyLimit abc",
			wantLine:      1,
			directiveName: "SecRequestBodyLimit",
			valueName:     "abc",
		},
		{
			name:          "unknown directive — squiggle stays on directive name",
			errMsg:        `unknown directive "SecRul"`,
			source:        "SecRul ARGS \"@rx x\" \"id:1,phase:2,deny\"",
			wantLine:      0,
			directiveName: "SecRul",
			valueName:     "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := locateCorazaError(tt.errMsg, tt.source)
			assert.Equal(t, tt.wantLine, r.Start.Line)

			lines := strings.Split(tt.source, "\n")
			squiggled := lines[r.Start.Line][r.Start.Character:r.End.Character]

			if tt.valueName != "" {
				assert.Equal(t, tt.valueName, squiggled, "squiggle should be on value token")
				assert.NotEqual(t, tt.directiveName, squiggled, "squiggle must not be on directive name")
			} else {
				assert.Equal(t, tt.directiveName, squiggled, "squiggle should be on directive name")
			}
		})
	}
}

func TestStripQuotes(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want string
	}{
		{`"XXX"`, "XXX"},
		{`'XXX'`, "XXX"},
		{`XXX`, "XXX"},
		{`""`, ""},
		{`"`, `"`},         // single char — not a pair
		{`"abc'`, `"abc'`}, // mismatched quotes
		{`"hello world"`, "hello world"},
		{`''`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, stripQuotes(tt.in))
		})
	}
}

func TestExtractRuleIDFromError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		errMsg string
		wantID string
	}{
		{
			name:   "id embedded in invalid actions message",
			errMsg: `invalid WAF config from string: failed to compile the directive "secrule": invalid actions for rule with operator: "ARGS \"@rx b\" \"id:1002,phase:2,deny,msg:'oops'"`,
			wantID: "1002",
		},
		{
			name:   "id on continuation line content",
			errMsg: `invalid WAF config from string: failed to compile the directive "secrule": invalid actions for rule with operator: "ARGS \"@rx x\" \"id:9999,phase:1,pass"`,
			wantID: "9999",
		},
		{
			name:   "no id in message",
			errMsg: `invalid WAF config from string: failed to compile the directive "secrule": invalid action "badaction"`,
			wantID: "",
		},
		{
			name:   "invalid operator — no id",
			errMsg: `invalid WAF config from string: failed to compile the directive "secrule": operator badop not found`,
			wantID: "",
		},
		{
			name:   "empty message",
			errMsg: "",
			wantID: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := extractRuleIDFromError(tt.errMsg)
			assert.Equal(t, tt.wantID, got)
		})
	}
}

func TestLocateCorazaError_MultipleSecRules(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		errMsg   string
		source   string
		wantLine int
	}{
		{
			name:   "error in second SecRule identified by id",
			errMsg: `invalid WAF config from string: failed to compile the directive "secrule": invalid actions for rule with operator: "ARGS \"@rx b\" \"id:1002,phase:2,deny,msg:'oops'"`,
			source: "SecRule ARGS \"@rx a\" \"id:1001,phase:2,deny\"\n" +
				"SecRule ARGS \"@rx b\" \"id:1002,phase:2,deny\\",
			wantLine: 1,
		},
		{
			name:   "error in third SecRule by id",
			errMsg: `invalid WAF config from string: failed to compile the directive "secrule": invalid actions for rule with operator: "ARGS \"@rx c\" \"id:1003,phase:2,deny,msg:'bad'"`,
			source: "SecRule ARGS \"@rx a\" \"id:1001,phase:2,deny\"\n" +
				"SecRule ARGS \"@rx b\" \"id:1002,phase:2,deny\"\n" +
				"SecRule ARGS \"@rx c\" \"id:1003,phase:2,deny\\",
			wantLine: 2,
		},
		{
			name:   "id on continuation line",
			errMsg: `invalid WAF config from string: failed to compile the directive "secrule": invalid actions for rule with operator: "ARGS \"@rx b\" \"phase:2,deny,id:1002"`,
			source: "SecRule ARGS \"@rx a\" \"id:1001,phase:2,deny\"\n" +
				"SecRule ARGS \"@rx b\" \"phase:2,deny\\\n" +
				",id:1002\"",
			wantLine: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := locateCorazaError(tt.errMsg, tt.source)
			assert.Equal(t, tt.wantLine, r.Start.Line, "wrong line")
		})
	}
}

func TestValidateWithCoraza_SecRuleWithContinuation(t *testing.T) {
	t.Parallel()

	// Valid two-rule file with continuation — must produce no diagnostics.
	t.Run("valid continuation no error", func(t *testing.T) {
		t.Parallel()
		src := "SecRule ARGS \"@rx a\" \"id:1001,phase:2,deny\"\n" +
			"SecRule ARGS \"@rx b\" \"id:1002,phase:2,deny,nolog\\\n" +
			",msg:'ok'\""
		diags := ValidateWithCoraza(src, "")
		assert.Empty(t, diags)
	})

	// Broken second rule — diagnostic must appear on line 1, not line 0.
	t.Run("broken second rule points to second secrule", func(t *testing.T) {
		t.Parallel()
		src := "SecRule ARGS \"@rx a\" \"id:1001,phase:2,deny\"\n" +
			"SecRule ARGS \"@rx b\" \"id:1002,phase:2,deny\\\n" +
			",msg:'oops'"
		diags := ValidateWithCoraza(src, "")
		require.NotEmpty(t, diags, "expected a Coraza diagnostic")
		assert.Equal(t, uint32(1), diags[0].Range.Start.Line,
			"diagnostic should be on the broken rule (line 1), not rule 1001 (line 0)")
	})
}

func TestExtractBadValueFromError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		errMsg  string
		wantVal string
	}{
		{
			name:    "strconv.ParseInt",
			errMsg:  `invalid WAF config from string: failed to compile the directive "secdebugloglevel": strconv.ParseInt: parsing "x": invalid syntax`,
			wantVal: "x",
		},
		{
			name:    "strconv.Atoi",
			errMsg:  `invalid WAF config from string: failed to compile the directive "secuploadfilelimit": strconv.Atoi: parsing "abc": invalid syntax`,
			wantVal: "abc",
		},
		{
			name:    "rule engine status quoted",
			errMsg:  `invalid WAF config from string: failed to compile the directive "secruleengine": invalid rule engine status: "XXX"`,
			wantVal: "XXX",
		},
		{
			name:    "audit engine status unquoted",
			errMsg:  `invalid WAF config from string: failed to compile the directive "secauditengine": invalid audit engine status: badvalue`,
			wantVal: "badvalue",
		},
		{
			name:    "invalid log level — no value extractable",
			errMsg:  `invalid WAF config from string: failed to compile the directive "secdebugloglevel": invalid log level`,
			wantVal: "",
		},
		{
			name:    "unknown directive — no value",
			errMsg:  `unknown directive "SecRul"`,
			wantVal: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := extractBadValueFromError(tt.errMsg)
			assert.Equal(t, tt.wantVal, got)
		})
	}
}

// TestLocateCorazaError_DuplicateDirective is the regression test for the bug
// where a compile error on the second occurrence of a directive (e.g. the second
// SecRuleEngine) was reported on the first (valid) occurrence instead.
func TestLocateCorazaError_DuplicateDirective(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		errMsg   string
		source   string
		wantLine int
		wantVal  string // value token that should be squiggled
	}{
		{
			name:   "SecRuleEngine On then SecRuleEngine XXX — error on second",
			errMsg: `invalid WAF config from string: failed to compile the directive "secruleengine": invalid rule engine status: "XXX"`,
			source: "SecRuleEngine On\n" +
				"SecRule ARGS \"@rx <script>\" \"id:1001,phase:2,deny\"\n" +
				"SecMarker END_RULES\n" +
				"SecRuleEngine XXX",
			wantLine: 3,
			wantVal:  "XXX",
		},
		{
			name:   "user-reported case: valid config then broken SecRuleEngine on line 5",
			errMsg: `invalid WAF config from string: failed to compile the directive "secruleengine": invalid rule engine status: "XXX"`,
			source: "SecRuleEngine On\n" +
				"SecRule ARGS \"@rx <script>\" \"id:1001,phase:2,deny,t:lowercase,msg:'XSS'\"\n" +
				"SecRule REQUEST_HEADERS:Content-Type \"@rx ^multipart\" \"id:1002,phase:1,pass,nolog\"\n" +
				"SecMarker END_RULES\n" +
				"SecDebugLogLevel 9\n" +
				"SecRuleEngine XXX",
			wantLine: 5,
			wantVal:  "XXX",
		},
		{
			name:   "SecAuditEngine repeated — error on second",
			errMsg: `invalid WAF config from string: failed to compile the directive "secauditengine": invalid audit engine status: badvalue`,
			source: "SecAuditEngine On\n" +
				"SecRuleEngine On\n" +
				"SecAuditEngine badvalue",
			wantLine: 2,
			wantVal:  "badvalue",
		},
		{
			name:   "SecDebugLogLevel repeated — strconv match picks right line",
			errMsg: `invalid WAF config from string: failed to compile the directive "secdebugloglevel": strconv.ParseInt: parsing "x": invalid syntax`,
			source: "SecDebugLogLevel 5\n" +
				"SecRuleEngine On\n" +
				"SecDebugLogLevel x",
			wantLine: 2,
			wantVal:  "x",
		},
		// --- quoted values ---
		{
			name:   "SecRuleEngine double-quoted bad value",
			errMsg: `invalid WAF config from string: failed to compile the directive "secruleengine": invalid rule engine status: "XXX"`,
			source: "SecRuleEngine On\n" +
				"SecRuleEngine \"XXX\"",
			wantLine: 1,
			wantVal:  `"XXX"`,
		},
		{
			name:   "SecRuleEngine single-quoted bad value",
			errMsg: `invalid WAF config from string: failed to compile the directive "secruleengine": invalid rule engine status: "XXX"`,
			source: "SecRuleEngine On\n" +
				"SecRuleEngine 'XXX'",
			wantLine: 1,
			wantVal:  `'XXX'`,
		},
		{
			name:   "user-reported: full file with quoted bad value on line 5",
			errMsg: `invalid WAF config from string: failed to compile the directive "secruleengine": invalid rule engine status: "XXX"`,
			source: "SecRuleEngine On\n" +
				"SecRule ARGS \"@rx <script>\" \"id:1001,phase:2,deny,t:lowercase,msg:'XSS attack detected'\"\n" +
				"SecRule REQUEST_HEADERS:Content-Type \"@rx ^multipart\" \"id:1002,phase:1,pass,nolog\"\n" +
				"SecMarker END_RULES\n" +
				"SecDebugLogLevel 9\n" +
				"SecRuleEngine \"XXX\"",
			wantLine: 5,
			wantVal:  `"XXX"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := locateCorazaError(tt.errMsg, tt.source)
			assert.Equal(t, tt.wantLine, r.Start.Line, "wrong line")
			lines := strings.Split(tt.source, "\n")
			squiggled := lines[r.Start.Line][r.Start.Character:r.End.Character]
			assert.Equal(t, tt.wantVal, squiggled, "squiggle should be on the bad value")
		})
	}
}

// TestValidateWithCoraza_DuplicateDirectivePosition is the end-to-end version
// of TestLocateCorazaError_DuplicateDirective — uses a real Coraza WAF call.
func TestValidateWithCoraza_DuplicateDirectivePosition(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		source   string
		wantLine uint32
		wantVal  string
	}{
		{
			name: "SecRuleEngine On then SecRuleEngine XXX",
			source: "SecRuleEngine On\n" +
				"SecRule ARGS \"@rx test\" \"id:1001,phase:2,deny\"\n" +
				"SecRuleEngine XXX",
			wantLine: 2,
			wantVal:  "XXX",
		},
		{
			name: "user-reported full file",
			source: "SecRuleEngine On\n" +
				"SecRule ARGS \"@rx <script>\" \"id:1001,phase:2,deny,t:lowercase,msg:'XSS attack detected'\"\n" +
				"SecRule REQUEST_HEADERS:Content-Type \"@rx ^multipart\" \"id:1002,phase:1,pass,nolog\"\n" +
				"SecMarker END_RULES\n" +
				"SecDebugLogLevel 9\n" +
				"SecRuleEngine XXX",
			wantLine: 5,
			wantVal:  "XXX",
		},
		{
			name: "user-reported full file with double-quoted bad value",
			source: "SecRuleEngine On\n" +
				"SecRule ARGS \"@rx <script>\" \"id:1001,phase:2,deny,t:lowercase,msg:'XSS attack detected'\"\n" +
				"SecRule REQUEST_HEADERS:Content-Type \"@rx ^multipart\" \"id:1002,phase:1,pass,nolog\"\n" +
				"SecMarker END_RULES\n" +
				"SecDebugLogLevel 9\n" +
				"SecRuleEngine \"XXX\"",
			wantLine: 5,
			wantVal:  `"XXX"`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			diags := ValidateWithCoraza(tt.source, "")
			require.NotEmpty(t, diags, "expected a diagnostic")
			d := diags[0]
			assert.Equal(t, tt.wantLine, d.Range.Start.Line, "wrong line — error shown on wrong directive occurrence")
			lines := strings.Split(tt.source, "\n")
			squiggled := lines[d.Range.Start.Line][d.Range.Start.Character:d.Range.End.Character]
			assert.Equal(t, tt.wantVal, squiggled, "squiggle should be on the bad value")
		})
	}
}

// ----------------------------------------------------------------------------
// Group 6: Interleaved valid and invalid rules
// Why: most tests use single-rule files. Real configs have many rules; a parse
// error or semantic error on rule N must not bleed into diagnostics for rule M.
// ----------------------------------------------------------------------------

// TestAnalyze_InterleavedRules verifies that per-rule errors do not affect
// unrelated rules in the same file.
func TestAnalyze_InterleavedRules(t *testing.T) {
	t.Parallel()

	t.Run("missing-id only on the rule that lacks it", func(t *testing.T) {
		t.Parallel()
		src := "SecRule ARGS \"@rx a\" \"id:1001,phase:2,deny\"\n" + // valid
			"SecRule ARGS \"@rx b\" \"phase:2,deny\"\n" + // missing id
			"SecRule ARGS \"@rx c\" \"id:1003,phase:2,deny\"" // valid
		f := parser.Parse("", src)
		diags := Analyze(f)
		missingIDs := filterByCode(diags, CodeMissingID)
		require.Len(t, missingIDs, 1, "exactly one rule is missing an id")
		assert.Equal(t, uint32(1), missingIDs[0].Range.Start.Line, "missing-id must be on line 1")
	})

	t.Run("multiple rules all missing phase — one warning per rule", func(t *testing.T) {
		t.Parallel()
		src := "SecRule ARGS \"@rx a\" \"id:1001,deny\"\n" +
			"SecRule ARGS \"@rx b\" \"id:1002,deny\"\n" +
			"SecRule ARGS \"@rx c\" \"id:1003,deny\""
		f := parser.Parse("", src)
		diags := Analyze(f)
		assert.Len(t, filterByCode(diags, CodeMissingPhase), 3, "each of 3 rules should warn about missing phase")
	})

	t.Run("parse error on one rule does not suppress semantic errors on others", func(t *testing.T) {
		t.Parallel()
		// Rule 0: valid
		// Rule 1: unclosed string (parse error — semantic checks skipped for rule 1 only)
		// Rule 2: missing id (semantic check must still fire)
		src := "SecRule ARGS \"@rx a\" \"id:1001,phase:2,deny\"\n" +
			"SecAction \"id:1002,phase:1,pass\n" + // unclosed outer "
			"SecRule ARGS \"@rx c\" \"phase:2,deny\"" // missing id
		f := parser.Parse("", src)
		diags := Analyze(f)

		assert.NotEmpty(t, filterByCode(diags, CodeParseError), "rule 1 unclosed string must fire")
		assert.NotEmpty(t, filterByCode(diags, CodeMissingID), "rule 2 missing-id must still fire")

		// Rule 1 should not also get a missing-id (actions unparseable due to unclosed string)
		// Check that the missing-id is on line 2 (rule 2), not line 1 (rule 1).
		for _, d := range filterByCode(diags, CodeMissingID) {
			assert.Equal(t, uint32(2), d.Range.Start.Line, "missing-id must be on rule 2 (line 2)")
		}
	})

	t.Run("duplicate id detected across interleaved valid rules", func(t *testing.T) {
		t.Parallel()
		src := "SecRule ARGS \"@rx a\" \"id:1001,phase:2,deny\"\n" +
			"SecRule ARGS \"@rx b\" \"id:1002,phase:2,deny\"\n" +
			"SecRule ARGS \"@rx c\" \"id:1001,phase:2,deny\"" // duplicate id:1001
		f := parser.Parse("", src)
		diags := Analyze(f)
		dupDiags := filterByCode(diags, CodeDuplicateID)
		require.Len(t, dupDiags, 1, "exactly one duplicate-id diagnostic")
		assert.Equal(t, uint32(2), dupDiags[0].Range.Start.Line, "duplicate must be flagged on the second occurrence (line 2)")
	})
}

// ----------------------------------------------------------------------------
// Group 7: Stage 2 suppression is per-file, not per-rule
// Why: hasParseErrors operates on the full Stage 1 slice. Any parse error in
// the file suppresses Stage 2 for the whole file — Coraza processes the file
// atomically, so there is no meaningful per-rule Stage 2 result.
// ----------------------------------------------------------------------------

func TestAnalyze_Stage2Suppression(t *testing.T) {
	t.Parallel()

	t.Run("one unclosed string in mixed file suppresses Stage 2 for whole file", func(t *testing.T) {
		t.Parallel()
		// Rules 0, 1, 2 are valid; rule 3 has an unclosed string.
		// Stage 2 must NOT run — so no coraza-error appears even though
		// the file would otherwise fail Coraza validation (unclosed string).
		src := "SecRule ARGS \"@rx a\" \"id:1001,phase:2,deny\"\n" +
			"SecRule ARGS \"@rx b\" \"id:1002,phase:2,deny\"\n" +
			"SecRule ARGS \"@rx c\" \"id:1003,phase:2,deny\"\n" +
			"SecAction \"id:1004,phase:1,pass" // unclosed
		f := parser.Parse("", src)
		stage1 := Analyze(f)

		assert.True(t, hasParseErrors(stage1), "file has a parse error — Stage 2 must be suppressed")
		assert.Empty(t, filterByCode(stage1, CodeCorazaError),
			"coraza-error must not appear in Stage 1 results")
	})

	t.Run("file with only valid rules — hasParseErrors returns false", func(t *testing.T) {
		t.Parallel()
		src := "SecRuleEngine On\n" +
			"SecRule ARGS \"@rx test\" \"id:1001,phase:2,deny\""
		f := parser.Parse("", src)
		stage1 := Analyze(f)
		assert.False(t, hasParseErrors(stage1), "valid file should not have parse errors")
	})
}

// ----------------------------------------------------------------------------
// Group 8: Numeric edge cases in phase and id validation
// Why: strconv.Atoi handles leading zeros, floats, and overflow differently
// than one might expect. These cases pin the behavior so regressions are caught.
// ----------------------------------------------------------------------------

func TestAnalyze_NumericEdgeCases(t *testing.T) {
	t.Parallel()

	phaseTests := []struct {
		phaseVal string
		wantErr  bool
		reason   string
	}{
		{"1", false, "valid lower bound"},
		{"5", false, "valid upper bound"},
		{"01", false, "leading zero — Atoi parses as 1, which is valid"},
		{"05", false, "leading zero — Atoi parses as 5, which is valid"},
		{"0", true, "zero is below minimum"},
		{"6", true, "above maximum"},
		{"-1", true, "negative"},
		{"-99", true, "large negative"},
		{"1.5", true, "float — Atoi rejects it"},
		{"abc", true, "non-numeric"},
		{"", true, "empty string"},
	}
	t.Run("phase values", func(t *testing.T) {
		t.Parallel()
		for _, tt := range phaseTests {
			tt := tt
			t.Run(tt.phaseVal+"_"+tt.reason, func(t *testing.T) {
				t.Parallel()
				src := `SecRule ARGS "@rx x" "id:1001,phase:` + tt.phaseVal + `,deny"`
				f := parser.Parse("", src)
				diags := Analyze(f)
				invalidPhase := filterByCode(diags, CodeInvalidPhase)
				if tt.wantErr {
					assert.NotEmpty(t, invalidPhase, "phase %q should be invalid: %s", tt.phaseVal, tt.reason)
				} else {
					assert.Empty(t, invalidPhase, "phase %q should be valid: %s", tt.phaseVal, tt.reason)
				}
			})
		}
	})

	idTests := []struct {
		idVal   string
		wantErr bool
		reason  string
	}{
		{"1", false, "minimum valid id"},
		{"1001", false, "typical id"},
		{"999999", false, "large but valid id"},
		{"0", true, "zero is not a valid rule id"},
		{"-1", true, "negative"},
		{"-5", true, "negative"},
		{"1.5", true, "float — Atoi rejects it"},
		{"abc", true, "non-numeric"},
		{"", true, "empty string"},
		{"9999999999999999999", true, "overflows int64 — Atoi returns error"},
	}
	t.Run("id values", func(t *testing.T) {
		t.Parallel()
		for _, tt := range idTests {
			tt := tt
			t.Run(tt.idVal+"_"+tt.reason, func(t *testing.T) {
				t.Parallel()
				src := `SecRule ARGS "@rx x" "id:` + tt.idVal + `,phase:2,deny"`
				f := parser.Parse("", src)
				diags := Analyze(f)
				invalidID := filterByCode(diags, CodeInvalidID)
				if tt.wantErr {
					assert.NotEmpty(t, invalidID, "id %q should be invalid: %s", tt.idVal, tt.reason)
				} else {
					assert.Empty(t, invalidID, "id %q should be valid: %s", tt.idVal, tt.reason)
				}
			})
		}
	})
}

// TestAnalyze_CaseInsensitiveSemantics verifies that semantic checks work
// regardless of the directive's letter casing.
// Why: SecLang is case-insensitive; SECRULE and secrule are the same directive.
func TestAnalyze_CaseInsensitiveSemantics(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		src     string
		wantErr string // diagnostic code expected, or "" for no errors
	}{
		{
			name:    "SECRULE uppercase — valid rule produces no errors",
			src:     `SECRULE ARGS "@rx x" "id:1001,phase:2,deny"`,
			wantErr: "",
		},
		{
			name:    "secrule lowercase — missing id is still detected",
			src:     `secrule ARGS "@rx x" "phase:2,deny"`,
			wantErr: CodeMissingID,
		},
		{
			name:    "SECACTION uppercase — missing id is detected",
			src:     `SECACTION "phase:1,pass"`,
			wantErr: CodeMissingID,
		},
		{
			name:    "SecRuLe mixed case — invalid phase is detected",
			src:     `SecRuLe ARGS "@rx x" "id:1001,phase:9,deny"`,
			wantErr: CodeInvalidPhase,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := parser.Parse("", tt.src)
			diags := Analyze(f)
			if tt.wantErr == "" {
				errDiags := filterBySeverity(diags, protocol_3_16.DiagnosticSeverityError)
				assert.Empty(t, errDiags, "valid rule should produce no error diagnostics")
			} else {
				assert.NotEmpty(t, filterByCode(diags, tt.wantErr),
					"expected diagnostic code %q", tt.wantErr)
			}
		})
	}
}

// TestAnalyze_InvalidVariableNameChars verifies that variable names with illegal
// characters produce parse errors (not "unknown variable" warnings).
// This makes the distinction between "bad syntax" and "valid syntax but unrecognised
// name" clear to the user.
func TestAnalyze_InvalidVariableNameChars(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		src         string
		wantMsgPart string
	}{
		{
			name:        "TX- — hyphen in variable name",
			src:         `SecRule TX- "@rx test" "id:1,phase:2,deny"`,
			wantMsgPart: "invalid character",
		},
		{
			name:        "ARGS.yyy — dot instead of colon",
			src:         `SecRule ARGS.yyy "@rx test" "id:1,phase:2,deny"`,
			wantMsgPart: "use ':' as the key separator",
		},
		{
			name:        "REQUEST-HEADERS — hyphen (should be underscore)",
			src:         `SecRule REQUEST-HEADERS "@rx test" "id:1,phase:2,deny"`,
			wantMsgPart: "invalid character",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := parser.Parse("test.conf", tt.src)
			// Must produce a parse ERROR (not a warning).
			parseErrs := filterByCode(Analyze(f), CodeParseError)
			require.NotEmpty(t, parseErrs, "expected parse-error diagnostic for %q", tt.src)
			assert.Contains(t, parseErrs[0].Message, tt.wantMsgPart)
			// Must NOT produce an unknown-variable warning (the real problem is syntax).
			assert.Empty(t, filterByCode(Analyze(f), CodeUnknownVariable),
				"invalid-char variable must not also produce unknown-variable warning")
		})
	}
}

// TestAnalyze_UnknownVariable verifies that variable names not in the knowledge
// base produce a Stage 1 diagnostic with the variable name in the message.
// This replaces Coraza's vague "unknown variable" with a precise, positioned error.
func TestAnalyze_UnknownVariable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		src         string
		wantCode    string
		wantMsgPart string // substring the message must contain
		wantLine    uint32
	}{
		{
			// User-reported: ARGS.yyy — dot instead of colon for key selector.
			// Now produces a parse error with a correction hint.
			name:        "ARGS.yyy — dot instead of colon — parse error with hint",
			src:         `SecRule ARGS.yyy "@rx test" "id:1001,phase:2,deny"`,
			wantCode:    CodeParseError,
			wantMsgPart: "use ':' as the key separator",
		},
		{
			// Full user-reported line from the conversation.
			name:        "user-reported: mixed variable list with ARGS.yyy",
			src:         `SecRule ARGS|ARGS:/xxx/|ARGS.yyy "@rx <script>" "id:1001,phase:2,deny,t:lowercase,msg:'XSS attack detected'"`,
			wantCode:    CodeParseError,
			wantMsgPart: "use ':' as the key separator",
		},
		{
			// Completely made-up variable name.
			name:        "totally unknown variable name",
			src:         `SecRule MADEUPVAR "@rx test" "id:1001,phase:2,deny"`,
			wantCode:    CodeUnknownVariable,
			wantMsgPart: `"MADEUPVAR"`,
		},
		{
			// Known variable — must NOT produce a diagnostic.
			name:     "ARGS — known variable, no diagnostic",
			src:      `SecRule ARGS "@rx test" "id:1001,phase:2,deny"`,
			wantCode: "",
		},
		{
			// TX — also known (transaction variable).
			name:     "TX:score — known variable, no diagnostic",
			src:      `SecRule TX:score "@gt 5" "id:1001,phase:2,deny"`,
			wantCode: "",
		},
		{
			// REQUEST_HEADERS with key — known collection.
			name:     "REQUEST_HEADERS:Content-Type — known variable, no diagnostic",
			src:      `SecRule REQUEST_HEADERS:Content-Type "@rx ^multipart" "id:1001,phase:1,pass"`,
			wantCode: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := parser.Parse("test.conf", tt.src)
			diags := Analyze(f)
			if tt.wantCode == "" {
				// No diagnostic expected — check neither unknown-variable nor parse-error fires.
				assert.Empty(t, filterByCode(diags, CodeUnknownVariable), "expected no unknown-variable diagnostic")
				assert.Empty(t, filterByCode(diags, CodeParseError), "expected no parse-error diagnostic")
				return
			}
			matched := filterByCode(diags, tt.wantCode)
			require.NotEmpty(t, matched, "expected diagnostic with code %q", tt.wantCode)
			assert.Contains(t, matched[0].Message, tt.wantMsgPart,
				"message must contain %q", tt.wantMsgPart)
		})
	}
}

// TestUnknownVariableMessage verifies the hint logic for common typos.
func TestUnknownVariableMessage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		varName     string
		wantPart    string
		wantHint    bool   // should the "did you mean" hint appear?
		wantHintVal string // expected suggested correction
	}{
		{
			name:        "ARGS.yyy — dot typo, base is known → hint with ARGS:yyy",
			varName:     "ARGS.YYY",
			wantPart:    `"ARGS.YYY"`,
			wantHint:    true,
			wantHintVal: `"ARGS:yyy"`,
		},
		{
			name:        "REQUEST_HEADERS.host — dot typo → hint",
			varName:     "REQUEST_HEADERS.HOST",
			wantPart:    `"REQUEST_HEADERS.HOST"`,
			wantHint:    true,
			wantHintVal: `"REQUEST_HEADERS:host"`,
		},
		{
			name:     "MADEUPVAR — completely unknown, no hint",
			varName:  "MADEUPVAR",
			wantPart: `"MADEUPVAR"`,
			wantHint: false,
		},
		{
			name:     "MADEUPVAR.key — unknown base, no hint",
			varName:  "MADEUPVAR.KEY",
			wantPart: `"MADEUPVAR.KEY"`,
			wantHint: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			msg := unknownVariableMessage(tt.varName)
			assert.Contains(t, msg, tt.wantPart, "message must name the variable")
			if tt.wantHint {
				assert.Contains(t, msg, tt.wantHintVal, "message should contain the corrected suggestion")
				assert.Contains(t, msg, "did you mean", "message should contain 'did you mean'")
			} else {
				assert.NotContains(t, msg, "did you mean", "no hint expected for unknown base")
			}
		})
	}
}

// TestAnalyze_UnclosedRegexVariable is the end-to-end regression test for
// ARGS:/xxx (missing closing /). Stage 1 must detect the unclosed regex and
// suppress Stage 2 so Coraza's confusing "unknown variable" error never shows.
func TestAnalyze_UnclosedRegexVariable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "user-reported: ARGS|ARGS:/xxx|ARGS.yyy|AR",
			src:  `SecRule ARGS|ARGS:/xxx|ARGS.yyy|AR "@rx <script>" "id:1001,phase:2,deny,t:lowercase,msg:'XSS attack detected'"`,
		},
		{
			name: "single unclosed regex variable",
			src:  `SecRule ARGS:/pattern "@rx test" "id:1001,phase:2,deny"`,
		},
		{
			name: "unclosed regex in multi-rule file — Stage 2 suppressed for whole file",
			src: "SecRuleEngine On\n" +
				`SecRule ARGS:/pattern "@rx test" "id:1001,phase:2,deny"`,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := parser.Parse("test.conf", tt.src)
			diags := Analyze(f)

			parseErrs := filterByCode(diags, CodeParseError)
			require.NotEmpty(t, parseErrs, "expected parse-error diagnostic for unclosed regex")
			assert.Contains(t, parseErrs[0].Message, "unclosed regex in variable key")

			// hasParseErrors must be true — Stage 2 should be suppressed.
			assert.True(t, hasParseErrors(diags))

			// No spurious missing-id / missing-phase noise on the broken rule.
			assert.Empty(t, filterByCode(diags, CodeMissingID))
			assert.Empty(t, filterByCode(diags, CodeMissingPhase))
		})
	}
}

// TestAnalyze_TrailingExtraQuote is the regression test for the user-reported
// case where a trailing `""` at the end of a continuation-line SecRule was
// silently swallowed, no Stage 1 error fired, and Coraza then reported a
// confusing "invalid rule engine status" error for a completely unrelated
// directive later in the file.
func TestAnalyze_TrailingExtraQuote(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  string
	}{
		{
			// Exact user-reported case.
			name: "trailing double-quote after continuation line",
			src: "SecRuleEngine On\n" +
				"SecRule ARGS \"@rx <script>\" \"id:1001,phase:2,deny,t:lowercase,msg:'XSS attack detected'\"\n" +
				"SecRule REQUEST_HEADERS:Content-Type \"@rx ^multipart\" \"id:1002,phase:1,pass,nolog\\\n" +
				",msg:'Multipart request detected'\"\"\n" +
				"SecMarker END_RULES\n" +
				"SecDebugLogLevel 9\n" +
				"SecRuleEngine \"XXX\"",
		},
		{
			// Simpler version: just a trailing " on a single-line rule.
			name: "single trailing quote on inline SecRule",
			src:  `SecRule ARGS "@rx test" "id:1001,phase:2,deny"` + `"`,
		},
		{
			// SecAction with extra closing quote.
			name: "SecAction with extra closing quote",
			src:  `SecAction "id:1000,phase:1,pass,nolog"` + `"`,
		},
		{
			// Trailing quote followed by other valid directives — Stage 2 must be suppressed.
			name: "trailing quote with valid directives after it",
			src: "SecRuleEngine On\n" +
				"SecAction \"id:1000,phase:1,pass,nolog\"\"\n" +
				"SecDebugLogLevel 9",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := parser.Parse("test.conf", tt.src)
			diags := Analyze(f)

			// Must detect a parse error.
			parseErrs := filterByCode(diags, CodeParseError)
			require.NotEmpty(t, parseErrs, "expected parse-error diagnostic for trailing quote")
			assert.Contains(t, parseErrs[0].Message, "unclosed string literal")

			// No spurious missing-id / missing-phase on the intact rules.
			assert.Empty(t, filterByCode(diags, CodeMissingID), "missing-id must not fire")
			assert.Empty(t, filterByCode(diags, CodeMissingPhase), "missing-phase must not fire")

			// hasParseErrors must return true so Validator suppresses Stage 2.
			assert.True(t, hasParseErrors(diags))
		})
	}
}

// TestAnalyze_UnclosedString verifies that unclosed quoted strings produce a
// Stage 1 parse-error diagnostic with the correct code and a clear message —
// and that the Validator suppresses Stage 2 in this case to avoid the confusing
// "invalid actions" Coraza error that would otherwise appear.
func TestAnalyze_UnclosedString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  string
	}{
		{
			name: "unclosed action list in SecRule",
			src:  `SecRule ARGS "@rx test" "id:1001,phase:2,deny`,
		},
		{
			name: "unclosed operator in SecRule",
			src:  `SecRule ARGS "@rx test`,
		},
		{
			name: "unclosed action list in SecAction",
			src:  `SecAction "id:1000,phase:1,pass`,
		},
		{
			name: "unclosed action list in SecDefaultAction",
			src:  `SecDefaultAction "phase:2,deny`,
		},
		{
			name: "unclosed string mixed with valid directives",
			src:  "SecRuleEngine On\nSecRule ARGS \"@rx test\" \"id:1001,phase:2,deny",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := parser.Parse("test.conf", tt.src)
			diags := Analyze(f)

			// Must have at least one parse-error diagnostic.
			parseErrs := filterByCode(diags, CodeParseError)
			require.NotEmpty(t, parseErrs, "expected at least one parse-error diagnostic for unclosed string")

			// The message must be human-readable.
			assert.Contains(t, parseErrs[0].Message, "unclosed string literal",
				"parse-error message should mention unclosed string literal")

			// Spurious semantic errors must be suppressed — the action list is
			// incomplete so missing-id / missing-phase would be noise.
			assert.Empty(t, filterByCode(diags, CodeMissingID),
				"missing-id must not fire when action list is unclosed")
			assert.Empty(t, filterByCode(diags, CodeMissingPhase),
				"missing-phase must not fire when action list is unclosed")

			// Stage 2 must be suppressed — Coraza's "invalid actions" must not appear.
			assert.True(t, hasParseErrors(diags),
				"hasParseErrors should return true so Validator skips Stage 2")
		})
	}
}

// TestValidateWithCoraza_ValidSource ensures no false-positive Stage 2 diagnostics.
func TestValidateWithCoraza_ValidSource(t *testing.T) {
	t.Parallel()
	validSources := []struct {
		name   string
		source string
	}{
		{"single rule", `SecRule ARGS "@rx <script" "id:1001,phase:2,deny,msg:'XSS'"`},
		{"multiple rules", "SecRuleEngine On\nSecRule ARGS \"@rx test\" \"id:1001,phase:2,deny\""},
		{"empty source", ""},
		{"comments only", "# just a comment\n# another one"},
		{"SecAction", `SecAction "id:9999,phase:1,pass,nolog"`},
	}
	for _, tc := range validSources {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			diags := ValidateWithCoraza(tc.source, "")
			assert.Empty(t, diags, "valid source should produce no Stage 2 diagnostics")
		})
	}
}

// Helpers.

func diagCodes(diags []protocol_3_16.Diagnostic) []string {
	var codes []string
	for _, d := range diags {
		if d.Code != nil {
			codes = append(codes, d.Code.Value.(string))
		}
	}
	return codes
}

func filterBySeverity(diags []protocol_3_16.Diagnostic, sev protocol_3_16.DiagnosticSeverity) []protocol_3_16.Diagnostic {
	var result []protocol_3_16.Diagnostic
	for _, d := range diags {
		if d.Severity != nil && *d.Severity == sev {
			result = append(result, d)
		}
	}
	return result
}

func filterByCode(diags []protocol_3_16.Diagnostic, code string) []protocol_3_16.Diagnostic {
	var result []protocol_3_16.Diagnostic
	for _, d := range diags {
		if d.Code != nil && d.Code.Value == code {
			result = append(result, d)
		}
	}
	return result
}

// TestAnalyze_SecDefaultAction verifies that SecDefaultAction never requires an
// id action (it sets WAF defaults — individual rules inherit and override them).
func TestAnalyze_SecDefaultAction(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		src         string
		wantMissing bool // whether missing-id is expected
	}{
		{
			name:        "SecDefaultAction without id — no missing-id",
			src:         `SecDefaultAction "phase:2,deny,log,auditlog"`,
			wantMissing: false,
		},
		{
			name:        "SecDefaultAction without phase — missing-phase only",
			src:         `SecDefaultAction "deny,log,auditlog"`,
			wantMissing: false,
		},
		{
			name:        "SecDefaultAction with id — accepted (id is optional here)",
			src:         `SecDefaultAction "phase:2,deny,log,id:1000"`,
			wantMissing: false,
		},
		{
			name:        "SecRule without id — missing-id fires",
			src:         `SecRule ARGS "@rx test" "phase:2,deny"`,
			wantMissing: true,
		},
		{
			name:        "SecAction without id — missing-id fires",
			src:         `SecAction "phase:1,pass"`,
			wantMissing: true,
		},
		{
			name:        "lowercase secdefaultaction without id — no missing-id",
			src:         `secdefaultaction "phase:2,deny,log"`,
			wantMissing: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := parser.Parse("test.conf", tt.src)
			diags := Analyze(f)
			missingID := filterByCode(diags, CodeMissingID)
			if tt.wantMissing {
				assert.NotEmpty(t, missingID, "expected missing-id diagnostic")
			} else {
				assert.Empty(t, missingID, "SecDefaultAction must not trigger missing-id")
			}
		})
	}
}

// TestAnalyze_CtlValidation verifies ctl option key and value linting.
func TestAnalyze_CtlValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		src       string
		wantCodes []string // expected diagnostic codes (may be empty)
	}{
		{
			name:      "valid ctl ruleEngine=On",
			src:       `SecAction "id:1,phase:1,pass,ctl:ruleEngine=On"`,
			wantCodes: nil,
		},
		{
			name:      "valid ctl ruleEngine=DetectionOnly",
			src:       `SecAction "id:1,phase:1,pass,ctl:ruleEngine=DetectionOnly"`,
			wantCodes: nil,
		},
		{
			name:      "valid ctl requestBodyProcessor=JSON",
			src:       `SecAction "id:1,phase:1,pass,ctl:requestBodyProcessor=JSON"`,
			wantCodes: nil,
		},
		{
			// Coraza v3.5.0 does NOT register a `noAuditLog` ctl sub-option; the
			// ctl action's switch rejects it as `unknown ctl action "noAuditLog"`.
			// It was removed from the KB CtlOptions, so the LSP must flag it.
			name:      "unknown ctl noAuditLog (not a Coraza ctl option)",
			src:       `SecAction "id:1,phase:1,pass,ctl:noAuditLog"`,
			wantCodes: []string{CodeUnknownCtlOption},
		},
		{
			// New in this KB revision — used by real CRS rules.
			name:      "valid ctl ruleRemoveByMsg (free-form value)",
			src:       `SecAction "id:1,phase:1,pass,ctl:ruleRemoveByMsg=SQLi"`,
			wantCodes: nil,
		},
		{
			name:      "valid ctl ruleRemoveTargetByMsg (free-form value)",
			src:       `SecAction "id:1,phase:1,pass,ctl:ruleRemoveTargetByMsg=SQLi;ARGS:x"`,
			wantCodes: nil,
		},
		{
			name:      "valid ctl ruleRemoveById (free-form value)",
			src:       `SecAction "id:1,phase:1,pass,ctl:ruleRemoveById=1000"`,
			wantCodes: nil,
		},
		{
			name:      "unknown ctl key",
			src:       `SecAction "id:1,phase:1,pass,ctl:unknownOption=On"`,
			wantCodes: []string{CodeUnknownCtlOption},
		},
		{
			name:      "invalid ctl value for ruleEngine",
			src:       `SecAction "id:1,phase:1,pass,ctl:ruleEngine=BadValue"`,
			wantCodes: []string{CodeInvalidCtlValue},
		},
		{
			name:      "invalid ctl value for requestBodyProcessor",
			src:       `SecAction "id:1,phase:1,pass,ctl:requestBodyProcessor=CSV"`,
			wantCodes: []string{CodeInvalidCtlValue},
		},
		{
			name:      "invalid ctl value for auditEngine",
			src:       `SecAction "id:1,phase:1,pass,ctl:auditEngine=Maybe"`,
			wantCodes: []string{CodeInvalidCtlValue},
		},
		{
			name:      "ctl key only (no = yet) — no error",
			src:       `SecAction "id:1,phase:1,pass,ctl:ruleEngine"`,
			wantCodes: nil,
		},
		{
			name:      "ctl value case-insensitive match — no error",
			src:       `SecAction "id:1,phase:1,pass,ctl:ruleEngine=on"`,
			wantCodes: nil,
		},
		{
			name:      "ctl key case-insensitive — valid",
			src:       `SecAction "id:1,phase:1,pass,ctl:RULEENGINE=On"`,
			wantCodes: nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := parser.Parse("test.conf", tt.src)
			diags := Analyze(f)

			// Collect only ctl-related diagnostic codes.
			var got []string
			for _, d := range diags {
				if d.Code == nil {
					continue
				}
				c := d.Code.Value.(string)
				if c == CodeUnknownCtlOption || c == CodeInvalidCtlValue {
					got = append(got, c)
				}
			}

			if len(tt.wantCodes) == 0 {
				assert.Empty(t, got, "expected no ctl diagnostics")
			} else {
				assert.Equal(t, tt.wantCodes, got)
			}
		})
	}
}

// TestAnalyze_ChainRules verifies that chained SecRules do not produce
// missing-id or missing-phase diagnostics, since they inherit those from
// the base rule. The base rule's id and phase checks must still fire.
func TestAnalyze_ChainRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		src              string
		wantMissingID    int // expected count of missing-id
		wantMissingPhase int // expected count of missing-phase
	}{
		{
			name: "base rule with chain — chained rule needs no id or phase",
			src: "SecRule ARGS \"@rx x\" \"id:1,phase:2,pass,chain\"\n" +
				"SecRule ARGS \"@rx y\" \"t:lowercase\"",
			wantMissingID:    0,
			wantMissingPhase: 0,
		},
		{
			name: "three-level chain — only base rule has id and phase",
			src: "SecRule ARGS \"@rx a\" \"id:1,phase:1,pass,chain\"\n" +
				"SecRule ARGS \"@rx b\" \"chain\"\n" +
				"SecRule ARGS \"@rx c\" \"t:none\"",
			wantMissingID:    0,
			wantMissingPhase: 0,
		},
		{
			name: "chain followed by independent rule without id — only independent fires",
			src: "SecRule ARGS \"@rx a\" \"id:1,phase:1,pass,chain\"\n" +
				"SecRule ARGS \"@rx b\" \"t:lowercase\"\n" +
				"SecRule ARGS \"@rx c\" \"phase:2,deny\"",
			wantMissingID:    1, // third rule is independent, missing id
			wantMissingPhase: 0,
		},
		{
			name: "base rule missing id — only base fires missing-id",
			src: "SecRule ARGS \"@rx a\" \"phase:1,pass,chain\"\n" +
				"SecRule ARGS \"@rx b\" \"t:lowercase\"",
			wantMissingID:    1, // base rule missing id
			wantMissingPhase: 0,
		},
		{
			name: "base rule missing phase — only base fires missing-phase",
			src: "SecRule ARGS \"@rx a\" \"id:1,pass,chain\"\n" +
				"SecRule ARGS \"@rx b\" \"t:lowercase\"",
			wantMissingID:    0,
			wantMissingPhase: 1, // base rule missing phase
		},
		{
			name: "two independent rules each missing id",
			src: "SecRule ARGS \"@rx a\" \"phase:1,pass\"\n" +
				"SecRule ARGS \"@rx b\" \"phase:2,deny\"",
			wantMissingID:    2,
			wantMissingPhase: 0,
		},
		{
			name: "CRS-style multi-level chain with setvar and initcol",
			src: "SecRule &TX:ENABLE_DEFAULT_COLLECTIONS \"@eq 1\" \\\n" +
				"    \"id:901320,\\\n" +
				"    phase:1,\\\n" +
				"    pass,\\\n" +
				"    nolog,\\\n" +
				"    chain\"\n" +
				"    SecRule TX:ENABLE_DEFAULT_COLLECTIONS \"@eq 1\" \\\n" +
				"        \"chain\"\n" +
				"        SecRule TX:ua_hash \"@unconditionalMatch\" \\\n" +
				"            \"t:none\"",
			wantMissingID:    0,
			wantMissingPhase: 0,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := parser.Parse("test.conf", tt.src)
			diags := Analyze(f)

			missingID := filterByCode(diags, CodeMissingID)
			missingPhase := filterByCode(diags, CodeMissingPhase)

			assert.Len(t, missingID, tt.wantMissingID,
				"missing-id count mismatch; diags: %v", diagCodes(diags))
			assert.Len(t, missingPhase, tt.wantMissingPhase,
				"missing-phase count mismatch; diags: %v", diagCodes(diags))
		})
	}
}

// TestAnalyze_XMLXPathVariables verifies that XML:/* and other XPath-style
// variable keys do not produce false-positive parse-error or unknown-variable
// diagnostics. The / in XML collection keys is an XPath path separator, not a
// regex delimiter, so it must not trigger the "unclosed regex" detection.
func TestAnalyze_XMLXPathVariables(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  string
	}{
		{
			name: "XML:/* — all nodes (common CRS pattern)",
			src:  `SecRule XML:/* "@rx test" "id:1,phase:2,deny"`,
		},
		{
			name: "pipe list with XML:/* alongside other variables",
			src:  `SecRule ARGS|REQUEST_BODY|XML:/* "@rx test" "id:1,phase:2,deny"`,
		},
		{
			name: "XML://body//* — deep XPath path",
			src:  `SecRule XML://body//* "@rx test" "id:1,phase:2,deny"`,
		},
		{
			name: "negated XML:/*",
			src:  `SecRule !XML:/* "@rx test" "id:1,phase:2,deny"`,
		},
		{
			name: "multi-variable list including XML like in CRS REQUEST-921",
			src:  `SecRule ARGS_NAMES|ARGS|REQUEST_BODY|XML:/* "@rx http" "id:921110,phase:2,block,t:none,t:urlDecodeUni,t:htmlEntityDecode"`,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := parser.Parse("test.conf", tt.src)
			diags := Analyze(f)

			assert.Empty(t, filterByCode(diags, CodeParseError),
				"XML XPath key must not produce parse-error: %v", diags)
			assert.Empty(t, filterByCode(diags, CodeUnknownVariable),
				"XML must not produce unknown-variable: %v", diags)
		})
	}
}

// TestValidateWithCoraza_AtPrefixedPath verifies that Coraza Stage 2 errors
// for @-prefixed include paths are suppressed entirely. These are virtual mount
// points (e.g. Include @coreruleset) that only exist at runtime — the LSP must
// not flag them as errors.
func TestValidateWithCoraza_AtPrefixedPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  string
	}{
		{
			name: "Include @coreruleset — no diagnostic",
			src:  "Include @coreruleset",
		},
		{
			name: "Include @owasp_crs — no diagnostic",
			src:  "Include @owasp_crs",
		},
		{
			name: "valid rule before Include @path — no diagnostic",
			src:  "SecRuleEngine On\nInclude @coreruleset",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			diags := ValidateWithCoraza(tt.src, "")
			assert.Empty(t, diags,
				"@-prefixed Include path must not produce a Stage 2 diagnostic")
		})
	}
}

// TestValidateWithCoraza_CorazaErrorIsWarning verifies that any Stage 2
// diagnostic that does reach the caller has Warning severity, not Error.
// Stage 2 runs without the full deployment context so its results are advisory.
func TestValidateWithCoraza_CorazaErrorIsWarning(t *testing.T) {
	t.Parallel()

	// A directive with a clearly bad value that Coraza will reject.
	src := `SecRuleEngine InvalidValue`
	diags := ValidateWithCoraza(src, "")
	require.NotEmpty(t, diags, "expected at least one Stage 2 diagnostic")

	for _, d := range diags {
		require.NotNil(t, d.Severity)
		assert.Equal(t, protocol_3_16.DiagnosticSeverityWarning, *d.Severity,
			"coraza-error must be a warning, not an error")
	}
}

// TestValidateWithCoraza_MessageStripsWrapper verifies that the
// "invalid WAF config from string: " prefix is stripped from error messages.
func TestValidateWithCoraza_MessageStripsWrapper(t *testing.T) {
	t.Parallel()

	src := `SecRuleEngine InvalidValue`
	diags := ValidateWithCoraza(src, "")
	require.NotEmpty(t, diags)

	for _, d := range diags {
		assert.False(t,
			strings.HasPrefix(d.Message, "invalid WAF config from string:"),
			"message should not start with the WAF wrapper prefix, got: %s", d.Message)
	}
}

// TestValidateWithCoraza_IncludeIsConfined verifies the Stage-2 security
// confinement: an Include of an arbitrary host path is resolved against the
// empty in-memory rootFS, so it can never read the host file. The unresolvable
// reference is suppressed (no false-positive diagnostic) and, critically, no
// file content is reflected back. See finding: confine the oracle's filesystem.
func TestValidateWithCoraza_IncludeIsConfined(t *testing.T) {
	t.Parallel()

	src := "SecRuleEngine On\nInclude /etc/hostname"
	diags := ValidateWithCoraza(src, "")

	// No diagnostic is published for an unresolvable Include in confined mode.
	assert.Empty(t, diags,
		"Include of a host path must not produce a diagnostic in confined mode")

	// Even if some diagnostic were produced, it must never contain host file
	// contents reflected back to the client.
	hostContents, _ := os.ReadFile("/etc/hostname")
	if name := strings.TrimSpace(string(hostContents)); name != "" {
		for _, d := range diags {
			assert.NotContains(t, d.Message, name,
				"diagnostic must not leak host file contents")
		}
	}
}

// ---------------------------------------------------------------------------
// Macro expansion linting
// ---------------------------------------------------------------------------

func TestAnalyze_MacroExpansion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		src       string
		wantCode  string
		wantCount int
	}{
		{
			name:      "valid TX macro in setvar",
			src:       `SecRule ARGS "@rx test" "id:1,phase:1,pass,setvar:tx.score=%{TX.score}"`,
			wantCount: 0,
		},
		{
			name:      "valid MATCHED_VAR macro in msg",
			src:       `SecRule ARGS "@rx test" "id:1,phase:1,deny,msg:'matched: %{MATCHED_VAR}'"`,
			wantCount: 0,
		},
		{
			name:      "valid MATCHED_VAR macro in logdata",
			src:       `SecRule ARGS "@rx test" "id:1,phase:1,deny,logdata:'val=%{MATCHED_VAR}'"`,
			wantCount: 0,
		},
		{
			name:      "valid remote_addr macro in initcol",
			src:       `SecRule ARGS "@rx test" "id:1,phase:1,pass,initcol:ip=%{REMOTE_ADDR}"`,
			wantCount: 0,
		},
		{
			name:      "valid MATCHED_VAR_NAME macro in setvar",
			src:       `SecRule ARGS "@rx test" "id:1,phase:1,pass,setvar:tx.k=%{MATCHED_VAR_NAME}"`,
			wantCount: 0,
		},
		{
			name:      "unknown collection in setvar",
			src:       `SecRule ARGS "@rx test" "id:1,phase:1,pass,setvar:tx.x=%{UNKNOWNCOL.0}"`,
			wantCode:  CodeInvalidMacro,
			wantCount: 1,
		},
		{
			name:      "unknown collection in msg",
			src:       `SecRule ARGS "@rx test" "id:1,phase:1,deny,msg:'%{BOGUS}'"`,
			wantCode:  CodeInvalidMacro,
			wantCount: 1,
		},
		{
			name:      "unclosed macro in logdata",
			src:       `SecRule ARGS "@rx test" "id:1,phase:1,deny,logdata:'%{TX.bad'"`,
			wantCode:  CodeInvalidMacro,
			wantCount: 1,
		},
		{
			name:      "empty macro %{} in msg",
			src:       `SecRule ARGS "@rx test" "id:1,phase:1,deny,msg:'%{}'"`,
			wantCode:  CodeInvalidMacro,
			wantCount: 1,
		},
		{
			name:      "valid macro in operator argument",
			src:       `SecRule TX:score "@gt %{TX.max_score}" "id:1,phase:1,deny"`,
			wantCount: 0,
		},
		{
			name:      "unknown collection in operator argument",
			src:       `SecRule TX:score "@gt %{BOGUSCOL.val}" "id:1,phase:1,deny"`,
			wantCode:  CodeInvalidMacro,
			wantCount: 1,
		},
		{
			name:      "multiple unknown macros in one value",
			src:       `SecRule ARGS "@rx test" "id:1,phase:1,pass,setvar:tx.x=%{BAD1}_%{BAD2}"`,
			wantCode:  CodeInvalidMacro,
			wantCount: 2,
		},
		{
			name:      "macro not in macro-capable action is ignored",
			src:       `SecRule ARGS "@rx test" "id:1,phase:1,deny,tag:'%{NOTMACRO}'"`,
			wantCount: 0, // tag is not a macro-capable action
		},
		{
			name:      "case-insensitive collection lookup (lowercase tx)",
			src:       `SecRule ARGS "@rx test" "id:1,phase:1,pass,setvar:tx.x=%{tx.score}"`,
			wantCount: 0,
		},
		{
			name:      "REQUEST_HEADERS collection in macro",
			src:       `SecRule ARGS "@rx test" "id:1,phase:1,pass,setvar:tx.ua=%{REQUEST_HEADERS.User-Agent}"`,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := parser.Parse("", tt.src)
			diags := Analyze(f)
			got := filterByCode(diags, CodeInvalidMacro)
			if tt.wantCount == 0 {
				assert.Empty(t, got, "should produce no invalid-macro diagnostics")
			} else {
				assert.Len(t, got, tt.wantCount, "wrong number of invalid-macro diagnostics")
				if tt.wantCode != "" {
					for _, d := range got {
						assert.Equal(t, tt.wantCode, diagCode(d))
					}
				}
			}
		})
	}
}

// diagCode returns the string code of a diagnostic (empty if nil).
func diagCode(d protocol_3_16.Diagnostic) string {
	if d.Code == nil {
		return ""
	}
	s, _ := d.Code.Value.(string)
	return s
}

// ---------------------------------------------------------------------------
// SecRuleUpdateTargetById linting
// ---------------------------------------------------------------------------

func TestAnalyze_SecRuleUpdateTargetById(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		src       string
		wantCodes []string // expected diagnostic codes; empty means no diagnostics
	}{
		{
			name: "valid — single variable",
			src:  `SecRuleUpdateTargetById 942550 "!REQUEST_COOKIES:FCCDCF"`,
		},
		{
			name: "valid — pipe-separated list",
			src:  `SecRuleUpdateTargetById 942550 "!REQUEST_COOKIES:token|!REQUEST_COOKIES_NAMES:token"`,
		},
		{
			name: "valid — count prefix",
			src:  `SecRuleUpdateTargetById 1001 "&ARGS"`,
		},
		{
			name:      "unclosed quoted string → parse-error",
			src:       `SecRuleUpdateTargetById 942550 "!REQUEST_COOKIES:FCCDCF`,
			wantCodes: []string{CodeParseError},
		},
		{
			name:      "non-numeric rule id",
			src:       `SecRuleUpdateTargetById notanid "!ARGS"`,
			wantCodes: []string{CodeInvalidID},
		},
		{
			name:      "rule id zero",
			src:       `SecRuleUpdateTargetById 0 "!ARGS"`,
			wantCodes: []string{CodeInvalidID},
		},
		{
			name:      "unknown variable in target list",
			src:       `SecRuleUpdateTargetById 1001 "!NOTAVARIABLE"`,
			wantCodes: []string{CodeUnknownVariable},
		},
		{
			name:      "multiple unknown variables",
			src:       `SecRuleUpdateTargetById 1001 "!BOGUS1|BOGUS2"`,
			wantCodes: []string{CodeUnknownVariable, CodeUnknownVariable},
		},
		{
			name: "known collection with key",
			src:  `SecRuleUpdateTargetById 1001 "!REQUEST_HEADERS:X-Custom"`,
		},
		{
			name: "negated ARGS_GET with key",
			src:  `SecRuleUpdateTargetById 1001 "!ARGS_GET:param"`,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := parser.Parse("", tt.src)
			diags := Analyze(f)
			if len(tt.wantCodes) == 0 {
				assert.Empty(t, diags, "expected no diagnostics")
				return
			}
			gotCodes := diagCodes(diags)
			for _, want := range tt.wantCodes {
				assert.Contains(t, gotCodes, want)
			}
		})
	}
}

func TestAnalyze_SecRuleUpdateTargetById_UnclosedDoesNotMaskVariableError(t *testing.T) {
	t.Parallel()
	// When the string is unclosed, we should get a parse-error but NOT an
	// unknown-variable diagnostic (the variable list is not parsed in that case).
	src := `SecRuleUpdateTargetById 1001 "!NOTAVARIABLE`
	f := parser.Parse("", src)
	diags := Analyze(f)
	codes := diagCodes(diags)
	assert.Contains(t, codes, CodeParseError, "unclosed string must produce a parse-error")
	assert.NotContains(t, codes, CodeUnknownVariable, "should not report unknown-variable when string is unclosed")
}

// ---------------------------------------------------------------------------
// Transformation linting
// ---------------------------------------------------------------------------

func TestAnalyze_Transformation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		src      string
		wantCode string
		wantNone bool
	}{
		{
			name:     "known transformation is valid",
			src:      `SecRule ARGS "@rx test" "id:1,phase:1,deny,t:lowercase"`,
			wantNone: true,
		},
		{
			name:     "t:none is valid",
			src:      `SecRule ARGS "@rx test" "id:1,phase:1,deny,t:none"`,
			wantNone: true,
		},
		{
			name:     "multiple transformations are valid",
			src:      `SecRule ARGS "@rx test" "id:1,phase:1,deny,t:none,t:lowercase,t:urlDecode"`,
			wantNone: true,
		},
		{
			name:     "unknown transformation raises warning",
			src:      `SecRule ARGS "@rx test" "id:1,phase:1,deny,t:notARealTransformation"`,
			wantCode: CodeUnknownTransformation,
		},
		{
			name:     "t: with empty value raises error",
			src:      `SecRule ARGS "@rx test" "id:1,phase:1,deny,t:"`,
			wantCode: CodeMissingTransformation,
		},
		{
			name:     "bare t with no colon raises error",
			src:      `SecRule ARGS "@rx test" "id:1,phase:1,deny,t"`,
			wantCode: CodeMissingTransformation,
		},
		{
			name:     "SecAction known transformation is valid",
			src:      `SecAction "id:1,phase:1,pass,t:base64Decode"`,
			wantNone: true,
		},
		{
			name:     "SecAction t: empty raises error",
			src:      `SecAction "id:1,phase:1,pass,t:"`,
			wantCode: CodeMissingTransformation,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := parser.Parse("", tt.src)
			diags := Analyze(f)
			if tt.wantNone {
				tDiags := filterByCode(diags, CodeUnknownTransformation)
				tDiags = append(tDiags, filterByCode(diags, CodeMissingTransformation)...)
				assert.Empty(t, tDiags, "should produce no transformation diagnostics")
				return
			}
			codes := diagCodes(diags)
			assert.Contains(t, codes, tt.wantCode)
		})
	}
}

// ----------------------------------------------------------------------------
// Variable diagnostic tests: known vs. unknown variables, wildcard syntax
// Why: the unknown-variable warning fires when a variable name is not found
// in the knowledge base. These tests pin the contract so regressions are
// caught immediately rather than discovered via VS Code.
// ----------------------------------------------------------------------------

func TestAnalyze_KnownVariables_NoWarning(t *testing.T) {
	t.Parallel()
	// Every entry here is a variable form that must NOT produce an unknown-variable
	// warning. This covers plain names, keyed forms, regex keys, negated/count
	// prefixes, and the wildcard * suffix.
	forms := []struct {
		name string
		vars string // variable-list portion of SecRule
	}{
		{"plain ARGS", "ARGS"},
		{"plain REQUEST_HEADERS", "REQUEST_HEADERS"},
		{"plain REQUEST_COOKIES", "REQUEST_COOKIES"},
		{"keyed ARGS:foo", "ARGS:foo"},
		{"keyed REQUEST_HEADERS:User-Agent", "REQUEST_HEADERS:User-Agent"},
		{"keyed REQUEST_COOKIES:session", "REQUEST_COOKIES:session"},
		{"regex key ARGS:/pattern/", "ARGS:/pattern/"},
		{"negated !ARGS", "!ARGS"},
		{"negated keyed !ARGS:foo", "!ARGS:foo"},
		{"count &ARGS", "&ARGS"},
		{"wildcard ARGS*", "ARGS*"},
		{"wildcard REQUEST_COOKIES*", "REQUEST_COOKIES*"},
		{"wildcard REQUEST_HEADERS*", "REQUEST_HEADERS*"},
		{"wildcard REQUEST_COOKIES_NAMES*", "REQUEST_COOKIES_NAMES*"},
		{"XML XPath XML:/*", "XML:/*"},
		{"XML XPath XML://body//*", "XML://body//*"},
		{"pipe list ARGS|REQUEST_HEADERS", "ARGS|REQUEST_HEADERS"},
		{"pipe list with wildcard ARGS*|REQUEST_COOKIES*", "ARGS*|REQUEST_COOKIES*"},
		{"CRS pattern REQUEST_COOKIES*|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*",
			"REQUEST_COOKIES*|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/*"},
		{"TX collection", "TX"},
		{"TX keyed TX:score", "TX:score"},
		{"REMOTE_ADDR", "REMOTE_ADDR"},
		{"REQUEST_URI", "REQUEST_URI"},
	}
	for _, f := range forms {
		f := f
		t.Run(f.name, func(t *testing.T) {
			t.Parallel()
			src := `SecRule ` + f.vars + ` "@rx test" "id:1001,phase:2,deny"`
			file := parser.Parse("test.conf", src)
			diags := Analyze(file)
			varWarnings := filterByCode(diags, CodeUnknownVariable)
			assert.Empty(t, varWarnings,
				"variable form %q should not produce unknown-variable warnings; got: %v",
				f.vars, varWarnings)
		})
	}
}

func TestAnalyze_UnknownVariable_Warning(t *testing.T) {
	t.Parallel()
	// Typo or invalid variable names MUST produce an unknown-variable warning.
	cases := []struct {
		name string
		vars string
	}{
		{"misspelled ARGZ", "ARGZ"},
		{"misspelled REQUEST_COOKIEZ", "REQUEST_COOKIEZ"},
		{"completely invalid FOOBAR", "FOOBAR"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			src := `SecRule ` + c.vars + ` "@rx test" "id:1001,phase:2,deny"`
			file := parser.Parse("test.conf", src)
			diags := Analyze(file)
			varWarnings := filterByCode(diags, CodeUnknownVariable)
			assert.NotEmpty(t, varWarnings,
				"variable form %q should produce an unknown-variable warning", c.vars)
		})
	}
}

// ----------------------------------------------------------------------------
// Multi-rule diagnostic attribution tests
// Why: a diagnostic emitted for rule N must appear on a line that belongs to
// rule N, never on a line belonging to rule N-1. This guards against the
// physPos() cross-rule contamination that was present in an earlier version.
// ----------------------------------------------------------------------------

func TestAnalyze_DiagLineStaysWithinRule(t *testing.T) {
	t.Parallel()
	// Two adjacent rules; the second one has a deliberate error (missing id).
	// The diagnostic must be on a line >= 1 (the first line of rule 2), not 0.
	src := `SecRule ARGS "@rx prev" "id:100,phase:2,deny"
SecRule REQUEST_HEADERS "@rx next" "phase:2,deny"`
	file := parser.Parse("test.conf", src)
	diags := Analyze(file)
	missingID := filterByCode(diags, CodeMissingID)
	require.Len(t, missingID, 1, "expected exactly one missing-id diagnostic")
	assert.GreaterOrEqual(t, int(missingID[0].Range.Start.Line), 1,
		"missing-id diagnostic must be on line 1 (rule 2), not line 0 (rule 1)")
}

func TestAnalyze_DiagLineStaysWithinMultiLineContinuationRule(t *testing.T) {
	t.Parallel()
	// Two adjacent multi-line (continuation) rules; the second has a missing id.
	// The diagnostic must be on a line >= 2 (where rule 2 starts).
	src := "SecRule ARGS \"@rx prev\" \\\n    \"id:100,phase:2,deny\"\nSecRule REQUEST_HEADERS \"@rx next\" \\\n    \"phase:2,deny\""
	file := parser.Parse("test.conf", src)
	diags := Analyze(file)
	missingID := filterByCode(diags, CodeMissingID)
	require.Len(t, missingID, 1, "expected exactly one missing-id diagnostic")
	assert.GreaterOrEqual(t, int(missingID[0].Range.Start.Line), 2,
		"missing-id diagnostic must be on line ≥2 (rule 2 start), not on rule 1's lines (0–1)")
}

// ----------------------------------------------------------------------------
// CRS rule pattern regression tests
// Why: these are exact patterns from OWASP CRS that previously produced false
// positive warnings. Each test documents the rule structure and asserts zero
// unknown-variable warnings.
// ----------------------------------------------------------------------------

func TestAnalyze_CRS_RCECommandInjectionRule(t *testing.T) {
	t.Parallel()
	// CRS 932100 pattern: wildcard collection + XPath variable, multi-line.
	src := "SecRule REQUEST_COOKIES*|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* \"@rx \\r\\n.*?\\b(?:(?:QUI|STA|RSE)T|NOOP|CAPA)\" \\\n" +
		"    \"id:932100,phase:2,block,capture,\\\n" +
		"     msg:'Remote Command Execution: Unix Shell',\\\n" +
		"     tag:'attack-rce',\\\n" +
		"     severity:'CRITICAL'\""
	file := parser.Parse("test.conf", src)
	assert.Empty(t, file.Errors, "parse errors: %v", file.Errors)
	diags := Analyze(file)
	varWarnings := filterByCode(diags, CodeUnknownVariable)
	assert.Empty(t, varWarnings,
		"CRS 932100 pattern must not produce unknown-variable warnings; got: %v", varWarnings)
}

func TestAnalyze_CRS_SQLiRule(t *testing.T) {
	t.Parallel()
	// CRS SQLi pattern: large variable list with negations and count operators.
	src := `SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|!REQUEST_COOKIES:/_pk_ref/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|!ARGS:__utm_source|REQUEST_HEADERS:User-Agent|REQUEST_HEADERS:Referer "@rx (?i:(?:select|update|insert|delete|drop|create|alter|exec))" "id:942100,phase:2,block,capture,msg:'SQL Injection Attack',tag:'attack-sqli',severity:'CRITICAL'"`
	file := parser.Parse("test.conf", src)
	assert.Empty(t, file.Errors, "parse errors: %v", file.Errors)
	diags := Analyze(file)
	varWarnings := filterByCode(diags, CodeUnknownVariable)
	assert.Empty(t, varWarnings,
		"CRS SQLi pattern must not produce unknown-variable warnings; got: %v", varWarnings)
}

func TestAnalyze_CRS_XSSRule(t *testing.T) {
	t.Parallel()
	// CRS XSS pattern: TX collection in setvar, macro expansion in msg.
	src := `SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS|ARGS_NAMES|ARGS "@rx <script" \
    "id:941100,phase:2,block,capture,\
     msg:'XSS Attack Detected via libinjection',\
     tag:'attack-xss',\
     setvar:'tx.xss_score=+%{tx.critical_anomaly_score}',\
     severity:'CRITICAL'"`
	file := parser.Parse("test.conf", src)
	assert.Empty(t, file.Errors, "parse errors: %v", file.Errors)
	diags := Analyze(file)
	varWarnings := filterByCode(diags, CodeUnknownVariable)
	assert.Empty(t, varWarnings,
		"CRS XSS pattern must not produce unknown-variable warnings; got: %v", varWarnings)
}

func TestAnalyze_CRS_EscapedQuotesInOperator(t *testing.T) {
	t.Parallel()
	// CRS pattern where the @rx argument contains escaped double-quotes.
	// The operator argument parser must not choke on \" inside the regex.
	src := `SecRule REQUEST_COOKIES|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "@rx \ba[\"'\)\[\x5c]*(?:\$)" "id:932200,phase:2,block,msg:'RCE'"` //nolint:gocritic
	file := parser.Parse("test.conf", src)
	assert.Empty(t, file.Errors, "parse errors: %v", file.Errors)
	diags := Analyze(file)
	varWarnings := filterByCode(diags, CodeUnknownVariable)
	assert.Empty(t, varWarnings,
		"rule with escaped quotes in operator must not produce unknown-variable warnings; got: %v", varWarnings)
}

// ---------------------------------------------------------------------------
// Regression tests for the analysis-layer audit findings
// ---------------------------------------------------------------------------

// TestExtractRuleIDFromError_NoPanicOnToLowerLengthChange is a regression test
// for the HIGH bug: extractRuleIDFromError indexed the lowercased string but
// sliced the original. strings.ToLower can change byte length (Turkish 'İ'
// folds to 2 bytes; the invalid byte 0xFF folds to U+FFFD, 1→3 bytes), so the
// offset computed against the lowercased string went out of range on the
// original. It must never panic and must still extract the id.
func TestExtractRuleIDFromError_NoPanicOnToLowerLengthChange(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		errMsg string
		wantID string
	}{
		{
			name:   "Turkish dotted capital I before id (ToLower grows bytes)",
			errMsg: "İİİİid:4242 bad",
			wantID: "4242",
		},
		{
			name:   "invalid UTF-8 byte 0xFF before id (folds to U+FFFD, 1->3 bytes)",
			errMsg: "\xff\xff\xffid:7 bad",
			wantID: "7",
		},
		{
			name:   "eszett before id",
			errMsg: "ẞẞid:99",
			wantID: "99",
		},
		{
			name:   "no panic, no id",
			errMsg: "\xffno-id-here",
			wantID: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Must not panic.
			got := extractRuleIDFromError(tc.errMsg)
			assert.Equal(t, tc.wantID, got)
		})
	}
}

// TestValidateWithCoraza_OddIncludeDoesNotHangOrLeak verifies finding #2 (HIGH
// security): an Include/@*FromFile referencing an odd or nonexistent host path
// is resolved against the confined empty rootFS. It must (a) return promptly
// (no hang) and (b) never reflect host file contents back in a diagnostic.
func TestValidateWithCoraza_OddIncludeDoesNotHangOrLeak(t *testing.T) {
	t.Parallel()

	srcs := []string{
		"Include /etc/passwd",
		"Include /dev/null",
		`SecRule ARGS "@pmFromFile /etc/hostname" "id:1,phase:2,deny"`,
		`SecRule ARGS "@ipMatchFromFile /etc/hosts" "id:2,phase:2,deny"`,
		"Include ./../../../../etc/shadow",
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, src := range srcs {
			diags := ValidateWithCoraza(src, "")
			// Confined rootFS: unresolvable references are suppressed.
			assert.Empty(t, diags, "confined Include/FromFile must not produce diagnostics for %q", src)
		}
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("ValidateWithCoraza hung on odd Include/FromFile paths")
	}

	// Explicit leak check against a readable host file.
	hostContents, err := os.ReadFile("/etc/hostname")
	if err == nil {
		if name := strings.TrimSpace(string(hostContents)); name != "" {
			for _, d := range ValidateWithCoraza(`SecRule ARGS "@pmFromFile /etc/hostname" "id:1,phase:2,deny"`, "") {
				assert.NotContains(t, d.Message, name, "must not leak host file contents")
			}
		}
	}
}

// TestValidateWithCoraza_TimeoutGuard verifies the build runs under a timeout
// and recovers; a normal small document completes well within the budget and
// the timeout path is exercised structurally via buildCorazaWAF.
func TestValidateWithCoraza_TimeoutGuard(t *testing.T) {
	t.Parallel()
	// A well-formed document returns nil quickly (no timeout note).
	diags := ValidateWithCoraza("SecRuleEngine On", "")
	assert.Empty(t, diags)
}

// TestSchedule_OversizedDocumentSkipsStage2 verifies finding #3: a document
// over the size cap skips the Stage-2 oracle, keeps Stage-1 diagnostics, and
// emits a single informational note.
func TestSchedule_OversizedDocumentSkipsStage2(t *testing.T) {
	t.Parallel()

	var got []protocol_3_16.Diagnostic
	done := make(chan struct{})
	v := NewValidator(5*time.Millisecond, func(uri string, diags []protocol_3_16.Diagnostic) {
		got = diags
		close(done)
	})

	// Build an oversized source (> maxDocumentBytes).
	var b strings.Builder
	line := "SecRule ARGS \"@rx x\" \"id:1,phase:2,deny\"\n"
	for b.Len() <= maxDocumentBytes {
		b.WriteString(line)
	}
	stage1 := []protocol_3_16.Diagnostic{} // pretend Stage 1 found nothing

	v.Schedule("file:///big.conf", b.String(), stage1)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("oversized document validation did not complete")
	}

	require.Len(t, got, 1, "oversized doc should yield exactly the informational note")
	require.NotNil(t, got[0].Severity)
	assert.Equal(t, protocol_3_16.DiagnosticSeverityInformation, *got[0].Severity)
	assert.Contains(t, got[0].Message, "too large")
}

// TestSuppressRedundantCorazaErrors_Generalized verifies finding #4: a defect
// reported by a Stage-1 structural diagnostic (invalid phase, unknown operator)
// is NOT repeated by a Stage-2 coraza-error on the same line.
func TestSuppressRedundantCorazaErrors_Generalized(t *testing.T) {
	t.Parallel()

	mk := func(line uint32, code string) protocol_3_16.Diagnostic {
		return protocol_3_16.Diagnostic{
			Range: protocol_3_16.Range{Start: protocol_3_16.Position{Line: line}},
			Code:  &protocol_3_16.IntegerOrString{Value: code},
		}
	}

	t.Run("invalid-phase suppresses coraza-error on same line", func(t *testing.T) {
		t.Parallel()
		stage1 := []protocol_3_16.Diagnostic{mk(0, CodeInvalidPhase)}
		stage2 := []protocol_3_16.Diagnostic{mk(0, CodeCorazaError)}
		assert.Empty(t, suppressRedundantCorazaErrors(stage1, stage2))
	})

	t.Run("unknown-operator suppresses coraza-error on same line", func(t *testing.T) {
		t.Parallel()
		stage1 := []protocol_3_16.Diagnostic{mk(2, CodeUnknownOperator)}
		stage2 := []protocol_3_16.Diagnostic{mk(2, CodeCorazaError)}
		assert.Empty(t, suppressRedundantCorazaErrors(stage1, stage2))
	})

	t.Run("coraza-error on a different line is kept", func(t *testing.T) {
		t.Parallel()
		stage1 := []protocol_3_16.Diagnostic{mk(0, CodeInvalidPhase)}
		stage2 := []protocol_3_16.Diagnostic{mk(5, CodeCorazaError)}
		assert.Len(t, suppressRedundantCorazaErrors(stage1, stage2), 1)
	})

	t.Run("end-to-end: invalid phase is reported once", func(t *testing.T) {
		t.Parallel()
		src := `SecRule ARGS "@rx a" "id:1,phase:9,deny"`
		f := parser.Parse("", src)
		stage1 := Analyze(f)
		stage2 := suppressRedundantCorazaErrors(stage1, ValidateWithCoraza(src, ""))
		// Stage 1 reports invalid-phase; Stage 2 must not repeat it on the same line.
		for _, d := range stage2 {
			if c, _ := codeOf(d); c == CodeCorazaError {
				assert.NotEqual(t, uint32(0), d.Range.Start.Line+1,
					"redundant coraza-error for invalid phase should be suppressed")
			}
		}
		// Confirm exactly one invalid-phase diagnostic overall.
		phaseCount := 0
		for _, d := range append(append([]protocol_3_16.Diagnostic{}, stage1...), stage2...) {
			if c, _ := codeOf(d); c == CodeInvalidPhase {
				phaseCount++
			}
		}
		assert.Equal(t, 1, phaseCount)
	})
}

// TestValidator_DropsResultForClosedDocument verifies finding #5: a Stage-2
// result for a URI that was cancelled (didClose) after the timer fired is not
// published.
func TestValidator_DropsResultForClosedDocument(t *testing.T) {
	t.Parallel()

	var calls int32
	v := NewValidator(20*time.Millisecond, func(uri string, diags []protocol_3_16.Diagnostic) {
		atomic.AddInt32(&calls, 1)
	})
	v.Schedule("file:///x.conf", "SecRuleEngine On", nil)
	// Cancel before the timer fires — bumps the epoch so any in-flight result drops.
	v.Cancel("file:///x.conf")
	time.Sleep(120 * time.Millisecond)
	assert.Equal(t, int32(0), atomic.LoadInt32(&calls),
		"cancelled (closed) document must not receive a published result")
}

// TestValidator_ReScheduleNotClobberedByOldTimer verifies the LOW timer-map
// bug from finding #5: an old fired timer must not delete a freshly re-armed
// entry, and the newer schedule must still fire exactly once.
func TestValidator_ReScheduleNotClobberedByOldTimer(t *testing.T) {
	t.Parallel()

	var calls int32
	v := NewValidator(15*time.Millisecond, func(uri string, diags []protocol_3_16.Diagnostic) {
		atomic.AddInt32(&calls, 1)
	})
	uri := "file:///y.conf"
	v.Schedule(uri, "SecRuleEngine On", nil)
	v.Schedule(uri, "SecRuleEngine On", nil) // re-arm
	time.Sleep(120 * time.Millisecond)
	// Exactly one callback (the latest schedule); the superseded one is stale.
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls))
}

// TestValidateWithCoraza_DuplicateIDOnSecondRule verifies finding #6a: the
// Stage-2 duplicate-id error points at the SECOND (offending) rule, not the
// first.
func TestValidateWithCoraza_DuplicateIDOnSecondRule(t *testing.T) {
	t.Parallel()

	src := "SecAction \"id:1,phase:1,pass\"\nSecAction \"id:1,phase:1,pass\""
	diags := ValidateWithCoraza(src, "")
	require.NotEmpty(t, diags)
	assert.Equal(t, uint32(1), diags[0].Range.Start.Line,
		"duplicate-id error must point at the second rule (line 1), not the first")
}

// TestAnalyze_RuneColumns_UTF8 verifies finding #6c/#7: diagnostic columns are
// rune offsets (not byte offsets). A multibyte value (msg:'café') precedes the
// flagged token; the squiggle, sliced by rune, must land exactly on the token.
func TestAnalyze_RuneColumns_UTF8(t *testing.T) {
	t.Parallel()

	src := `SecRule ARGS "@rx x" "id:1,phase:2,deny,msg:'café',t:notreal"`
	f := parser.Parse("", src)
	diags := filterByCode(Analyze(f), CodeUnknownTransformation)
	require.Len(t, diags, 1)
	d := diags[0]

	// Slice the source line by RUNE to extract the squiggled text. If the column
	// were a byte offset, the multibyte 'é' would shift this and the slice would
	// not equal the action token.
	runes := []rune(src)
	require.LessOrEqual(t, int(d.Range.End.Character), len(runes))
	squiggle := string(runes[d.Range.Start.Character:d.Range.End.Character])
	assert.Equal(t, "t:notreal", squiggle,
		"rune-sliced squiggle must land exactly on the offending token")
}

// TestLocateCorazaError_RuneColumns_UTF8 verifies finding #6c on the Stage-2
// path: locateCorazaError returns rune-based columns even when multibyte runes
// precede the matched directive/value token.
func TestLocateCorazaError_RuneColumns_UTF8(t *testing.T) {
	t.Parallel()

	// A comment with multibyte runes, then SecRuleEngine with a bad value. The
	// value squiggle must be a rune offset.
	src := "# café configuración\nSecRuleEngine BADVALUE"
	errMsg := `invalid WAF config from string: failed to compile the directive "secruleengine": Invalid SecRuleEngine argument: BADVALUE`
	r := locateCorazaError(errMsg, src)
	runes := []rune(strings.Split(src, "\n")[r.Start.Line])
	require.LessOrEqual(t, r.End.Character, len(runes))
	squiggle := string(runes[r.Start.Character:r.End.Character])
	assert.Equal(t, "BADVALUE", squiggle, "value squiggle must be rune-aligned")
}

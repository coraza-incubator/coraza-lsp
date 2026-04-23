// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coraza-incubator/coraza-lsp/internal/parser"
)

// TestAnalyze_SyntaxEdgeCases locks in expected diagnostic behaviour for a
// broad set of awkward-but-legal-looking SecLang fragments. Each row documents
// what the analyzer currently says about a specific kind of malformed input.
//
// The "mustHave" set asserts diagnostic codes that MUST appear. Other codes
// are permitted (the parser may surface additional parse errors). No row is
// allowed to crash the analyzer.
func TestAnalyze_SyntaxEdgeCases(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		src      string
		mustHave []DiagnosticCode // codes required in the output
		wantNone bool             // when true, no diagnostics at all
	}{
		// --- action-list punctuation -----------------------------------------
		{
			name: "double comma in actions",
			src:  `SecRule ARGS "@rx x" "id:1,,phase:2,deny"`,
		},
		{
			name: "trailing comma in actions",
			src:  `SecRule ARGS "@rx x" "id:1,phase:2,deny,"`,
		},
		{
			name: "leading comma in actions",
			src:  `SecRule ARGS "@rx x" ",id:1,phase:2,deny"`,
		},
		{
			name: "space-separated actions (no commas)",
			src:  `SecRule ARGS "@rx x" "id:1 phase:2 deny"`,
		},

		// --- quoting ---------------------------------------------------------
		{
			name: "single-quoted action list",
			src:  `SecRule ARGS "@rx x" 'id:1,phase:2,deny'`,
		},
		{
			name: "escaped single quote inside msg",
			src:  `SecRule ARGS "@rx x" "id:1,phase:2,deny,msg:'it\'s ok'"`,
		},
		{
			name:     "unclosed msg quote",
			src:      `SecRule ARGS "@rx x" "id:1,phase:2,deny,msg:'unclosed`,
			mustHave: []DiagnosticCode{CodeParseError},
		},
		{
			name:     "unclosed action-list quote",
			src:      `SecRule ARGS "@rx x" "id:1,phase:2,deny`,
			mustHave: []DiagnosticCode{CodeParseError},
		},

		// --- directive shape -------------------------------------------------
		{
			name:     "unknown directive",
			src:      `SecCompletelyMadeUp foo`,
			mustHave: []DiagnosticCode{CodeUnknownDirective},
		},
		{
			name: "lowercase directive still known",
			src:  `secruleengine On`,
		},
		{
			name: "uppercase directive still known",
			src:  `SECRULEENGINE On`,
		},
		{
			name: "just the directive name",
			src:  `SecRule`,
		},
		{
			name: "directive with one arg only",
			src:  `SecRule ARGS`,
		},
		{
			name: "SecRule with no actions",
			src:  `SecRule ARGS "@rx x"`,
		},
		{
			name: "SecRule with empty action list",
			src:  `SecRule ARGS "@rx x" ""`,
		},

		// --- id / phase ------------------------------------------------------
		{
			name:     "id zero",
			src:      `SecRule ARGS "@rx x" "id:0,phase:2,deny"`,
			mustHave: []DiagnosticCode{CodeInvalidID},
		},
		{
			name:     "id non-numeric",
			src:      `SecRule ARGS "@rx x" "id:abc,phase:2,deny"`,
			mustHave: []DiagnosticCode{CodeInvalidID},
		},
		{
			name:     "phase out of range",
			src:      `SecRule ARGS "@rx x" "id:1,phase:9,deny"`,
			mustHave: []DiagnosticCode{CodeInvalidPhase},
		},
		{
			name:     "missing id entirely",
			src:      `SecRule ARGS "@rx x" "phase:2,deny"`,
			mustHave: []DiagnosticCode{CodeMissingID},
		},
		{
			name:     "missing phase entirely",
			src:      `SecRule ARGS "@rx x" "id:1001,deny"`,
			mustHave: []DiagnosticCode{CodeMissingPhase},
		},

		// --- variables -------------------------------------------------------
		{
			name:     "unknown variable",
			src:      `SecRule TOTALLY_FAKE_VAR "@rx x" "id:1,phase:2,deny"`,
			mustHave: []DiagnosticCode{CodeUnknownVariable},
		},
		{
			// `ARGS.foo` is not a legal variable selector (SecLang uses `:` for
			// keys) — the parser rejects it at the syntax layer rather than
			// letting the analyzer flag it as "unknown variable".
			name: "dot-instead-of-colon selector",
			src:  `SecRule ARGS.foo "@rx x" "id:1,phase:2,deny"`,
		},
		{
			name: "count prefix on ARGS",
			src:  `SecRule &ARGS "@eq 0" "id:1,phase:2,deny"`,
		},
		{
			name: "exclusion with negation",
			src:  `SecRule ARGS|!ARGS:password "@rx x" "id:1,phase:2,deny"`,
		},

		// --- operator --------------------------------------------------------
		{
			name: "negated operator",
			src:  `SecRule ARGS "!@rx x" "id:1,phase:2,deny"`,
		},

		// --- actions: ctl / t / skipAfter -----------------------------------
		{
			name:     "unknown transformation",
			src:      `SecRule ARGS "@rx x" "id:1,phase:2,deny,t:madeUp"`,
			mustHave: []DiagnosticCode{CodeUnknownTransformation},
		},
		{
			name:     "empty t:",
			src:      `SecRule ARGS "@rx x" "id:1,phase:2,deny,t:"`,
			mustHave: []DiagnosticCode{CodeMissingTransformation},
		},
		{
			name:     "unknown ctl option",
			src:      `SecAction "id:1,phase:1,pass,ctl:nopeNotAnOption=Off"`,
			mustHave: []DiagnosticCode{CodeUnknownCtlOption},
		},
		{
			name: "skipAfter to nonexistent marker (cross-file hint)",
			src:  `SecRule ARGS "@rx x" "id:1,phase:2,pass,skipAfter:NOWHERE"`,
			mustHave: []DiagnosticCode{CodeSkipAfterNotFound},
		},
		{
			name: "skipAfter to present marker",
			src: "SecRule ARGS \"@rx x\" \"id:1,phase:2,pass,skipAfter:END\"\n" +
				"SecMarker END",
		},

		// --- continuation / line endings ------------------------------------
		{
			name: "continuation line",
			src:  "SecRule ARGS \"@rx x\" \\\n  \"id:1,phase:2,deny\"",
		},
		{
			name: "dangling continuation",
			src:  "SecRule ARGS \"@rx x\" \\",
		},
		{
			name: "CRLF line endings",
			src:  "SecRuleEngine On\r\nSecRuleEngine Off\r\n",
		},

		// --- comments and whitespace ----------------------------------------
		{
			name:     "comment only",
			src:      "# nothing here\n",
			wantNone: true,
		},
		{
			name:     "only whitespace",
			src:      "   \n\t\n",
			wantNone: true,
		},
		{
			name:     "empty file",
			src:      ``,
			wantNone: true,
		},

		// --- include / marker -----------------------------------------------
		{
			name: "include with wildcard",
			src:  `Include rules/*.conf`,
		},
		{
			name: "bare marker without name",
			src:  `SecMarker`,
		},

		// --- macro expansion -------------------------------------------------
		{
			name: "unclosed macro in msg",
			src:  `SecRule ARGS "@rx x" "id:1,phase:2,deny,msg:'hi %{TX.foo'"`,
		},
		{
			name: "macro with nonexistent collection",
			src:  `SecRule ARGS "@rx x" "id:1,phase:2,deny,msg:'hi %{NOPE.foo}'"`,
		},

		// --- multi-issue packs ----------------------------------------------
		{
			name: "everything wrong at once",
			src: strings.Join([]string{
				`SecRule ARGS "@rx x" "phase:2,deny"`,
				`SecRule ARGS "@rx x" "id:abc,phase:9,deny"`,
				`SecRule TOTALLY_FAKE_VAR "@rx x" "id:1,phase:2,deny,t:nope"`,
				`SecCompletelyMadeUp thing`,
				`SecRule ARGS "@rx x" "id:1000,phase:2,pass,skipAfter:NOWHERE"`,
				`SecRule ARGS "@rx x" "id:1000,phase:2,deny"`,
				`SecRule ARGS "@rx x" "id:1000,phase:2,deny"`,
			}, "\n"),
			mustHave: []DiagnosticCode{
				CodeMissingID,
				CodeInvalidID,
				CodeInvalidPhase,
				CodeUnknownVariable,
				CodeUnknownTransformation,
				CodeUnknownDirective,
				CodeSkipAfterNotFound,
				CodeDuplicateID,
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.True(t, utf8.ValidString(tc.src), "test source must be valid utf8")

			f := parser.Parse("", tc.src)
			require.NotNil(t, f, "parser must never return nil")

			diags := Analyze(f)

			if tc.wantNone {
				assert.Empty(t, diags, "expected zero diagnostics")
				return
			}

			got := make(map[DiagnosticCode]int, len(diags))
			for _, d := range diags {
				if d.Code == nil {
					continue
				}
				if s, ok := d.Code.Value.(DiagnosticCode); ok {
					got[s]++
					continue
				}
				if s, ok := d.Code.Value.(string); ok {
					got[DiagnosticCode(s)]++
				}
			}

			for _, code := range tc.mustHave {
				assert.Contains(t, got, code, "expected %q; got codes=%v", code, got)
			}
		})
	}
}

// FuzzAnalyze stresses the full static-analysis pipeline. Any input that
// parses successfully must also analyse without panicking. Stage-2 (Coraza
// WAF) is intentionally excluded because it is debounced and does network-y
// work (fresh WAF init).
func FuzzAnalyze(f *testing.F) {
	seeds := []string{
		``,
		`SecRule ARGS "@rx x" "id:1,phase:2,deny"`,
		`SecRule ARGS "@rx x" "id:1,,phase:2,deny,"`,
		`SecRule ARGS "@rx x" "id:1,phase:2,deny,msg:'unclosed`,
		"SecRule ARGS \"@rx x\" \\\n \"id:1,phase:2,deny\"",
		`SecAction "id:1,phase:1,pass,ctl:nope=Off,t:madeUp"`,
		`SecRule TOTALLY_FAKE "@rx x" "id:1,phase:2,pass,skipAfter:NOWHERE"`,
		"SecMarker END\nSecMarker END\nSecRule ARGS \"@rx x\" \"id:1,phase:2,pass,skipAfter:END\"",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, source string) {
		if !utf8.ValidString(source) || len(source) > 32*1024 {
			t.Skip()
		}
		file := parser.Parse("file:///fuzz.conf", source)
		if file == nil {
			t.Fatal("Parse returned nil")
		}
		// Must not panic.
		_ = Analyze(file)
	})
}

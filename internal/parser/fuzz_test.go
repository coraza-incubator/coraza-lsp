// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package parser

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// seedCorpus is a handpicked collection of odd-but-real SecLang fragments.
// Each one has caused a parser regression or is known to exercise a tricky
// code path. FuzzParse seeds its corpus with these so the first generation of
// mutations starts from interesting shapes.
var seedCorpus = []string{
	``,
	` `,
	"\n\n\n",
	"\r\n",
	"\uFEFFSecRuleEngine On\n", // BOM + valid directive
	`SecRule ARGS "@rx x" "id:1,,phase:2,deny"`,                     // double comma
	`SecRule ARGS "@rx x" "id:1,phase:2,deny,"`,                     // trailing comma
	`SecRule ARGS "@rx x" ",id:1,phase:2,deny"`,                     // leading comma
	`SecRule ARGS "@rx x" "id:1 phase:2 deny"`,                      // missing commas
	`SecRule ARGS "@rx x" 'id:1,phase:2,deny'`,                      // single-quoted actions
	`SecRule ARGS '@rx x' "id:1,phase:2,deny"`,                      // single-quoted operator
	`SecRule ARGS "@rx x" "id:1,phase:2,deny,msg:'it\'s ok'"`,       // escaped quote inside
	`SecRule ARGS "@rx x" "id:1,phase:2,deny,msg:'unclosed`,         // unclosed msg
	`SecRule ARGS "@rx "`,                                           // empty operator arg, no actions
	`SecRule`,                                                       // only directive
	`SecRule ARGS`,                                                  // one arg
	`SecRule ARGS "@rx x"`,                                          // no actions
	`SecRule ARGS "@rx x" ""`,                                       // empty actions
	`SecRule ARGS|!ARGS:password "@rx x" "id:1,phase:2,deny"`,       // variable exclusion
	`SecRule &ARGS "@eq 0" "id:1,phase:2,deny"`,                     // count prefix
	`SecRule ARGS:foo.bar "@rx x" "id:1,phase:2,deny"`,              // dotted selector (typo)
	`SecRule ARGS.foo "@rx x" "id:1,phase:2,deny"`,                  // dot-instead-of-colon
	`SecRule ARGS:'quoted key' "@rx x" "id:1,phase:2,deny"`,         // quoted selector
	`SecRule ARGS "@@rx x" "id:1,phase:2,deny"`,                     // double @
	`SecRule ARGS "!@rx x" "id:1,phase:2,deny"`,                     // negated op
	`SecRule ARGS "! @rx x" "id:1,phase:2,deny"`,                    // negated op with space
	`SecRule ARGS "@rxpattern" "id:1,phase:2,deny"`,                 // op name and arg fused
	`secrule args "@rx x" "id:1,phase:2,deny"`,                      // lowercase directive
	`SECRULE ARGS "@rx x" "id:1,phase:2,deny"`,                      // uppercase directive
	"SecRule ARGS \"@rx x\" \\\n  \"id:1,phase:2,deny\"",            // continuation
	"SecRule ARGS \"@rx x\" \\\n\\\n  \"id:1,phase:2,deny\"",        // blank continuation
	"SecRule ARGS \"@rx x\" \\",                                     // dangling continuation
	"SecRuleEngine On\r\nSecRuleEngine Off\r\n",                     // CRLF
	`SecMarker`,                                                     // marker no name
	`SecMarker "quoted name"`,                                       // marker quoted
	`SecMarker 'with spaces'`,                                       // marker single-quoted w/ space
	`Include`,                                                       // include no path
	`Include rules/*.conf`,                                          // wildcard include
	`Include "rules with spaces.conf"`,                              // quoted include path
	`SecAction`,                                                     // bare SecAction
	`SecAction "id:1,phase:1,pass,chain"`,                           // chain on SecAction
	`SecRule ARGS "@rx x" "id:1,phase:2,pass,ctl:"`,                 // empty ctl
	`SecRule ARGS "@rx x" "id:1,phase:2,pass,ctl:ruleRemoveById"`,   // ctl without =value
	`SecRule ARGS "@rx x" "id:1,phase:2,pass,ctl:ruleRemoveById="`,  // ctl with empty value
	`SecRule ARGS "@rx x" "id:1,phase:2,deny,t:"`,                   // empty t:
	`SecRule ARGS "@rx x" "id:1,phase:2,deny,t:,t:lowercase"`,       // t: then more
	`SecRule ARGS "@rx x" "id:1,phase:2,deny,msg:"`,                 // empty msg
	`SecRule ARGS "@rx x" "id:1,phase:2,deny,msg:\"he said \\\"hi\\\"\""`,
	`SecRule ARGS "@rx \"double-quoted pattern\"" "id:1,phase:2,deny"`,
	"SecRule ARGS \"@rx x\" \"id:1,phase:2,deny,msg:'with\ttab'\"", // tab inside msg
	`SecRule ARGS "@rx x" "id:1,phase:2,deny,msg:'naïve utf8 😀'"`,   // non-ASCII
	`SecRule ARGS "@rx (?:[a-z]+)\\\\(?:x+)" "id:1,phase:2,deny"`,   // regex backslashes
	`# comment only`,
	`# comment
SecRuleEngine On`,
	`SecRuleEngine On # trailing comment`,
	`phase:2`,   // action outside a rule context
	`id:1001`,   // ditto
	`"just quotes"`,
	`""`,
	`\\`,
	`\`,
}

func FuzzParse(f *testing.F) {
	for _, seed := range seedCorpus {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, source string) {
		// Reject inputs with invalid UTF-8 — the editor wire protocol guarantees
		// valid UTF-8, and we don't claim to be resilient to arbitrary byte soup.
		if !utf8.ValidString(source) {
			t.Skip()
		}
		// Cap length so a runaway mutation doesn't dominate the fuzzing budget.
		if len(source) > 32*1024 {
			t.Skip()
		}

		// Primary invariant: Parse must not panic on any UTF-8 input.
		file := Parse("file:///fuzz.conf", source)
		if file == nil {
			t.Fatal("Parse returned nil")
		}

		// Secondary invariants on the returned AST.
		lineCount := strings.Count(source, "\n") + 1
		for _, n := range file.Nodes {
			r := n.GetRange()
			if r.Start.Line < 0 || r.Start.Character < 0 {
				t.Fatalf("negative Start position: %+v for %T", r, n)
			}
			if r.End.Line < r.Start.Line {
				t.Fatalf("End.Line %d < Start.Line %d for %T", r.End.Line, r.Start.Line, n)
			}
			if r.Start.Line > lineCount {
				t.Fatalf("Start.Line %d beyond source (%d lines) for %T", r.Start.Line, lineCount, n)
			}
		}

		// NodeAtPosition must also be panic-free for every line/col in the file.
		// We probe a handful of representative positions rather than the full grid.
		probes := [][2]int{
			{0, 0}, {0, 1}, {0, len(source)},
			{lineCount / 2, 0}, {lineCount - 1, 0}, {lineCount + 5, 0},
		}
		for _, p := range probes {
			_ = file.NodeAtPosition(p[0], p[1])
		}

		// Monotonicity: nodes must be emitted in source order.
		for i := 1; i < len(file.Nodes); i++ {
			prev := file.Nodes[i-1].GetRange()
			cur := file.Nodes[i].GetRange()
			if cur.Start.Line < prev.Start.Line ||
				(cur.Start.Line == prev.Start.Line && cur.Start.Character < prev.Start.Character) {
				t.Fatalf("node %d (%T) starts at %+v before prior node start %+v",
					i, file.Nodes[i], cur.Start, prev.Start)
			}
		}
	})
}

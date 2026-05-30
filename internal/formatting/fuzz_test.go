// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package formatting

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/coraza-incubator/coraza-lsp/internal/parser"
)

var formatSeeds = []string{
	``,
	`SecRuleEngine On`,
	`SecRule ARGS "@rx x" "id:1,phase:2,deny"`,
	"SecRule   ARGS    \"@rx x\"    \"id:1,phase:2,deny\"",
	"SecRule ARGS \"@rx x\" \\\n  \"id:1,phase:2,deny\"",
	"\n\n\nSecRuleEngine On\n\n\n\nSecRuleEngine Off\n\n\n",
	"# comment\nSecRuleEngine On\n# comment\n",
	"SecRule ARGS \"@rx x\" \\\n\\\n  \"id:1,phase:2,deny\"",
	"SecRuleEngine On\r\nSecRuleEngine Off\r\n",
	"  SecRuleEngine On  \n\t\tSecRuleEngine Off\t\n",
	// Regex split across a continuation boundary: the bytes inside the quote must
	// rejoin with NO separator, or the operator argument changes meaning.
	"SecRule ARGS \"@rx ab\\\ncd\" \"id:1,phase:2,deny\"",
	// CRS-style indented continuation action list: leading indentation of the
	// continuation lines must not leak into the quoted action string.
	"SecAction \\\n    \"id:980099,\\\n    phase:5,\\\n    pass\"",
}

// FuzzFormatIdempotent asserts Format(Format(x)) == Format(x). A formatter
// that is not idempotent will oscillate between two outputs when the editor
// formats on save, producing phantom diffs. Easy to check, hard bug to spot
// manually.
func FuzzFormatIdempotent(f *testing.F) {
	for _, s := range formatSeeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, source string) {
		if !utf8.ValidString(source) || len(source) > 32*1024 {
			t.Skip()
		}
		once := formatSource(source)
		twice := formatSource(once)
		if once != twice {
			t.Fatalf("formatter not idempotent\ninput:  %q\nonce:   %q\ntwice:  %q", source, once, twice)
		}
	})
}

// FuzzFormatPreservesSemantics asserts the formatter never changes rule
// semantics: parse(format(x)) must yield the same rules — same directives,
// variables, operators (name + argument), and actions (name + value) — as
// parse(x). This is the invariant that actually protects quoted-string content
// (regex operator arguments, action values) from spurious whitespace insertion
// when continuation lines are joined; the old bag-of-bytes-minus-backslashes
// check could not see a space wrongly added inside a quoted span.
func FuzzFormatPreservesSemantics(f *testing.F) {
	for _, s := range formatSeeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, source string) {
		if !utf8.ValidString(source) || len(source) > 32*1024 {
			t.Skip()
		}
		formatted := formatSource(source)

		before := ruleDigest(source)
		after := ruleDigest(formatted)
		if before != after {
			t.Fatalf("formatter changed rule semantics\ninput:     %q\nformatted: %q\nbefore:\n%s\nafter:\n%s",
				source, formatted, before, after)
		}
	})
}

// ruleDigest renders a stable, whitespace-independent summary of every rule in
// source: directive, variable names, operator (name + exact argument bytes),
// and each action (name + exact value bytes). Two sources with the same digest
// are semantically equivalent rule sets.
func ruleDigest(source string) string {
	file := parser.Parse("file:///fuzz.conf", source)
	var sb strings.Builder
	for _, rule := range file.AllRules() {
		sb.WriteString("RULE ")
		sb.WriteString(rule.Directive)
		sb.WriteByte('\n')
		for _, v := range rule.Variables {
			fmt.Fprintf(&sb, "  VAR neg=%t count=%t %s:%s\n", v.Negated, v.Count, v.Name, v.Key)
		}
		if rule.Operator != nil {
			fmt.Fprintf(&sb, "  OP neg=%t @%s|%s\n", rule.Operator.Negated, rule.Operator.Name, rule.Operator.Argument)
		}
		for _, a := range rule.Actions {
			fmt.Fprintf(&sb, "  ACT %s colon=%t |%s\n", a.LowerName(), a.HasColon, a.Value)
		}
	}
	return sb.String()
}

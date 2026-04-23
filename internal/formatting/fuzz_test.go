// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package formatting

import (
	"testing"
	"unicode/utf8"
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

// FuzzFormatPreservesBytes asserts the formatter never introduces new
// non-whitespace content. The diff between source and formatted source must
// consist entirely of whitespace changes, so the bag of non-whitespace bytes
// must be identical. Catches transformations that mangle rule text.
func FuzzFormatPreservesBytes(f *testing.F) {
	for _, s := range formatSeeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, source string) {
		if !utf8.ValidString(source) || len(source) > 32*1024 {
			t.Skip()
		}
		formatted := formatSource(source)
		if nonWS(source) != nonWS(formatted) {
			t.Fatalf("formatter changed non-whitespace bytes\ninput:     %q\nformatted: %q", source, formatted)
		}
	})
}

// nonWS returns s with ASCII whitespace AND all backslashes removed.
// Backslashes in SecLang have two roles: line-continuation markers (which the
// formatter may legitimately remove) and regex escapes inside quoted strings
// (preserved on both sides since the formatter never touches quoted content).
// In either case, comparing bag-of-bytes minus whitespace-and-backslash is
// a conservative invariant: it catches any loss of actual rule content
// (directive names, variables, operator names, action keys/values, comments)
// without false-flagging structural backslash rewrites.
func nonWS(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\r', '\n', '\v', '\f', '\\':
			continue
		}
		b = append(b, s[i])
	}
	return string(b)
}

package parser

import (
	"strings"
	"testing"

	"github.com/coraza-incubator/coraza-lsp/internal/lsppos"
)

// Positions must be reported in UTF-16 code units (the LSP default encoding), so
// an astral-plane character (emoji = 1 rune but 2 UTF-16 units) before a token
// shifts that token's column by the extra unit. This is what lets a client put
// the squiggle on exactly the right spot even in AI-generated rules full of
// emoji / unusual Unicode.
func TestActionColumns_UTF16AstralExact(t *testing.T) {
	src := `SecAction "id:1,phase:2,msg:'😀',deny"`
	f := Parse("u", src)
	if len(f.Nodes) == 0 {
		t.Fatal("no nodes parsed")
	}
	rule, ok := f.Nodes[0].(*RuleNode)
	if !ok {
		t.Fatalf("expected RuleNode, got %T", f.Nodes[0])
	}

	var deny *ActionExpr
	for i := range rule.Actions {
		if rule.Actions[i].Name == "deny" {
			deny = &rule.Actions[i]
		}
	}
	if deny == nil {
		t.Fatal("deny action not found")
	}

	// The expected column is the UTF-16 length of everything before "deny".
	want := lsppos.UTF16Len(src[:strings.Index(src, "deny")])
	if deny.Range.Start.Character != want {
		t.Fatalf("deny column = %d, want %d (UTF-16). Rune-based code would report %d",
			deny.Range.Start.Character, want, want-1)
	}
}

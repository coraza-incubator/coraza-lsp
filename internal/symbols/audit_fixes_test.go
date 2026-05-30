package symbols

import (
	"strings"
	"testing"

	"github.com/coraza-incubator/coraza-lsp/internal/parser"
)

func TestWorkspaceSymbols_MatchesTagAndSkipsNoID(t *testing.T) {
	src := strings.Join([]string{
		`SecRule ARGS "@rx x" "id:100,phase:2,tag:'attack-sqli',chain"`,
		`    SecRule ARGS "@rx y" "t:none"`, // chain child: no id
	}, "\n")
	docs := map[string]*parser.File{"file:///r.conf": parser.Parse("file:///r.conf", src)}

	// Tag search finds the rule by its tag value.
	got := WorkspaceSymbols("attack-sqli", docs)
	if len(got) != 1 || !strings.Contains(got[0].Name, "100") {
		t.Fatalf("tag search: got %+v, want one symbol for id 100", got)
	}

	// Listing all symbols skips the chain continuation (no id) — no bare "SecRule".
	all := WorkspaceSymbols("", docs)
	if len(all) != 1 {
		t.Fatalf("got %d symbols, want 1 (no-id chain child must be skipped): %+v", len(all), all)
	}
}

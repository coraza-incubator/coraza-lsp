package knowledge

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The vim syntax file keeps a hand-written `syntax keyword seclangDirective`
// list that must not drift behind the knowledge base. This test extracts that
// keyword block and fails if any KB directive is missing from it (matching is
// case-insensitive, mirroring vim's `syntax case ignore`).
func TestVimSyntaxCoversKnowledgeDirectives(t *testing.T) {
	const vimPath = "../../editors/vim/syntax/seclang.vim"
	data, err := os.ReadFile(vimPath)
	if err != nil {
		t.Fatalf("read %s: %v", vimPath, err)
	}

	// Collect the keyword tokens in the seclangDirective block.
	keywords := map[string]bool{}
	tokenRe := regexp.MustCompile(`[A-Za-z][A-Za-z0-9]+`)
	inBlock := false
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "syntax keyword seclangDirective") {
			inBlock = true
			continue
		}
		if inBlock {
			if strings.HasPrefix(strings.TrimSpace(line), `\`) {
				for _, tok := range tokenRe.FindAllString(line, -1) {
					keywords[strings.ToLower(tok)] = true
				}
				continue
			}
			break // block ended
		}
	}
	if len(keywords) == 0 {
		t.Fatal("could not parse the seclangDirective keyword block from the vim syntax file")
	}

	var missing []string
	for _, d := range Default.Directives {
		if !keywords[strings.ToLower(d.Name)] {
			missing = append(missing, d.Name)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("vim syntax/seclang.vim is missing %d knowledge-base directive(s): %s\n"+
			"Add them to the `syntax keyword seclangDirective` block in editors/vim/syntax/seclang.vim.",
			len(missing), strings.Join(missing, ", "))
	}
}

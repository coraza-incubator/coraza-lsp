package hover

import (
	"strings"
	"testing"

	"github.com/coraza-incubator/coraza-lsp/internal/parser"
)

// Hovering a %{...} macro inside an operator argument returns the macro's
// variable doc, not the operator doc.
func TestHover_MacroInsideOperatorArg(t *testing.T) {
	src := `SecRule TX:foo "@rx %{TX.0}" "id:1,phase:2"`
	f := parser.Parse("u", src)
	col := strings.Index(src, "%{TX") + 2 // on the "TX" inside %{...}
	res := Hover(f, src, 0, col)
	if res == nil || !strings.Contains(strings.ToUpper(res.Contents.Value), "TX") {
		t.Fatalf("macro hover in operator arg: got %+v, want TX variable doc", res)
	}
}

// Hovering the `t` keyword shows the `t` action doc; hovering the value shows
// the transformation doc.
func TestHover_TKeywordVsValue(t *testing.T) {
	src := `SecRule ARGS "@rx x" "id:1,t:lowercase"`
	f := parser.Parse("u", src)
	kw := strings.Index(src, "t:lowercase") // on the `t`
	val := strings.Index(src, "lowercase")  // on the value

	kwRes := Hover(f, src, 0, kw)
	valRes := Hover(f, src, 0, val)
	if kwRes == nil || valRes == nil {
		t.Fatalf("expected hover results: kw=%v val=%v", kwRes, valRes)
	}
	// The `t` keyword shows the `t` action doc (title "## t"); the value shows
	// the lowercase transformation doc (title "## lowercase").
	if !strings.HasPrefix(kwRes.Contents.Value, "## t\n") {
		t.Fatalf("hovering `t` keyword should show the `t` action doc, got: %q", kwRes.Contents.Value)
	}
	if !strings.Contains(valRes.Contents.Value, "## lowercase") {
		t.Fatalf("hovering the value should show the lowercase transformation doc, got: %q", valRes.Contents.Value)
	}
	if kwRes.Contents.Value == valRes.Contents.Value {
		t.Fatalf("keyword and value hovers should differ")
	}
}

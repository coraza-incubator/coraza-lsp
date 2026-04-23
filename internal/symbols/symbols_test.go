// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package symbols

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	protocol_3_16 "github.com/tliron/glsp/protocol_3_16"

	"github.com/coraza-incubator/coraza-lsp/internal/parser"
)

func TestDocumentSymbols_Empty(t *testing.T) {
	t.Parallel()
	f := parser.Parse("", "")
	syms := DocumentSymbols(f)
	assert.Empty(t, syms)
}

func TestDocumentSymbols_Rule(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx test" "id:1001,phase:2,deny,msg:'Test Rule'"`
	f := parser.Parse("", src)
	syms := DocumentSymbols(f)
	require.Len(t, syms, 1)
	assert.Contains(t, syms[0].Name, "1001")
	assert.Contains(t, syms[0].Name, "Test Rule")
	assert.Equal(t, protocol_3_16.SymbolKindKey, syms[0].Kind)
}

func TestDocumentSymbols_RuleNoMsg(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx test" "id:1001,phase:2,deny"`
	f := parser.Parse("", src)
	syms := DocumentSymbols(f)
	require.Len(t, syms, 1)
	assert.Contains(t, syms[0].Name, "1001")
}

func TestDocumentSymbols_RuleNoID(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx test" "phase:2,deny"`
	f := parser.Parse("", src)
	syms := DocumentSymbols(f)
	require.Len(t, syms, 1)
	assert.Equal(t, "SecRule", syms[0].Name)
}

func TestDocumentSymbols_Marker(t *testing.T) {
	t.Parallel()
	src := "SecMarker BEGIN_CHECKS"
	f := parser.Parse("", src)
	syms := DocumentSymbols(f)
	require.Len(t, syms, 1)
	assert.Contains(t, syms[0].Name, "BEGIN_CHECKS")
	assert.Equal(t, protocol_3_16.SymbolKindNamespace, syms[0].Kind)
}

func TestDocumentSymbols_Include(t *testing.T) {
	t.Parallel()
	src := "Include /etc/coraza/*.conf"
	f := parser.Parse("", src)
	syms := DocumentSymbols(f)
	require.Len(t, syms, 1)
	assert.Contains(t, syms[0].Name, "/etc/coraza/*.conf")
	assert.Equal(t, protocol_3_16.SymbolKindFile, syms[0].Kind)
}

func TestDocumentSymbols_Multiple(t *testing.T) {
	t.Parallel()
	src := "SecMarker BEGIN\nSecRule ARGS \"@rx x\" \"id:1,phase:2,deny\"\nSecMarker END"
	f := parser.Parse("", src)
	syms := DocumentSymbols(f)
	assert.Len(t, syms, 3)
}

func TestDocumentSymbols_SecAction(t *testing.T) {
	t.Parallel()
	src := `SecAction "id:100,phase:1,pass"`
	f := parser.Parse("", src)
	syms := DocumentSymbols(f)
	require.Len(t, syms, 1)
	assert.Contains(t, syms[0].Name, "100")
}

func TestWorkspaceSymbols_EmptyQuery(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx x" "id:1001,phase:2,deny,msg:'XSS'"`
	docs := map[string]*parser.File{
		"file:///a.conf": parser.Parse("file:///a.conf", src),
	}
	syms := WorkspaceSymbols("", docs)
	require.Len(t, syms, 1)
}

func TestWorkspaceSymbols_FilterByID(t *testing.T) {
	t.Parallel()
	src1 := `SecRule ARGS "@rx x" "id:1001,phase:2,deny,msg:'XSS Attack'"`
	src2 := `SecRule ARGS "@rx y" "id:2002,phase:2,deny,msg:'SQL Injection'"`
	docs := map[string]*parser.File{
		"file:///a.conf": parser.Parse("", src1),
		"file:///b.conf": parser.Parse("", src2),
	}
	syms := WorkspaceSymbols("1001", docs)
	require.Len(t, syms, 1)
	assert.Contains(t, syms[0].Name, "1001")
}

func TestWorkspaceSymbols_FilterByMsg(t *testing.T) {
	t.Parallel()
	src1 := `SecRule ARGS "@rx x" "id:1001,phase:2,deny,msg:'XSS Attack'"`
	src2 := `SecRule ARGS "@rx y" "id:2002,phase:2,deny,msg:'SQL Injection'"`
	docs := map[string]*parser.File{
		"file:///a.conf": parser.Parse("", src1),
		"file:///b.conf": parser.Parse("", src2),
	}
	syms := WorkspaceSymbols("SQL", docs)
	require.Len(t, syms, 1)
	assert.Contains(t, syms[0].Name, "SQL Injection")
}

func TestWorkspaceSymbols_CaseInsensitive(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx x" "id:1001,phase:2,deny,msg:'XSS Attack'"`
	docs := map[string]*parser.File{
		"file:///a.conf": parser.Parse("", src),
	}
	syms := WorkspaceSymbols("xss", docs)
	require.Len(t, syms, 1)
}

func TestWorkspaceSymbols_NoMatch(t *testing.T) {
	t.Parallel()
	src := `SecRule ARGS "@rx x" "id:1001,phase:2,deny,msg:'XSS'"`
	docs := map[string]*parser.File{
		"file:///a.conf": parser.Parse("", src),
	}
	syms := WorkspaceSymbols("zzznomatch", docs)
	assert.Empty(t, syms)
}

func TestContainsIgnoreCase(t *testing.T) {
	t.Parallel()
	assert.True(t, containsIgnoreCase("Hello World", "world"))
	assert.True(t, containsIgnoreCase("Hello World", "HELLO"))
	assert.True(t, containsIgnoreCase("abc", ""))
	assert.False(t, containsIgnoreCase("abc", "xyz"))
}

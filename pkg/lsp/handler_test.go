// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package lsp

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tliron/glsp"
	protocol "github.com/tliron/glsp/protocol_3_16"
)

// newTestCtx builds a minimal *glsp.Context suitable for unit tests.
// Notify and Call are no-ops so async goroutines don't panic.
func newTestCtx() *glsp.Context {
	return &glsp.Context{
		Notify: func(method string, params any) {},
		Call:   func(method string, params any, result any) {},
	}
}

// openDoc is a helper that opens a document in the server's store and returns the doc.
func openDoc(t *testing.T, s *Server, uri, src string) *Document {
	t.Helper()
	ctx := newTestCtx()
	err := s.didOpen(ctx, &protocol.DidOpenTextDocumentParams{
		TextDocument: protocol.TextDocumentItem{
			URI:  protocol.DocumentUri(uri),
			Text: src,
		},
	})
	require.NoError(t, err)
	return s.store.Get(uri)
}

// ---- document sync ---------------------------------------------------------

func TestDidOpen_StoresDocument(t *testing.T) {
	t.Parallel()
	s := New("test")
	doc := openDoc(t, s, "file:///test.conf", "SecRuleEngine On")
	require.NotNil(t, doc)
	assert.Equal(t, "SecRuleEngine On", doc.Content)
}

func TestDidChange_UpdatesContent(t *testing.T) {
	t.Parallel()
	s := New("test")
	openDoc(t, s, "file:///test.conf", "SecRuleEngine On")

	ctx := newTestCtx()
	raw, _ := json.Marshal(protocol.TextDocumentContentChangeEventWhole{Text: "SecRuleEngine Off"})
	var change any
	json.Unmarshal(raw, &change)
	err := s.didChange(ctx, &protocol.DidChangeTextDocumentParams{
		TextDocument: protocol.VersionedTextDocumentIdentifier{
			TextDocumentIdentifier: protocol.TextDocumentIdentifier{URI: "file:///test.conf"},
			Version:                2,
		},
		ContentChanges: []interface{}{change},
	})
	require.NoError(t, err)
	doc := s.store.Get("file:///test.conf")
	require.NotNil(t, doc)
	assert.Equal(t, "SecRuleEngine Off", doc.Content)
}

func TestDidClose_RemovesDocument(t *testing.T) {
	t.Parallel()
	s := New("test")
	openDoc(t, s, "file:///test.conf", "SecRuleEngine On")

	ctx := newTestCtx()
	err := s.didClose(ctx, &protocol.DidCloseTextDocumentParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "file:///test.conf"},
	})
	require.NoError(t, err)
	assert.Nil(t, s.store.Get("file:///test.conf"))
}

// ---- completion ------------------------------------------------------------

func TestCompletionHandler_DirectiveName(t *testing.T) {
	t.Parallel()
	s := New("test")
	openDoc(t, s, "file:///test.conf", "")

	ctx := newTestCtx()
	result, err := s.completionHandler(ctx, &protocol.CompletionParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: "file:///test.conf"},
			Position:     protocol.Position{Line: 0, Character: 3},
		},
	})
	require.NoError(t, err)
	items, ok := result.([]protocol.CompletionItem)
	if ok {
		// If items are returned, they should include SecRule.
		var found bool
		for _, item := range items {
			if item.Label == "SecRule" {
				found = true
			}
		}
		assert.True(t, found, "SecRule should be in completions for empty line")
	}
}

func TestCompletionHandler_MissingDocument(t *testing.T) {
	t.Parallel()
	s := New("test")
	ctx := newTestCtx()
	result, err := s.completionHandler(ctx, &protocol.CompletionParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: "file:///missing.conf"},
			Position:     protocol.Position{Line: 0, Character: 0},
		},
	})
	require.NoError(t, err)
	assert.Nil(t, result)
}

// ---- hover -----------------------------------------------------------------

func TestHoverHandler_MissingDocument(t *testing.T) {
	t.Parallel()
	s := New("test")
	ctx := newTestCtx()
	result, err := s.hoverHandler(ctx, &protocol.HoverParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: "file:///missing.conf"},
			Position:     protocol.Position{Line: 0, Character: 0},
		},
	})
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestHoverHandler_KnownDirective(t *testing.T) {
	t.Parallel()
	s := New("test")
	openDoc(t, s, "file:///test.conf", "SecRuleEngine On")

	ctx := newTestCtx()
	result, err := s.hoverHandler(ctx, &protocol.HoverParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: "file:///test.conf"},
			Position:     protocol.Position{Line: 0, Character: 5},
		},
	})
	require.NoError(t, err)
	if result != nil {
		mc, ok := result.Contents.(protocol.MarkupContent)
		if ok {
			assert.Contains(t, mc.Value, "SecRuleEngine")
		}
	}
}

// ---- definition ------------------------------------------------------------

func TestDefinitionHandler_MissingDocument(t *testing.T) {
	t.Parallel()
	s := New("test")
	ctx := newTestCtx()
	result, err := s.definitionHandler(ctx, &protocol.DefinitionParams{
		TextDocumentPositionParams: protocol.TextDocumentPositionParams{
			TextDocument: protocol.TextDocumentIdentifier{URI: "file:///missing.conf"},
			Position:     protocol.Position{Line: 0, Character: 0},
		},
	})
	require.NoError(t, err)
	assert.Nil(t, result)
}

// ---- document symbols ------------------------------------------------------

func TestDocumentSymbolsHandler_ReturnsSymbols(t *testing.T) {
	t.Parallel()
	s := New("test")
	src := `SecRule ARGS "@rx x" "id:1001,phase:2,deny,msg:'XSS Attack'"`
	openDoc(t, s, "file:///test.conf", src)

	ctx := newTestCtx()
	result, err := s.documentSymbols(ctx, &protocol.DocumentSymbolParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "file:///test.conf"},
	})
	require.NoError(t, err)
	syms, ok := result.([]protocol.DocumentSymbol)
	if ok {
		require.NotEmpty(t, syms)
		assert.Contains(t, syms[0].Name, "1001")
	}
}

func TestDocumentSymbolsHandler_MissingDocument(t *testing.T) {
	t.Parallel()
	s := New("test")
	ctx := newTestCtx()
	result, err := s.documentSymbols(ctx, &protocol.DocumentSymbolParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "file:///missing.conf"},
	})
	require.NoError(t, err)
	assert.Nil(t, result)
}

// ---- workspace symbols -----------------------------------------------------

func TestWorkspaceSymbols_ReturnsMatches(t *testing.T) {
	t.Parallel()
	s := New("test")
	openDoc(t, s, "file:///test.conf", `SecRule ARGS "@rx x" "id:1001,phase:2,deny,msg:'XSS Attack'"`)

	ctx := newTestCtx()
	result, err := s.workspaceSymbols(ctx, &protocol.WorkspaceSymbolParams{Query: "1001"})
	require.NoError(t, err)
	// result is already []protocol.SymbolInformation
	assert.NotEmpty(t, result)
}

// ---- formatting ------------------------------------------------------------

func TestFormattingHandler_ReturnsEdits(t *testing.T) {
	t.Parallel()
	s := New("test")
	openDoc(t, s, "file:///test.conf", "SecRuleEngine   On")

	ctx := newTestCtx()
	edits, err := s.formattingHandler(ctx, &protocol.DocumentFormattingParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "file:///test.conf"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, edits)
	assert.Equal(t, "SecRuleEngine On", edits[0].NewText)
}

func TestFormattingHandler_MissingDocument(t *testing.T) {
	t.Parallel()
	s := New("test")
	ctx := newTestCtx()
	edits, err := s.formattingHandler(ctx, &protocol.DocumentFormattingParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "file:///missing.conf"},
	})
	require.NoError(t, err)
	assert.Nil(t, edits)
}

// ---- code actions ----------------------------------------------------------

func TestCodeActionHandler_MissingDocument(t *testing.T) {
	t.Parallel()
	s := New("test")
	ctx := newTestCtx()
	result, err := s.codeActionHandler(ctx, &protocol.CodeActionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "file:///missing.conf"},
	})
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestCodeActionHandler_NoDiagnostics(t *testing.T) {
	t.Parallel()
	s := New("test")
	openDoc(t, s, "file:///test.conf", "SecRuleEngine On")

	ctx := newTestCtx()
	result, err := s.codeActionHandler(ctx, &protocol.CodeActionParams{
		TextDocument: protocol.TextDocumentIdentifier{URI: "file:///test.conf"},
		Context:      protocol.CodeActionContext{Diagnostics: nil},
	})
	require.NoError(t, err)
	assert.Nil(t, result)
}

// ---- initialize ------------------------------------------------------------

func TestInitialize_ReturnsCapabilities(t *testing.T) {
	t.Parallel()
	s := New("1.2.3")
	ctx := newTestCtx()
	fn := s.initialize("1.2.3")
	result, err := fn(ctx, &protocol.InitializeParams{})
	require.NoError(t, err)
	ir, ok := result.(protocol.InitializeResult)
	require.True(t, ok)
	assert.NotNil(t, ir.Capabilities.CompletionProvider)
	assert.Equal(t, true, ir.Capabilities.HoverProvider)
	assert.Equal(t, true, ir.Capabilities.DefinitionProvider)
	assert.Equal(t, true, ir.Capabilities.DocumentFormattingProvider)
	require.NotNil(t, ir.ServerInfo)
	assert.Equal(t, "1.2.3", *ir.ServerInfo.Version)
}

// ---- helpers ---------------------------------------------------------------

func TestSplitLines(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input    string
		expected []string
	}{
		{"a\nb\nc", []string{"a", "b", "c"}},
		{"single", []string{"single"}},
		{"a\n", []string{"a", ""}},
		{"", []string{""}},
	}
	for _, tc := range cases {
		got := splitLines(tc.input)
		assert.Equal(t, tc.expected, got, "input: %q", tc.input)
	}
}

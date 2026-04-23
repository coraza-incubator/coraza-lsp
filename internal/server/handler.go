// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/tliron/glsp"
	protocol "github.com/tliron/glsp/protocol_3_16"
	glspserver "github.com/tliron/glsp/server"

	"github.com/coraza-incubator/coraza-lsp/internal/analysis"
	"github.com/coraza-incubator/coraza-lsp/internal/codeactions"
	"github.com/coraza-incubator/coraza-lsp/internal/completion"
	"github.com/coraza-incubator/coraza-lsp/internal/definition"
	"github.com/coraza-incubator/coraza-lsp/internal/formatting"
	"github.com/coraza-incubator/coraza-lsp/internal/hover"
	"github.com/coraza-incubator/coraza-lsp/internal/parser"
	"github.com/coraza-incubator/coraza-lsp/internal/symbols"
)

const serverName = "coraza-lsp"

// Server wraps the glsp server and all LSP state.
type Server struct {
	store     *DocumentStore
	validator *analysis.Validator
	glsp      *glspserver.Server

	// ctxMu guards ctx; captured from any handler call for async notifications.
	ctxMu sync.RWMutex
	ctx   *glsp.Context
}

// New creates and wires up a new Server ready to call RunStdio / RunTCP / RunWebSocket.
func New(version string) *Server {
	s := &Server{
		store: NewDocumentStore(),
	}

	// Debounced Coraza oracle — fires 300 ms after the last change and pushes diagnostics.
	s.validator = analysis.NewValidator(300*time.Millisecond, func(uri string, diags []protocol.Diagnostic) {
		ctx := s.getCtx()
		if ctx == nil {
			return
		}
		go ctx.Notify(protocol.ServerTextDocumentPublishDiagnostics, &protocol.PublishDiagnosticsParams{
			URI:         protocol.DocumentUri(uri),
			Diagnostics: diags,
		})
	})

	handler := protocol.Handler{
		Initialize:                 s.initialize(version),
		Initialized:                s.initialized,
		Shutdown:                   s.shutdown,
		TextDocumentDidOpen:        s.didOpen,
		TextDocumentDidChange:      s.didChange,
		TextDocumentDidClose:       s.didClose,
		TextDocumentCompletion:     s.completionHandler,
		TextDocumentHover:          s.hoverHandler,
		TextDocumentDefinition:     s.definitionHandler,
		TextDocumentDocumentSymbol: s.documentSymbols,
		WorkspaceSymbol:            s.workspaceSymbols,
		TextDocumentFormatting:     s.formattingHandler,
		TextDocumentCodeAction:     s.codeActionHandler,
	}

	s.glsp = glspserver.NewServer(&handler, serverName, false)
	return s
}

// RunStdio starts the LSP server over stdin/stdout.
func (s *Server) RunStdio() error { return s.glsp.RunStdio() }

// RunTCP starts the LSP server on the given TCP address (e.g. "127.0.0.1:7998").
func (s *Server) RunTCP(addr string) error { return s.glsp.RunTCP(addr) }

// RunWebSocket starts the LSP server on the given WebSocket address.
func (s *Server) RunWebSocket(addr string) error { return s.glsp.RunWebSocket(addr) }

// saveCtx stores the most-recent glsp.Context for async notifications.
func (s *Server) saveCtx(ctx *glsp.Context) {
	s.ctxMu.Lock()
	s.ctx = ctx
	s.ctxMu.Unlock()
}

func (s *Server) getCtx() *glsp.Context {
	s.ctxMu.RLock()
	ctx := s.ctx
	s.ctxMu.RUnlock()
	return ctx
}

// ---- lifecycle -------------------------------------------------------------

func (s *Server) initialize(version string) protocol.InitializeFunc {
	return func(ctx *glsp.Context, params *protocol.InitializeParams) (any, error) {
		s.saveCtx(ctx)
		syncFull := protocol.TextDocumentSyncKindFull
		triggerChars := []string{"@", ":", " ", "|", "\""}
		return protocol.InitializeResult{
			Capabilities: protocol.ServerCapabilities{
				TextDocumentSync: &protocol.TextDocumentSyncOptions{
					OpenClose: boolPtr(true),
					Change:    &syncFull,
				},
				CompletionProvider: &protocol.CompletionOptions{
					TriggerCharacters: triggerChars,
				},
				HoverProvider:              true,
				DefinitionProvider:         true,
				DocumentSymbolProvider:     true,
				WorkspaceSymbolProvider:    true,
				DocumentFormattingProvider: true,
				CodeActionProvider:         true,
			},
			ServerInfo: &protocol.InitializeResultServerInfo{
				Name:    serverName,
				Version: &version,
			},
		}, nil
	}
}

func (s *Server) initialized(_ *glsp.Context, _ *protocol.InitializedParams) error {
	return nil
}

func (s *Server) shutdown(_ *glsp.Context) error {
	s.validator.CancelAll()
	return nil
}

// ---- document sync ---------------------------------------------------------

func (s *Server) didOpen(ctx *glsp.Context, params *protocol.DidOpenTextDocumentParams) error {
	s.saveCtx(ctx)
	uri := string(params.TextDocument.URI)
	doc := s.store.Open(uri, params.TextDocument.Text, params.TextDocument.Version)
	s.pushDiagnostics(ctx, uri, doc)
	return nil
}

func (s *Server) didChange(ctx *glsp.Context, params *protocol.DidChangeTextDocumentParams) error {
	s.saveCtx(ctx)
	if len(params.ContentChanges) == 0 {
		return nil
	}
	// Full-sync: the last event always carries the entire document text.
	text := extractFullText(params.ContentChanges[len(params.ContentChanges)-1])
	uri := string(params.TextDocument.URI)
	doc := s.store.Change(uri, text, params.TextDocument.Version)
	s.pushDiagnostics(ctx, uri, doc)
	return nil
}

func (s *Server) didClose(ctx *glsp.Context, params *protocol.DidCloseTextDocumentParams) error {
	s.saveCtx(ctx)
	uri := string(params.TextDocument.URI)
	s.validator.Cancel(uri)
	s.store.Close(uri)
	// Clear diagnostics on close.
	go ctx.Notify(protocol.ServerTextDocumentPublishDiagnostics, &protocol.PublishDiagnosticsParams{
		URI:         params.TextDocument.URI,
		Diagnostics: []protocol.Diagnostic{},
	})
	return nil
}

// pushDiagnostics sends Stage-1 diagnostics immediately then schedules Stage-2.
func (s *Server) pushDiagnostics(ctx *glsp.Context, uri string, doc *Document) {
	stage1 := analysis.Analyze(doc.AST)
	go ctx.Notify(protocol.ServerTextDocumentPublishDiagnostics, &protocol.PublishDiagnosticsParams{
		URI:         protocol.DocumentUri(uri),
		Diagnostics: stage1,
	})
	s.validator.Schedule(uri, doc.Content, stage1)
}

// ---- completion ------------------------------------------------------------

func (s *Server) completionHandler(ctx *glsp.Context, params *protocol.CompletionParams) (any, error) {
	s.saveCtx(ctx)
	doc := s.store.Get(string(params.TextDocument.URI))
	if doc == nil {
		return nil, nil
	}
	line := int(params.Position.Line)
	char := int(params.Position.Character)

	lines := splitLines(doc.Content)
	if line >= len(lines) {
		return nil, nil
	}
	partialLine := lines[line]
	if char <= len(partialLine) {
		partialLine = partialLine[:char]
	}

	compCtx, prefix := completion.DetectContext(partialLine, char)

	// For multi-line SecRules, physical continuation lines (e.g. "    phase:2,\")
	// don't start with a directive keyword so DetectContext returns
	// ContextDirectiveName or ContextUnknown. Use the AST to detect when the
	// cursor is inside a rule's action list and re-detect from the current line.
	if compCtx == completion.ContextDirectiveName || compCtx == completion.ContextUnknown {
		node := doc.AST.NodeAtPosition(line, char)
		if rule, ok := node.(*parser.RuleNode); ok {
			if rule.ActionsRange.ContainsPosition(line, char) {
				compCtx, prefix = completion.DetectContextInActionList(partialLine)
			}
		}
	}

	return completion.GetCompletions(compCtx, prefix, doc.AST), nil
}

// ---- hover -----------------------------------------------------------------

func (s *Server) hoverHandler(ctx *glsp.Context, params *protocol.HoverParams) (*protocol.Hover, error) {
	s.saveCtx(ctx)
	doc := s.store.Get(string(params.TextDocument.URI))
	if doc == nil {
		return nil, nil
	}
	result := hover.Hover(doc.AST, doc.Content, int(params.Position.Line), int(params.Position.Character))
	if result == nil {
		return nil, nil
	}
	return result.ToProtocol(), nil
}

// ---- definition ------------------------------------------------------------

func (s *Server) definitionHandler(ctx *glsp.Context, params *protocol.DefinitionParams) (any, error) {
	s.saveCtx(ctx)
	doc := s.store.Get(string(params.TextDocument.URI))
	if doc == nil {
		return nil, nil
	}
	locs := definition.Resolve(
		doc.AST,
		int(params.Position.Line),
		int(params.Position.Character),
		string(params.TextDocument.URI),
	)
	return locs, nil
}

// ---- symbols ---------------------------------------------------------------

func (s *Server) documentSymbols(ctx *glsp.Context, params *protocol.DocumentSymbolParams) (any, error) {
	s.saveCtx(ctx)
	doc := s.store.Get(string(params.TextDocument.URI))
	if doc == nil {
		return nil, nil
	}
	return symbols.DocumentSymbols(doc.AST), nil
}

func (s *Server) workspaceSymbols(ctx *glsp.Context, params *protocol.WorkspaceSymbolParams) ([]protocol.SymbolInformation, error) {
	s.saveCtx(ctx)
	return symbols.WorkspaceSymbols(params.Query, s.store.All()), nil
}

// ---- formatting ------------------------------------------------------------

func (s *Server) formattingHandler(ctx *glsp.Context, params *protocol.DocumentFormattingParams) ([]protocol.TextEdit, error) {
	s.saveCtx(ctx)
	doc := s.store.Get(string(params.TextDocument.URI))
	if doc == nil {
		return nil, nil
	}
	return formatting.Format(doc.Content), nil
}

// ---- code actions ----------------------------------------------------------

func (s *Server) codeActionHandler(ctx *glsp.Context, params *protocol.CodeActionParams) (any, error) {
	s.saveCtx(ctx)
	doc := s.store.Get(string(params.TextDocument.URI))
	if doc == nil {
		return nil, nil
	}
	actions := codeactions.CodeActionsForDiagnostics(params.Context.Diagnostics, doc.AST, doc.Content, params.Range)
	if len(actions) == 0 {
		return nil, nil
	}
	return actions, nil
}

// ---- helpers ---------------------------------------------------------------

func boolPtr(b bool) *bool { return &b }

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	lines = append(lines, s[start:])
	return lines
}

// extractFullText extracts the text from a TextDocumentContentChangeEvent.
// Under full-sync, every event is a "whole" event with only a Text field.
func extractFullText(raw any) string {
	b, err := json.Marshal(raw)
	if err != nil {
		return ""
	}
	var whole protocol.TextDocumentContentChangeEventWhole
	if err := json.Unmarshal(b, &whole); err != nil {
		return ""
	}
	return whole.Text
}

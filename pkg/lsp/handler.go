// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package lsp

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coraza-incubator/coraza-lsp/internal/config"

	"github.com/gorilla/websocket"
	"github.com/tliron/glsp"
	protocol "github.com/tliron/glsp/protocol_3_16"
	glspserver "github.com/tliron/glsp/server"

	"github.com/coraza-incubator/coraza-lsp/internal/analysis"
	"github.com/coraza-incubator/coraza-lsp/internal/codeactions"
	"github.com/coraza-incubator/coraza-lsp/internal/completion"
	"github.com/coraza-incubator/coraza-lsp/internal/definition"
	"github.com/coraza-incubator/coraza-lsp/internal/formatting"
	"github.com/coraza-incubator/coraza-lsp/internal/hover"
	"github.com/coraza-incubator/coraza-lsp/internal/lsppos"
	"github.com/coraza-incubator/coraza-lsp/internal/parser"
	"github.com/coraza-incubator/coraza-lsp/internal/symbols"
	"github.com/coraza-incubator/coraza-lsp/internal/uri"
)

const serverName = "coraza-lsp"

// Server wraps the glsp server and all LSP state.
type Server struct {
	store     *DocumentStore
	validator *analysis.Validator
	glsp      *glspserver.Server
	fs        FileSystem

	// ctxMu guards ctx; captured from any handler call for async notifications.
	ctxMu sync.RWMutex
	ctx   *glsp.Context

	// cfgState holds the live `.coraza.json` and its derived analysis options.
	// See pkg/lsp/config.go.
	cfgState configState
}

// New creates and wires up a new Server ready to call RunStdio / RunTCP /
// RunWebSocket / ServeWebSocket.
//
// Pass options to customise behaviour:
//   - WithFileSystem to inject a sandboxed FileSystem (required for embedders
//     that host the LSP in a multi-tenant web application — without it the
//     LSP reads directly from the host's disk).
//
// With no options the server behaves identically to previous releases: it
// uses OSFileSystem() and operates against the real disk.
func New(version string, opts ...Option) *Server {
	o := defaultOptions()
	for _, opt := range opts {
		opt(o)
	}

	s := &Server{
		store: NewDocumentStore(),
		fs:    o.fs,
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

// maxWSMessageBytes bounds the size of a single inbound WebSocket message so a
// hostile client can't force an unbounded allocation. Generous enough for very
// large rule files, bounded enough to deny a memory-exhaustion DoS.
//
// NOTE: this cap only applies to the WebSocket transport, where gorilla exposes
// Conn.SetReadLimit. The TCP transport goes through glsp's hardcoded
// jsonrpc2.VSCodeObjectCodec, which reads a client-supplied Content-Length and
// allocates that many bytes with no upstream hook to bound it; we do not fork
// glsp. The mitigation there is to bind TCP/WS to loopback only (see
// cmd/coraza-lsp). Both transports are documented as loopback-dev-only.
const maxWSMessageBytes = 32 << 20 // 32 MiB

// RunStdio starts the LSP server over stdin/stdout.
func (s *Server) RunStdio() error { return s.glsp.RunStdio() }

// RunTCP starts the LSP server on the given TCP address (e.g. "127.0.0.1:7998").
//
// SECURITY: there is no per-message size limit on this transport — glsp's
// jsonrpc2 codec honours a client-supplied Content-Length with no upstream
// hook to bound it (see maxWSMessageBytes). Bind to loopback only and treat
// this transport as dev-only.
func (s *Server) RunTCP(addr string) error { return s.glsp.RunTCP(addr) }

// RunWebSocket starts the LSP server on the given WebSocket address. Unlike the
// bundled glsp entrypoint (which accepts any Origin and sets no read limit),
// this owns the HTTP upgrade so it can:
//   - enforce a strict same-origin / no-Origin policy (rejecting cross-origin
//     browser connections), and
//   - cap the inbound message size via Conn.SetReadLimit.
//
// Native editor clients send no Origin header and are accepted; browser pages
// send one and are rejected unless it matches the listen host. Embedders that
// already own an HTTP router (and authenticate the upgrade themselves) should
// upgrade in their own handler and call ServeWebSocket on the resulting
// *websocket.Conn instead.
func (s *Server) RunWebSocket(addr string) error {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return checkWSOrigin(r) },
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("coraza-lsp: websocket upgrade failed: %v", err)
			return
		}
		defer conn.Close()
		s.ServeWebSocket(conn)
	})
	server := &http.Server{Addr: addr, Handler: mux}
	log.Printf("coraza-lsp: listening for WebSocket connections on %s", addr)
	return server.ListenAndServe()
}

// checkWSOrigin rejects cross-origin browser connections. Requests with no
// Origin header (native editors, CLI tools) are allowed. Requests whose Origin
// host doesn't match the request Host are rejected. This is intentionally
// strict: the WS transport is loopback-dev-only and must not be drivable from
// an arbitrary web page (which could otherwise reach the file-read primitive
// in the analyser).
func checkWSOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // non-browser client
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	// Allow only when the Origin host matches the host we're serving on.
	return strings.EqualFold(u.Host, r.Host)
}

// ServeWebSocket drives the LSP protocol over an already-upgraded WebSocket
// connection. It applies a read limit (maxWSMessageBytes) to bound inbound
// allocations, then blocks until the client disconnects. Use this from an
// authenticated HTTP handler:
//
//	upgrader := websocket.Upgrader{...}
//	conn, err := upgrader.Upgrade(w, r, nil)
//	if err != nil { return }
//	defer conn.Close()
//	lspsrv.ServeWebSocket(conn)
func (s *Server) ServeWebSocket(conn *websocket.Conn) {
	conn.SetReadLimit(maxWSMessageBytes)
	s.glsp.ServeWebSocket(conn)
}

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

		// Load `.coraza.json` from the workspace, if any. Parse/validation
		// errors are surfaced via window/showMessage so users aren't left
		// wondering why their overrides aren't taking effect.
		root := workspaceRoot(params)
		showError := func(msg string) {
			mt := protocol.MessageTypeWarning
			go ctx.Notify(protocol.ServerWindowShowMessage, &protocol.ShowMessageParams{
				Type:    mt,
				Message: msg,
			})
		}
		s.LoadConfig(root, showError)
		if err := s.WatchConfig(s.onConfigChange, showError); err != nil {
			showError(fmt.Sprintf("coraza-lsp: config watcher disabled: %v", err))
		}

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
	s.StopWatchConfig()
	return nil
}

// onConfigChange is called by the config watcher after a successful reload.
// Currently: re-publishes diagnostics for every open document so severity
// overrides from the new `.coraza.json` take effect immediately.
func (s *Server) onConfigChange(_, _ config.Config) {
	ctx := s.getCtx()
	if ctx == nil {
		return
	}
	for uri, doc := range s.store.AllDocs() {
		stage1 := analysis.AnalyzeWith(doc.AST, s.analysisOptions())
		stage1 = s.augmentCrossFile(uri, doc.AST, stage1)
		uriCopy := uri
		go ctx.Notify(protocol.ServerTextDocumentPublishDiagnostics, &protocol.PublishDiagnosticsParams{
			URI:         protocol.DocumentUri(uriCopy),
			Diagnostics: stage1,
		})
	}
}

// workspaceRoot extracts a filesystem path from the LSP initialize params.
// Falls back to the current working directory when no root is provided.
func workspaceRoot(params *protocol.InitializeParams) string {
	if params == nil {
		return "."
	}
	// Prefer WorkspaceFolders; fall back to rootUri.
	if len(params.WorkspaceFolders) > 0 {
		return uriToPath(params.WorkspaceFolders[0].URI)
	}
	if params.RootURI != nil {
		return uriToPath(string(*params.RootURI))
	}
	return "."
}

// uriToPath converts a file:// URI to an OS path (Windows drive letters and
// percent-encoding handled). See internal/uri for the canonical mapping.
func uriToPath(s string) string { return uri.ToPath(s) }

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
	// Full-sync: the last event always carries the entire document text. If
	// the client misbehaves and sends an incremental change (or a value we
	// can't interpret), skip the update rather than overwriting the document
	// with a fragment or an empty string.
	text, ok := extractFullText(params.ContentChanges[len(params.ContentChanges)-1])
	if !ok {
		return nil
	}
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
// The current `.coraza.json` severity overrides are applied on every call —
// hot-reload takes effect on the next edit/save without restarting the editor.
// When `global: true` is configured the set is augmented with workspace-wide
// duplicate-id diagnostics from the indexed closed-file set.
func (s *Server) pushDiagnostics(ctx *glsp.Context, uri string, doc *Document) {
	stage1 := analysis.AnalyzeWith(doc.AST, s.analysisOptions())
	stage1 = s.augmentCrossFile(uri, doc.AST, stage1)
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

	lines := doc.Lines
	if line >= len(lines) {
		return nil, nil
	}
	// params.Position.Character is a UTF-16 column. DetectContext and the line
	// slicing below are byte-based, so map it to a byte offset within this line.
	// (The AST position checks further down keep the UTF-16 column, since AST
	// ranges are UTF-16 too.)
	partialLine := lines[line]
	byteCol := lsppos.UTF16ColumnToByte(partialLine, char)
	partialLine = partialLine[:byteCol]

	compCtx, prefix := completion.DetectContext(partialLine, byteCol)

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
		s.fs,
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
	// Re-derive the diagnostics from our own analysis rather than trusting
	// params.Context.Diagnostics: glsp's IntegerOrString.UnmarshalJSON has a value
	// receiver, so a Diagnostic's `code` sent back by the client never populates
	// (Code.Value stays nil) and code-based quick-fixes would never match. Our
	// freshly-computed diagnostics carry the correct codes and overlap the same
	// requested range.
	diags := analysis.AnalyzeWith(doc.AST, s.analysisOptions())
	actions := codeactions.CodeActionsForDiagnostics(diags, doc.AST, doc.Content, params.Range, string(params.TextDocument.URI))
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

// extractFullText extracts the whole-document text from a content-change
// event. The server advertises TextDocumentSyncKindFull, so glsp has already
// unmarshalled each change into a concrete typed value (see
// DidChangeTextDocumentParams.UnmarshalJSON): a "whole" event when no Range is
// present, otherwise an incremental event with a Range.
//
// A direct type switch avoids the JSON marshal/unmarshal round-trip that used
// to run on every keystroke. The second return is false when the change cannot
// be treated as a full-document replacement (a mis-typed value, or an
// incremental change carrying a Range) so the caller can skip the store update
// rather than clobbering the document with a fragment or an empty string.
func extractFullText(raw any) (string, bool) {
	switch v := raw.(type) {
	case protocol.TextDocumentContentChangeEventWhole:
		return v.Text, true
	case *protocol.TextDocumentContentChangeEventWhole:
		return v.Text, true
	case protocol.TextDocumentContentChangeEvent:
		// Only a full replacement when no Range is present.
		if v.Range == nil {
			return v.Text, true
		}
		return "", false
	case *protocol.TextDocumentContentChangeEvent:
		if v.Range == nil {
			return v.Text, true
		}
		return "", false
	}
	return "", false
}

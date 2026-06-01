# AGENTS.md — Coraza LSP Developer Guide

This document is for developers and AI agents working on `coraza-lsp`. It explains
the repository layout, key design decisions, and how to extend the server.

---

## Repository Map

```
coraza-lsp/
├── cmd/coraza-lsp/main.go          CLI: --stdio (default), --tcp, --ws, --version
│
├── internal/
│   ├── knowledge/
│   │   ├── knowledge.go            Item struct, Registry (pre-built maps), FilterByPrefix
│   │   ├── directives.go           ~37 SecLang directives with markdown docs
│   │   ├── variables.go            ~45 variables (ARGS, REQUEST_HEADERS, TX, …)
│   │   ├── operators.go            ~30 operators (@rx, @pm, @detectSQLi, …)
│   │   ├── actions.go              ~35 actions with ActionType tag
│   │   ├── transformations.go      ~34 transformations (lowercase, base64Decode, …)
│   │   └── knowledge_test.go
│   │
│   ├── parser/
│   │   ├── token.go                TokenType enum, Token struct (0-indexed positions)
│   │   ├── lexer.go                Line-oriented lexer; continuation-line stitching
│   │   ├── lexer_test.go
│   │   ├── ast.go                  Node interface, File, RuleNode, OperatorExpr, …
│   │   ├── parser.go               Tolerant recursive-descent parser → *File
│   │   ├── parser_test.go
│   │   ├── variables.go            Variable-list sub-parser (handles |, !, &, :key)
│   │   └── actions.go              Action-list sub-parser (handles comma, colon, quotes)
│   │
│   ├── analysis/
│   │   ├── diagnostics.go          Stage-1 (AST) + Stage-2 (Coraza oracle) + Validator
│   │   └── diagnostics_test.go
│   │
│   ├── completion/
│   │   ├── context.go              Context detection from partial line + cursor offset
│   │   ├── completion.go           Per-context item providers (snippets for directives)
│   │   └── completion_test.go
│   │
│   ├── hover/
│   │   ├── hover.go                Token-at-position → knowledge Registry lookup
│   │   └── hover_test.go
│   │
│   ├── symbols/
│   │   ├── symbols.go              Document symbols (rules/markers/includes), workspace symbols
│   │   └── symbols_test.go
│   │
│   ├── formatting/
│   │   ├── formatter.go            Normalise whitespace, collapse blank lines, join continuations
│   │   └── formatter_test.go
│   │
│   ├── definition/
│   │   ├── definition.go           skipAfter→SecMarker, Include→file URI
│   │   └── definition_test.go
│   │
│   ├── codeactions/
│   │   ├── codeactions.go          Quick-fixes: add id, add phase:2, remove line
│   │   └── codeactions_test.go
│   │
│   └── server/
│       ├── documents.go            Thread-safe full-sync document store + cached AST
│       ├── handler.go              glsp protocol.Handler wiring (all capabilities)
│       └── handler_test.go
│
├── editors/
│   ├── vscode/                     VS Code extension (TypeScript)
│   │   ├── package.json
│   │   ├── tsconfig.json
│   │   ├── language-configuration.json
│   │   ├── src/extension.ts        LanguageClient activation
│   │   └── syntaxes/seclang.tmLanguage.json
│   └── monaco/
│       ├── README.md               WebSocket integration guide
│       └── example/index.html      Stub HTML example
│
├── AGENTS.md                       ← you are here
├── README.md
├── go.mod
├── go.sum
└── Makefile
```

---

## 5 Key Design Decisions

> The rationale behind these (why a hand-written parser rather than reusing
> Coraza's, how the Coraza oracle is confined, the knowledge/vim drift guards,
> UTF-16 positions) is recorded in
> [`docs/adr/0001-parser-knowledge-and-positions.md`](docs/adr/0001-parser-knowledge-and-positions.md).

### 1. Hand-written recursive-descent parser (zero external deps)

We do **not** use ANTLR, PEG, or any parser generator. SecLang is line-oriented with
simple 3-token structure (`Directive Arg1 Arg2`). The only interesting sub-grammars
(variable expressions, action lists) are handled by small focused sub-parsers in
`internal/parser/variables.go` and `internal/parser/actions.go` (~80 lines each).

Benefit: no generated code to check in, no runtime dependency on `antlr4-go`,
full control over tolerance and position tracking.

### 2. Tolerant parsing — always produce a partial AST

The parser **never panics**. An error on line N does not stop parsing line N+1. Every
`Parse(uri, source)` call returns a complete `*File` with whatever nodes could be
parsed plus a `[]ParseError` slice. LSP features (hover, completion, symbols) all work
on partially-valid documents.

### 3. Compiled-in knowledge base — no files at runtime

All ~170 items (directives, variables, operators, actions, transformations) are compiled
Go slices and maps. The `knowledge.Default` registry is built once at `init()` with
`O(1)` name lookup. No JSON/YAML files, no `//go:embed`, no disk I/O after startup.

### 4. Two-stage diagnostics with Coraza WAF oracle

- **Stage 1** (synchronous, ~0ms): AST-level checks — missing `id`/`phase`, duplicate
  ids, invalid phase values, unknown directives, unresolved `skipAfter` targets. Pushes
  results immediately on every keystroke.
- **Stage 2** (async, debounced 300ms): Creates a fresh `coraza.NewWAF` instance with
  the document content as directives. Catches semantic errors the AST pass misses
  (e.g. invalid variable names, operator argument errors). Pushes merged results when
  the timer fires.

### 5. Full document sync — no incremental patching

We advertise `TextDocumentSyncKindFull`. Every `textDocument/didChange` event contains
the complete new document text. The server re-parses the entire file and caches the new
AST in the `DocumentStore`. This avoids the complexity and bugs of incremental patching,
and is fast enough because the parser is O(n) with n = number of logical lines.

---

## How to Add Items to the Knowledge Base

### Add a directive

Edit `internal/knowledge/directives.go`. Append an `Item{}` to `allDirectives`:

```go
{
    Name:        "SecNewDirective",
    Summary:     "One-line summary.",
    Description: "Full markdown description.\n\nUse double-quoted Go strings — Description fields\nmust NOT use backtick raw strings because backtick\nchars inside raw strings are a Go syntax error.",
    Syntax:      "SecNewDirective <value>",
    Example:     "SecNewDirective On",
},
```

Then run `make test` — `TestAllItemsWellFormed` will catch any empty Name/Summary.

### Add a variable / operator / action / transformation

Same pattern as above in the corresponding `internal/knowledge/<type>.go` file.

For **actions**, also set `ActionType` to one of:
`"disruptive"`, `"metadata"`, `"flow"`, `"non-disruptive"`, `"data"`.

---

## How to Add a New LSP Feature

1. Write the business logic in a new or existing `internal/<feature>/` package.
2. Add it to `internal/server/handler.go`:
   - Register a handler in `protocol.Handler{}` inside `New()`.
   - Declare the capability in `initialize()`.
3. Add tests to `internal/<feature>/<feature>_test.go` and `internal/server/handler_test.go`.

---

## Common Pitfalls

### LSP positions are 0-indexed; Coraza errors are 1-indexed

The parser, all AST nodes, and all LSP protocol positions use **0-indexed** line and
character offsets. Coraza's error messages report 1-indexed line numbers. When mapping
Coraza errors back to LSP ranges, subtract 1 from the line number.

### Full-sync content change casting

Under `TextDocumentSyncKindFull`, every change event is a
`TextDocumentContentChangeEventWhole` (which has only `Text`). The Go glsp library
deserialises changes as `interface{}`. In `handler.go` we marshal back to JSON and
unmarshal into `TextDocumentContentChangeEventWhole` to extract the text safely. Do not
attempt a direct type assertion to `map[string]interface{}`.

### ctx.Notify from async goroutines

The `*glsp.Context` passed to each handler wraps the persistent JSON-RPC connection,
not the request scope. It is safe to capture and call `ctx.Notify` from a goroutine
started in a different handler invocation. We store the most-recent ctx in
`Server.ctx` (protected by `sync.RWMutex`) for use by the `Validator` callback.

### String literals with backticks in knowledge files

Go raw string literals (`` `...` ``) cannot contain backtick characters. Knowledge item
`Description` fields that need inline code (` `` `) must use regular double-quoted
strings with `\n` for newlines. Using raw string literals for multi-line descriptions
that contain code examples will cause a syntax error at build time.

---

## Test and Build Commands

```bash
# Build the binary
make build

# Run all tests (with race detector)
make test

# Coverage report (opens in browser)
make cover

# Lint (requires golangci-lint)
make lint

# Build + package VSCode extension
make vscode

# Clean build artifacts
make clean
```

---

## Adding a New Transport

The `glspserver.Server` returned by `glspserver.NewServer()` exposes:
- `RunStdio()` — stdin/stdout (default, used by VS Code)
- `RunTCP(addr string)` — raw TCP (e.g. `:7998`)
- `RunWebSocket(addr string)` — WebSocket (e.g. `:7999`, used by Monaco)

All three call the same `protocol.Handler`. No code changes are required to add a new
transport beyond calling the appropriate `Run*` method.

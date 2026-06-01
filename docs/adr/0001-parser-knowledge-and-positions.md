# ADR 0001 — Parser, knowledge base, diagnostics oracle, and position encoding

Status: accepted (2026-05) · Supersedes: none

This record answers a recurring question — *is the hand-written approach right,
or should we refactor onto Coraza's own machinery?* — and documents the
architecture decisions reached during the May 2026 audit (PRs #3–#13) so they
are not re-litigated.

## Context

`coraza-lsp` is a Language Server for OWASP Coraza / ModSecurity SecLang rule
files. An LSP must keep working on **incomplete, invalid** documents (offering
hover/completion/symbols while the user is mid-edit) and must report problems at
**exact** source positions. The reference engine, Coraza, is a fail-fast rule
**loader**: it stops at the first error and does not retain editor-grade position
information. These are different jobs.

## Decisions

### 1. Keep the hand-written, tolerant recursive-descent parser

We do **not** reuse Coraza's `internal/seclang` parser for the AST.

- The LSP parser is **tolerant**: an error on one line never stops parsing the
  rest, so every `Parse` returns a complete `*File` plus a `[]ParseError`. Coraza's
  loader is fail-fast and its parser is in an `internal/` package (no API, no
  position fidelity).
- This is also what gopls / rust-analyzer / clangd do — editor parsers are
  hand-written precisely for error recovery.

Cost accepted: we maintain a parser. Mitigated by fuzzing, a CRS corpus parse
test, and the items below.

### 2. Coraza is used as a *semantic oracle*, not as the parser

Stage-1 diagnostics are AST checks (synchronous). Stage-2 builds a real
`coraza.NewWAF` from the document (debounced) to catch semantics the AST can't
(regex compile errors, etc.). The oracle is **confined**:

- built against an empty in-memory root FS (`fstest.MapFS{}`) so `Include` /
  `@pmFromFile` cannot read host files or block on a FIFO (PR #5);
- run under a wall-clock timeout with `recover()`;
- skipped for oversized documents;
- its position-less errors are de-duplicated against the precise Stage-1
  findings, and treated as best-effort (we do not expand reliance on parsing its
  error strings).

### 3. Knowledge base is compiled-in, guarded against drift

Directives/variables/operators/actions/transformations are static Go tables (fast,
no I/O). To stop them drifting from what Coraza actually accepts,
`internal/knowledge/drift_test.go` compiles every KB name through
`coraza.NewWAF` and fails CI if Coraza rejects it (pinned to the built Coraza
version, currently v3.5.0). We do **not** import Coraza's internal registries
(they are not exported) or generate the KB from them.

### 4. Positions are UTF-16 code units

LSP's default and universally-supported position encoding is UTF-16 code units.
The parser emits UTF-16 columns (`internal/lsppos`), and request handlers convert
the incoming UTF-16 column to a byte/rune index before indexing line text. We do
**not** advertise the 3.17 `positionEncoding` capability because the glsp library
is protocol 3.16 and exposes no field for it; clients therefore use the UTF-16
default, which is exactly what we emit. Result: diagnostics land on the exact
column even for non-ASCII / astral content (emoji, smart quotes, CJK).

### 5. Full document sync

We advertise `TextDocumentSyncKindFull` and re-parse on each change. SecLang
files are config-scale and the parser is O(n); incremental sync's complexity buys
nothing here.

### 6. Highlighting: TextMate is primary, vim is kept in lockstep

Editor highlighting is the TextMate grammar (`seclang.tmLanguage.json`); the vim
syntax mirrors it. Two guard rails keep them honest:

- `test/highlight/` tokenizes with the real `vscode-textmate` engine and fails on
  unscoped "holes"; `vscode-tmgrammar-snap` snapshots catch wrong scopes.
- `internal/knowledge/vim_drift_test.go` fails CI if the vim directive keyword
  list falls behind the knowledge base.

We considered driving highlighting from LSP semantic tokens instead; rejected for
now — it would not remove the TextMate grammar (needed for instant, pre-server
highlighting) and SecLang's highlighting needs are largely keyword/operator-based.

## Consequences

- We own a parser, a knowledge base, and two grammars — but each has an automated
  drift/regression guard, so the maintenance is bounded and CI-enforced.
- Reuse of Coraza is deliberate and narrow: as a confined semantic oracle and as
  the source of truth for the knowledge drift guard.

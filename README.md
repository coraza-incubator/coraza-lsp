# coraza-lsp

> **Status: experimental (v0.x).** The language server works end-to-end and
> has solid test coverage, but the public surface (diagnostic codes, CLI
> flags, LSP extensions, editor-side config keys) may change before 1.0.
> Pin a released version in CI and expect occasional breaking changes
> between minor releases. Feedback and issue reports are very welcome.

A Language Server for [OWASP Coraza](https://coraza.io) / ModSecurity SecLang
rule files. Provides editor support in VS Code, JetBrains IDEs (via LSP),
and Monaco Editor.

## Features

| Feature | Description |
|---|---|
| **Diagnostics** | Missing `id`/`phase`, duplicate ids, invalid phase, unknown directives, unresolved `skipAfter` targets. Backed by a live Coraza WAF oracle. |
| **Completions** | Directives, variables, operators, actions, transformations — context-aware with LSP snippets. |
| **Hover** | Full markdown documentation for any directive, variable, operator, action, or transformation. |
| **Go to Definition** | Jump from `skipAfter:MARKER` to `SecMarker MARKER`. Jump from `Include` path to the included file. |
| **Document Symbols** | List all rules (by id), markers, and includes in the current file. |
| **Workspace Symbols** | Search rules by id or message across all open files. |
| **Formatting** | Normalise spacing, collapse blank lines, join continuation lines. |
| **Code Actions** | Quick-fix: add missing `id`, add missing `phase:2`, remove unknown directive. |

## Scope & multi-file rule sets

`coraza-lsp` analyses each open file **in isolation**. It does **not** eagerly
crawl `Include` directives, and it does not know the order in which your rule
files are loaded at runtime — SecLang is a line-ordered, include-driven
language, and that order lives in the host's config (nginx, Apache, Caddy,
your own embedding), not in any one rule file.

Practical consequences:

- References that cross files (e.g. a `skipAfter:MARKER` whose `SecMarker` is
  defined in another file, or `SecRuleRemoveById` for an id defined elsewhere)
  are reported at **Information** severity with a note that the target may
  live in an Included file. They are hints, not errors.
- Duplicate-id detection only sees duplicates **within a single file**.
- Go-to-definition for markers and Includes works within the current file and
  for directly-Included paths that the server can resolve from the file's own
  directory.
- The Stage-2 Coraza WAF oracle also runs per-file, so any diagnostic that
  would require a global view is conservatively suppressed.

### Project config: `.coraza.json`

Drop a `.coraza.json` at the workspace root to override defaults. Generate a
commented starter with:

```bash
coraza-lsp init
```

Fields:

| Field | Type | Default | Purpose |
|---|---|---|---|
| `entrypoint` | string | `""` | Rule file that bootstraps the full set (e.g. `crs-setup.conf`). When set, cross-file diagnostics are promoted to warnings/errors. |
| `includePaths` | string[] | `[]` | Search roots for `Include` resolution, in order. Relative to the config file. |
| `global` | boolean | `false` | Index every workspace file matching `filePatterns`, not just open ones. Enables workspace-wide duplicate-id detection. |
| `filePatterns` | string[] | `["**/*.conf"]` | Files to treat as SecLang (combined with a SecLang-directive sniff). |
| `ignore` | string[] | `["**/.git/**", "**/node_modules/**"]` | Globs excluded from indexing. |
| `diagnostics` | map[string]string | `{}` | Per-code severity override: `error` / `warning` / `information` / `hint` / `off`. Keys are the diagnostic codes emitted by the server. |

The file is **hot-reloaded**: saving changes to `.coraza.json` re-applies the
settings to every open document without restarting the editor.

Schema: <https://raw.githubusercontent.com/coraza-incubator/coraza-lsp/main/schema/coraza.schema.json>
(the VS Code extension registers this automatically; other editors can
reference the URL via JSON Schema associations).

## Installation

### Pre-built binary

Download the latest release from the [releases page](https://github.com/coraza-incubator/coraza-lsp/releases).

### Build from source

```bash
git clone https://github.com/coraza-incubator/coraza-lsp
cd coraza-lsp
make build
# Binary at ./bin/coraza-lsp
```

Requires Go 1.25+.

## Usage

### VS Code

1. Install the **Coraza SecLang** extension from the VS Code Marketplace.
2. Place `coraza-lsp` on your `$PATH`, or set `coraza-lsp.serverPath` in settings.
3. Open any `.conf` file — the server starts automatically.

### Other editors (LSP-capable)

Start the server and point your editor's LSP client at it:

```bash
# stdio (default) — VS Code, Neovim, Helix, …
coraza-lsp --stdio

# TCP — Emacs lsp-mode, Sublime Text LSP, …
coraza-lsp --tcp 127.0.0.1:7998

# WebSocket — Monaco Editor in the browser
coraza-lsp --ws 127.0.0.1:7999
```

> **Security note**: the TCP and WebSocket transports have no authentication
> and no TLS. Always bind to a loopback address (`127.0.0.1` / `[::1]`) and
> treat them as local-development-only. Do not expose them to untrusted
> networks; put a reverse proxy with TLS and auth in front if you must.

### Monaco Editor

See [`editors/monaco/README.md`](editors/monaco/README.md) for the WebSocket integration guide.

## Configuration

| VS Code setting | Default | Description |
|---|---|---|
| `coraza-lsp.serverPath` | `coraza-lsp` | Path to the binary |
| `coraza-lsp.trace.server` | `off` | LSP trace level (`off`/`messages`/`verbose`) |

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  coraza-lsp                                         │
│                                                     │
│  cmd/coraza-lsp/main.go   — CLI flag parsing        │
│                                                     │
│  internal/server/                                   │
│    handler.go             — glsp protocol wiring    │
│    documents.go           — thread-safe doc store   │
│                                                     │
│  internal/parser/         — hand-written RD parser  │
│    lexer.go + token.go    — line-oriented tokeniser │
│    parser.go              — tolerant AST builder    │
│    variables.go           — variable sub-parser     │
│    actions.go             — action sub-parser       │
│                                                     │
│  internal/knowledge/      — compiled knowledge base │
│    directives / variables / operators /             │
│    actions / transformations                        │
│                                                     │
│  internal/analysis/       — two-stage diagnostics   │
│  internal/completion/     — context-aware completions│
│  internal/hover/          — markdown hover docs     │
│  internal/symbols/        — document + workspace    │
│  internal/formatting/     — whitespace normalisation│
│  internal/definition/     — go-to-definition        │
│  internal/codeactions/    — quick-fix actions       │
└─────────────────────────────────────────────────────┘
```

See [`AGENTS.md`](AGENTS.md) for a detailed developer guide.

## Performance

- **Parser**: O(n) with n = logical lines; a 10k-line rule set parses in < 5ms.
- **Completions / hover / symbols**: all operate on the cached AST — O(1) or O(rules) per request.
- **Stage-1 diagnostics**: synchronous on every change, < 1ms for typical files.
- **Stage-2 diagnostics**: debounced 300ms, async. Creates a fresh Coraza WAF (~5ms).

## Development

```bash
make test         # go test -race ./...
make cover        # coverage report (target: ≥90%)
make lint         # golangci-lint run
make integration  # live-WAF tests against OWASP CRS
make fuzz         # burst-fuzz the parser and analyzer (override FUZZTIME=2m for longer)
```

`make integration` expects the OWASP Core Rule Set checked out at
`/tmp/coreruleset`:

```bash
git clone --depth 1 https://github.com/coreruleset/coreruleset /tmp/coreruleset
```

## Author

Juan Pablo Tosso &lt;pablo@owasp.org&gt;

## License

Apache 2.0 — see [LICENSE](LICENSE). Copyright 2026 OWASP Coraza.

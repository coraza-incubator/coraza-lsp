# Coraza SecLang for VS Code

Rich editor support for [OWASP Coraza](https://coraza.io) / ModSecurity
SecLang rule files, powered by the [`coraza-lsp`](https://github.com/coraza-incubator/coraza-lsp)
language server.

> **Status: experimental.** Public surface (diagnostic codes, CLI flags,
> settings) may change before 1.0. Pin a version in CI.

## Features

- **Diagnostics** — missing `id` / `phase`, invalid phase, unknown
  directives, duplicate ids, unresolved `skipAfter` targets. A live
  Coraza WAF oracle runs in the background and surfaces semantic errors
  that static analysis alone would miss.
- **Completions** — directives, variables, operators, actions, and
  transformations, context-aware.
- **Hover** — full markdown documentation for every language element.
- **Go to definition** — jump from `skipAfter:MARKER` to `SecMarker MARKER`,
  or from `Include` to the included file.
- **Document / workspace symbols** — navigate rules by id, message or tag.
- **Go to rule by ID** — run **Coraza: Go to Rule by ID** (Command Palette) and
  type a rule id to jump straight to it. (Built on workspace symbols; open the
  rule files, or set `"global": true` in `.coraza.json`, so they are indexed.)
- **Formatting** — normalise whitespace and continuation lines on save.
- **Quick-fixes** — add missing `id`, add `phase:2`, remove unknown directive.

## Installation

### From the VS Code Marketplace

Search for **Coraza SecLang** in the Extensions view, or install from the
command line:

```bash
code --install-extension corazawaf.coraza-lsp
```

### VSCodium / Open VSX

```bash
codium --install-extension corazawaf.coraza-lsp
```

## Requirements

The extension needs the `coraza-lsp` binary on your `$PATH`. Options:

1. **Download a release** from
   <https://github.com/coraza-incubator/coraza-lsp/releases>, unpack, and
   add to `$PATH`.
2. **Build from source**:

   ```bash
   git clone https://github.com/coraza-incubator/coraza-lsp
   cd coraza-lsp && make build
   # Add ./bin to PATH, or set coraza-lsp.serverPath in VS Code settings.
   ```

## Settings

| Setting | Default | Description |
|---|---|---|
| `coraza-lsp.serverPath` | `coraza-lsp` | Path to the language-server binary. |
| `coraza-lsp.trace.server` | `off` | LSP trace level (`off` / `messages` / `verbose`). |
| `coraza-lsp.extraOperators` | `[]` | Extra operator names registered by Coraza / CRS plugins, treated as known so they aren't flagged unknown. Names may include a leading `@`. |
| `coraza-lsp.extraActions` | `[]` | Extra action names registered by plugins, treated as known. |
| `coraza-lsp.extraTransformations` | `[]` | Extra transformation names registered by plugins, treated as known. |

The three `extra*` settings declare custom-knowledge names so the analyser
does not report them as unknown. They **layer on top of** (are UNIONed with)
the matching `extraOperators` / `extraActions` / `extraTransformations` fields
in your workspace `.coraza.json` — declaring a name in either place is enough.
Because these are passed to the server only at startup, the language server is
**restarted automatically** when you change any of them.

## Multi-file rule sets

The server analyses each file in isolation — it does not eagerly crawl
`Include` directives, and it does not know the order in which your rules
load at runtime (that lives in your nginx / Apache / Caddy config). As a
result, references that cross files (e.g. `skipAfter:MARKER` whose marker
lives in another file) are reported at **Information** severity as hints,
not errors. See the [main README](https://github.com/coraza-incubator/coraza-lsp#scope--multi-file-rule-sets)
for details.

## Feedback

Issues and feature requests:
<https://github.com/coraza-incubator/coraza-lsp/issues>

## License

Apache 2.0 — see [LICENSE](LICENSE). Copyright 2026 OWASP Coraza.

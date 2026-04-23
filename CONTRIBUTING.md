# Contributing to coraza-lsp

Thanks for your interest in improving the Coraza Language Server.

## Development setup

```bash
git clone https://github.com/coraza-incubator/coraza-lsp
cd coraza-lsp
make build        # binary at ./bin/coraza-lsp
make test         # unit + race tests
make cover        # coverage report (target: ≥90%)
make lint         # golangci-lint run
make integration  # live-WAF tests against OWASP CRS (see README)
```

Requires Go 1.25+.

## Project layout

See [`AGENTS.md`](AGENTS.md) for a developer-oriented tour of the codebase.
Key packages:

- `internal/parser` — hand-written tolerant SecLang parser.
- `internal/knowledge` — compiled knowledge base of directives / variables /
  operators / actions / transformations.
- `internal/analysis` — two-stage diagnostics (static + live Coraza WAF).
- `internal/{completion,hover,symbols,formatting,definition,codeactions}` —
  one LSP feature each, all operating on the cached AST.
- `internal/server` — glsp protocol wiring and the thread-safe document store.

## Pull requests

- Keep changes focused — one feature or fix per PR.
- Add or update tests for every behavioural change.
- Run `make test` and `make lint` before pushing.
- Prefer Go standard-library idioms; avoid new dependencies without discussion.
- For new language-level behaviour, update the knowledge base and both
  completion + hover + diagnostic tests as needed.

## Releases

The core language server, the VS Code extension, and the Neovim plugin ship
independently. Each has its own tag prefix so you only trigger the release
pipeline for the thing that actually changed.

| Artifact | Version source | Tag format | Workflow |
|---|---|---|---|
| Core LSP (Go binary) | `git describe` / goreleaser | `v<semver>` (e.g. `v0.1.0`) | `.github/workflows/release.yml` |
| VS Code extension | `editors/vscode/package.json` | `vscode-v<semver>` (e.g. `vscode-v0.1.0`) | `.github/workflows/release-vscode.yml` |
| Neovim plugin | `editors/vim/` at HEAD | no tag needed; plugin managers follow git | — |

Rules of thumb:

- Bumping core code → bump `CHANGELOG.md`, commit, tag `v<new>`, push tag.
  Don't touch the extension version.
- Bumping the VS Code extension → bump `editors/vscode/package.json` version,
  commit, tag `vscode-v<new>`, push tag. The workflow verifies the tag matches
  the manifest before publishing. Full setup guide and secret configuration
  in [`editors/vscode/PUBLISHING.md`](editors/vscode/PUBLISHING.md).
- Both changed → two separate commits and two separate tags. This keeps
  release notes scoped and lets downstream users pin.

## Commit style

Conventional-commit-flavoured prefixes are appreciated (`feat:`, `fix:`,
`refactor:`, `docs:`, `test:`, `chore:`), as the release changelog is
grouped by them.

## Performance

Performance is a first-class concern — the language server runs inside the
user's editor and should never block the UI. When touching hot paths
(`parser`, `analysis`, `completion`, `hover`) please:

- Prefer pre-built maps and cached AST traversals.
- Avoid per-request allocations where a package-level slice / map works.
- Benchmark anything that touches the debounced Stage-2 validator.

## Code of Conduct

This project follows the Coraza [Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing you agree that your contributions are licensed under
Apache 2.0, matching the rest of the project.

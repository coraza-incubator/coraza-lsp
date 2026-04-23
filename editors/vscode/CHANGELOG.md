# Changelog

See the [top-level `CHANGELOG.md`](https://github.com/coraza-incubator/coraza-lsp/blob/main/CHANGELOG.md)
for the full history of the language server. Entries below track VS Code
extension-specific changes only.

## [Unreleased]

### Added

- Registers a JSON Schema for `.coraza.json` so the project config gets
  autocompletion + validation automatically.
- Bundled with esbuild; published `.vsix` is now a single file.

## [0.1.0] - 2026-04-23

Initial release. Thin wrapper over the `coraza-lsp` language server —
activates on `.conf` files with SecLang content, forwards LSP requests,
and registers the `seclang` language ID.

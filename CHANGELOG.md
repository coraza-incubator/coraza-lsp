# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Project config file `.coraza.json` at the workspace root, with JSON Schema
  (`schema/coraza.schema.json`). Fields: `entrypoint`, `includePaths`,
  `global`, `filePatterns`, `ignore`, `diagnostics`. Comments via the
  `"//":` JSONC convention supported.
- `coraza-lsp init` subcommand — writes a commented starter config.
- Hot reload: `.coraza.json` is watched via `fsnotify`; saving changes
  re-applies settings to every open document (100 ms debounce).
- Per-diagnostic severity overrides via `diagnostics` map (e.g.
  `"skipafter-not-found": "error"`, `"unknown-variable": "off"`).
- Workspace-wide duplicate-id detection when `global: true` — closed rule
  files are indexed and cross-file id collisions surface as diagnostics.
- VS Code extension registers the JSON schema via `contributes.jsonValidation`
  so `.coraza.json` autocompletes out of the box.
- VS Code extension bundled with esbuild — `.vsix` drops from 324 files /
  476 KB to 11 files / 103 KB, bundling warning eliminated.

## [0.1.0] - 2026-04-23

Initial release.

### Added

- Language server for OWASP Coraza / ModSecurity SecLang rule files.
- Diagnostics (stage-1 static + stage-2 live Coraza WAF oracle).
- Context-aware completions for directives, variables, operators, actions, transformations.
- Markdown hover documentation.
- Go to definition for `skipAfter:MARKER` and `Include` paths.
- Document and workspace symbol providers.
- Formatting (whitespace normalisation, continuation-line joining).
- Code actions (add missing `id`, add missing `phase:2`, remove unknown directive).
- stdio, TCP, and WebSocket transports.
- VS Code extension.
- Neovim plugin.
- Monaco Editor integration guide.

[Unreleased]: https://github.com/coraza-incubator/coraza-lsp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/coraza-incubator/coraza-lsp/releases/tag/v0.1.0

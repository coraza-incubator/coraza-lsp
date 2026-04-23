# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

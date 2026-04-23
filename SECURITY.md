# Security Policy

## Reporting a vulnerability

`coraza-lsp` is a development-time tool (an LSP server) and is not intended
to be exposed on a network. Still, if you discover a vulnerability that
could affect users of the language server, please report it privately.

**Preferred**: open a [private security advisory](https://github.com/coraza-incubator/coraza-lsp/security/advisories/new)
on GitHub.

**Alternative**: email the Coraza security team at security@coraza.io.

Please include:

- A description of the issue and the potential impact.
- Steps to reproduce, ideally with a minimal SecLang rule file or LSP request.
- The commit / release version you tested against.

We aim to acknowledge reports within five business days and will coordinate
a fix and disclosure timeline with you.

## Scope

In-scope:

- Crashes, panics, or infinite loops triggered by malicious rule files or LSP
  requests in the language server.
- Path-traversal or arbitrary-file-read issues via `Include` directive resolution.
- Unauthenticated access to functionality exposed by the `--tcp` or `--ws`
  transports (note: these transports are intended for loopback use only — see
  the README security note).

Out of scope:

- Vulnerabilities in OWASP Coraza itself — please report those upstream at
  <https://github.com/corazawaf/coraza>.
- Issues that require local filesystem access equivalent to running the server.

## Supported versions

Only the latest released minor version receives security fixes.

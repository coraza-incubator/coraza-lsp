# SecLang highlighting tests

Tests for the SecLang **TextMate grammar** (`editors/vscode/syntaxes/seclang.tmLanguage.json`)
that the VS Code and Monaco editors use for syntax highlighting. They tokenize
with the exact engine VS Code ships — [`vscode-textmate`](https://github.com/microsoft/vscode-textmate)
driving an Oniguruma WASM regex backend — so what they measure is the real
in-editor highlighting, not an approximation.

The vim syntax (`editors/vim/syntax/seclang.vim`) is covered separately by a
Neovim plenary spec at `editors/vim/test/spec/syntax_spec.lua`.

## Layout

| Path | Purpose |
|---|---|
| `lib/grammar.mjs` | Loads the shipped grammar and tokenizes text (line → tokens+scopes). |
| `tokenize.mjs` | CLI: dump every token of a file with its scope stack. |
| `audit.mjs` | Sweep a corpus and report **highlighting holes** — non-whitespace tokens that got no scope beyond the root `source.seclang` (they'd render as plain, unstyled text). |
| `fixtures/edge-cases.conf` | Hand-written corpus stressing operators, variable lists, macros, ctl/setvar, quoting, continuations and transformations. |
| `snap/*.conf` + `*.snap` | `vscode-tmgrammar-snap` snapshots: the full scope stack of every token. A snapshot diff catches **wrong** scopes (e.g. a transformation mis-scoped as a plain value), which the hole sweep alone cannot. |

## Running

```bash
cd test/highlight
npm install
npm test                 # snapshot tests + hole gate over fixtures (CI gate)

# Ad-hoc:
node tokenize.mjs ../../editors/vscode/testdata/simple.conf
node audit.mjs --corpus /tmp/coreruleset/rules        # sweep real OWASP CRS
npm run test:snap:update                              # re-bless snapshots after an intentional grammar change
```

`audit.mjs` accepts `--corpus DIR|FILE`, `--show N` (top-N holes), and
`--max N` (exit non-zero if distinct holes exceed N).

## What this caught

Running the sweep over the full OWASP CRS, the ModSecurity example rules and
the Coraza engine test corpus, plus the edge-case fixtures, surfaced and locked
fixes for:

1. An escaped quote (`\"`) inside a single-quoted `msg:'…'` value prematurely
   terminated the action-list region, breaking highlighting for the rest of a
   multi-line rule (region end now uses a negative lookbehind).
2. The generic action-key rule consumed leading whitespace, so on indented
   continuation lines it out-raced the specific `msg`/`id`/`severity`/… rules.
3. Column-0 (unindented) continuation lines — the canonical `modsecurity.conf`
   style — were not highlighted at all.
4. A trailing optional quote in `severity:`/`id:` swallowed the action list's
   own closing `"` when the action was last and unquoted (e.g. `…,severity:2"`).
5. `t:` transformations were never scoped as transformations — the rule was
   ordered after the generic value rule and never won.
6. Variable targets now scope the `|` separator, the `&`/`!` modifiers and
   `:selector` (plain / `'quoted'` / `/regex/`) distinctly, without a `/`-prefixed
   non-regex selector (e.g. `XML:/*`) bleeding into the operator string.

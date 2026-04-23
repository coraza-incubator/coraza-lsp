# coraza-lsp — Vim / Neovim Extension

Vim and Neovim editor support for [OWASP Coraza](https://coraza.io) / ModSecurity SecLang rule files, powered by the `coraza-lsp` language server.

| Feature | Neovim 0.8+ | Vim 8 + ALE |
|---------|:-----------:|:-----------:|
| Diagnostics / linting | ✓ | ✓ |
| Auto-completions | ✓ | — |
| Hover documentation | ✓ | — |
| Go-to-definition | ✓ | — |
| Document / workspace symbols | ✓ | — |
| Formatting | ✓ | — |
| Code actions (quick-fix) | ✓ | — |
| Syntax highlighting | ✓ | ✓ |
| Smart filetype detection | ✓ | ✓ |

---

## Prerequisites

Build the language server binary (once):

```bash
make build          # produces ./bin/coraza-lsp
```

Then make it available on `$PATH`:

```bash
# Option A — add the project bin/ to PATH
export PATH="$PWD/bin:$PATH"

# Option B — install to a standard location
cp bin/coraza-lsp /usr/local/bin/
```

---

## Neovim (full LSP support)

### Installation

**lazy.nvim**

```lua
{
  dir = '/path/to/coraza-lsp/editors/vim',
  ft  = 'seclang',
  config = function()
    require('coraza-lsp').setup()
  end,
}
```

**vim-plug**

```vim
Plug '/path/to/coraza-lsp/editors/vim'
```

Then in your `init.lua`:

```lua
require('coraza-lsp').setup()
```

### Configuration

All options are optional — the defaults mirror the VS Code extension:

```lua
require('coraza-lsp').setup({
  -- Path to the coraza-lsp binary (default: 'coraza-lsp', resolved via $PATH).
  server_path = 'coraza-lsp',

  -- Extra CLI arguments, e.g. { '-v' } for verbose server logs.
  cmd_extra_args = {},

  -- Called when the LSP client attaches to a buffer.
  on_attach = function(client, bufnr)
    local map = function(key, fn, desc)
      vim.keymap.set('n', key, fn, { buffer = bufnr, desc = desc })
    end
    map('K',          vim.lsp.buf.hover,           'Hover docs')
    map('gd',         vim.lsp.buf.definition,       'Go to definition')
    map('<leader>ca', vim.lsp.buf.code_action,      'Code actions')
    map('<leader>f',  vim.lsp.buf.format,           'Format file')
    map('<leader>s',  vim.lsp.buf.document_symbol,  'Document symbols')
  end,

  -- Override default LSP capabilities.
  capabilities = nil,

  -- Workspace root override (nil = parent directory of the opened file).
  root_dir = nil,

  -- Settings forwarded via workspace/didChangeConfiguration.
  settings = {},
})
```

### Commands

| Command | Description |
|---------|-------------|
| `:CorazaRestartServer` | Stop and restart the LSP server for all seclang buffers |
| `:CorazaServerInfo` | Show current server status |

### nvim-lspconfig compatibility

If you use [nvim-lspconfig](https://github.com/neovim/nvim-lspconfig), call `setup()` first
to register the server config, then configure it via lspconfig:

```lua
require('coraza-lsp').setup()           -- registers 'coraza_lsp' with lspconfig

require('lspconfig').coraza_lsp.setup({
  on_attach = my_on_attach,
  capabilities = my_capabilities,
})
```

---

## Vim (ALE linting only)

### Requirements

- [ALE](https://github.com/dense-analysis/ale) (any recent version)
- `coraza-lsp` on `$PATH` (or configure `g:ale_seclang_coraza_lsp_executable`)

### Installation

Add the plugin's `ale_linters/` directory to ALE's linter path, or copy/symlink
the linter file into your ALE installation:

```vim
" In your vimrc — add the plugin directory to the runtime path.
set rtp+=/path/to/coraza-lsp/editors/vim
```

ALE will auto-discover the linter once the filetype is `seclang`.

### Configuration

```vim
" Custom path to the binary (default: 'coraza-lsp').
let g:ale_seclang_coraza_lsp_executable = '/usr/local/bin/coraza-lsp'

" Restrict linters to just coraza_lsp for seclang files.
let g:ale_linters = { 'seclang': ['coraza_lsp'] }
```

---

## Filetype Detection

The plugin automatically assigns the `seclang` filetype to `.conf` files that
contain a SecLang directive in the first 20 lines. This avoids conflicts with
nginx, apache, and other `.conf`-based formats.

To force the filetype for a file that doesn't auto-detect:

```vim
:set filetype=seclang
```

Or add a modeline at the top of the file:

```
# vim: ft=seclang
```

---

## Running Tests

```bash
make vim        # runs the plenary.nvim test suite (requires Neovim)
```

Integration tests require the binary to be on `$PATH` or `CORAZA_LSP_PATH` to be set:

```bash
CORAZA_LSP_PATH=./bin/coraza-lsp make vim
```

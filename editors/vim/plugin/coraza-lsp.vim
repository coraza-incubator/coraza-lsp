" coraza-lsp Neovim plugin bootstrap.
" Provides user-facing commands. The actual LSP wiring is done in Lua
" via require('coraza-lsp').setup() in the user's init.lua / init.vim.

if !has('nvim') || exists('g:loaded_coraza_lsp')
  finish
endif
let g:loaded_coraza_lsp = 1

if !has('nvim-0.8')
  echohl WarningMsg
  echomsg 'coraza-lsp: Neovim 0.8+ required for LSP support. For Vim, use the ALE linter.'
  echohl None
  finish
endif

" :CorazaRestartServer — stop and restart the LSP server for all seclang buffers.
command! CorazaRestartServer lua require('coraza-lsp').restart()

" :CorazaServerInfo — display the current server status.
command! CorazaServerInfo    lua vim.notify(require('coraza-lsp').status(), vim.log.levels.INFO)

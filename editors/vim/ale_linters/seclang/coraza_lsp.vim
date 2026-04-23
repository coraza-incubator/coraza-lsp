" ALE linter for SecLang using coraza-lsp over stdio.
" Works with classic Vim 8+ and Neovim when ALE (dense-analysis/ale) is installed.
"
" Configuration:
"   let g:ale_seclang_coraza_lsp_executable = '/path/to/coraza-lsp'
"
" ALE uses the LSP stdio transport, so coraza-lsp must be on $PATH or the
" executable variable must point to the binary.

" Only register when ALE is loaded.
if !exists('g:loaded_ale')
  finish
endif

call ale#Set('seclang_coraza_lsp_executable', 'coraza-lsp')

call ale#linter#Define('seclang', {
\   'name':         'coraza_lsp',
\   'lsp':          'stdio',
\   'language':     'seclang',
\   'executable':   {b -> ale#Var(b, 'seclang_coraza_lsp_executable')},
\   'command':      '%e --stdio',
\   'project_root': {b -> expand('#' . b . ':p:h')},
\})

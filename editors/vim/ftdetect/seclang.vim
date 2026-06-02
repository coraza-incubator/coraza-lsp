" Filetype detection for SecLang (OWASP Coraza / ModSecurity rule files).
" Only assigns 'seclang' to .conf files that contain SecLang directives,
" avoiding conflicts with nginx, apache, and other .conf formats.

if exists('g:loaded_coraza_lsp_ftdetect')
  finish
endif
let g:loaded_coraza_lsp_ftdetect = 1

function! s:DetectSecLang() abort
  " Scan the first 20 lines for a recognisable SecLang directive.
  for l:lnum in range(1, min([20, line('$')]))
    if getline(l:lnum) =~# '\v^\s*(SecRule|SecAction|SecMarker|SecDefaultAction|SecRuleEngine|SecRequestBodyAccess|SecResponseBodyAccess|SecAuditEngine|SecAuditLog|Include)>'
      " Use `set filetype=seclang` rather than `setfiletype seclang` to
      " override the built-in `.conf` detection (which runs first and
      " would otherwise win because `setfiletype` is a no-op when the
      " filetype is already set).
      set filetype=seclang
      return
    endif
  endfor
endfunction

augroup coraza_lsp_ftdetect
  autocmd!
  autocmd BufNewFile,BufRead *.conf call s:DetectSecLang()
augroup END

" Syntax highlighting for SecLang (OWASP Coraza / ModSecurity rule files).
" Ported from editors/vscode/syntaxes/seclang.tmLanguage.json.

if exists('b:current_syntax')
  finish
endif

syntax case ignore

" ── Comments ───────────────────────────────────────────────────────────────
syntax match seclangComment /^\s*#.*/

" ── Line continuation ───────────────────────────────────────────────────────
syntax match seclangContinuation /\\$/

" ── Directive keywords ─────────────────────────────────────────────────────
" All Sec* directives and Include (case-insensitive via 'syntax case ignore').
syntax keyword seclangDirective
  \ SecAction SecDefaultAction SecRule SecMarker
  \ SecRuleEngine SecRequestBodyAccess SecResponseBodyAccess
  \ SecAuditEngine SecAuditLog SecAuditLogParts SecAuditLogType
  \ SecAuditLogStorageDir SecAuditLogRelevantStatus
  \ SecDebugLog SecDebugLogLevel
  \ SecDataDir SecTmpDir
  \ SecUploadDir SecUploadKeepFiles SecUploadFileMode SecUploadFileLimit
  \ SecRequestBodyLimit SecRequestBodyNoFilesLimit SecRequestBodyInMemoryLimit
  \ SecResponseBodyLimit SecResponseBodyMimeType SecResponseBodyMimeTypesClear
  \ SecArgumentSeparator SecCookieFormat SecUnicodeMapFile
  \ SecStatusEngine SecPcreMatchLimit SecPcreMatchLimitRecursion
  \ SecConnEngine SecReadStateLimit SecWriteStateLimit
  \ SecComponentSignature SecGeoLookupDB SecGsbLookupDB
  \ SecHashEngine SecHashKey SecHashParam SecHashMethodRx SecHashMethodPm
  \ Include

" ── Variables (ALL_CAPS, with optional :key suffix) ────────────────────────
" Matches e.g. ARGS, REQUEST_HEADERS, TX:my_var, &MATCHED_VARS
syntax match seclangVariable /[&!]\?\<[A-Z_][A-Z0-9_.]*\>\(:[^ \t@"\\|,]*\)\?/

" ── Quoted strings ─────────────────────────────────────────────────────────
" A region for any double-quoted string; contained patterns apply inside it.
syntax region seclangString
  \ start=/"/
  \ skip=/\\"/
  \ end=/"/
  \ contains=seclangOperator,seclangActionKey,seclangTransformation

" Operator name at the start of a quoted string, e.g. "@rx", "!@pm", "@detectSQLi"
syntax match seclangOperator /\(^\|"\)\s*!*@[a-zA-Z][a-zA-Z0-9_]*/ contained

" Action keys: word immediately after a '"' or ',' separator inside action lists.
" Matches "id", "phase", "deny", "msg", "t" etc. before ':' or ','
syntax match seclangActionKey /\(["',]\s*\)\@<=[a-zA-Z][a-zA-Z0-9_]*\ze\s*[:,"]/ contained

" Transformation names after t:, e.g. t:lowercase, t:base64Decode
syntax match seclangTransformation /\(t:\)\@<=[a-zA-Z][a-zA-Z0-9_]*/ contained

" Comments take highest priority (override any region).
syntax match seclangComment /^\s*#.*/ contains=NONE

" ── Highlight links ────────────────────────────────────────────────────────
highlight default link seclangComment      Comment
highlight default link seclangContinuation Special
highlight default link seclangDirective    Keyword
highlight default link seclangVariable     Identifier
highlight default link seclangString       String
highlight default link seclangOperator     Function
highlight default link seclangActionKey    Type
highlight default link seclangTransformation Constant

let b:current_syntax = 'seclang'

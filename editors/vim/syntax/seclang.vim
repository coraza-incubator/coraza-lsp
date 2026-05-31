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
" This list is kept in sync with internal/knowledge/directives.go — a Go test
" (TestVimSyntaxCoversKnowledgeDirectives) fails CI if a known directive is
" missing here. 'syntax case ignore' makes matching case-insensitive.
syntax keyword seclangDirective
  \ SecAction SecArgumentSeparator SecArgumentsLimit SecAuditEngine SecAuditLog
  \ SecAuditLogDirMode SecAuditLogFileMode SecAuditLogFormat SecAuditLogParts SecAuditLogRelevantStatus
  \ SecAuditLogStorageDir SecAuditLogType SecCollectionTimeout SecComponentSignature SecConnEngine
  \ SecConnReadStateLimit SecConnWriteStateLimit SecCookieFormat SecDataDir SecDataset
  \ SecDebugLog SecDebugLogLevel SecDefaultAction SecGeoLookupDB SecGsbLookupDb
  \ SecHTTPBlKey SecHashEngine SecHashKey SecHashMethodPm SecHashMethodRx
  \ SecHashParam SecIgnoreRuleCompilationErrors SecMarker SecPcreMatchLimit SecPcreMatchLimitRecursion
  \ SecReadStateLimit SecRemoteRules SecRemoteRulesFailAction SecRequestBodyAccess SecRequestBodyInMemoryLimit
  \ SecRequestBodyJsonDepthLimit SecRequestBodyLimit SecRequestBodyLimitAction SecRequestBodyNoFilesLimit SecResponseBodyAccess
  \ SecResponseBodyLimit SecResponseBodyLimitAction SecResponseBodyMimeType SecResponseBodyMimeTypesClear SecRule
  \ SecRuleEngine SecRulePerfTime SecRuleRemoveById SecRuleRemoveByMsg SecRuleRemoveByTag
  \ SecRuleScript SecRuleUpdateActionById SecRuleUpdateTargetById SecRuleUpdateTargetByMsg SecRuleUpdateTargetByTag
  \ SecSensorID SecServerSignature SecStatusEngine SecTmpDir SecUnicodeMap
  \ SecUnicodeMapFile SecUploadDir SecUploadFileLimit SecUploadFileMode SecUploadKeepFiles
  \ SecWebAppID SecWriteStateLimit
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

" ── Multi-line sync ─────────────────────────────────────────────────────────
" Action-list and operator strings span several physical lines via '\'
" continuation. Sync from far enough back that scrolling into the middle of a
" long multi-line rule (e.g. CRS 942220 spans ~20 lines) still resolves the
" enclosing quoted-string region correctly.
syntax sync minlines=50

let b:current_syntax = 'seclang'

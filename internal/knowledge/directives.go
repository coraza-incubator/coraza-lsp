// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package knowledge

// allDirectives contains all known SecLang directives with full documentation.
var allDirectives = []Item{
	{
		Name:    "SecRule",
		Summary: "Create an inspection rule that matches variables against an operator",
		Syntax:  `SecRule VARIABLES "@OPERATOR argument" "ACTIONS"`,
		Example: `SecRule ARGS "@rx <script" "id:1001,phase:2,deny,status:403,msg:'XSS Attack'"`,
		Description: "**SecRule** defines an inspection rule. It evaluates one or more *variables* against\n" +
			"an *operator* and executes *actions* when a match is found.\n\n" +
			"**Arguments:**\n" +
			"- **VARIABLES** — one or more collection variables, pipe-separated (e.g. `ARGS|REQUEST_HEADERS`)\n" +
			"- **OPERATOR** — operator prefixed with `@`, defaults to `@rx` if omitted\n" +
			"- **ACTIONS** — comma-separated list of actions; must include `id` and `phase`\n\n" +
			"**Chaining:** Append `chain` to link this rule with the next; all rules in a chain must match.",
	},
	{
		Name:    "SecAction",
		Summary: "Execute actions unconditionally (no variable matching)",
		Syntax:  `SecAction "ACTIONS"`,
		Example: `SecAction "id:1000,phase:1,pass,nolog,setvar:tx.anomaly_score=0"`,
		Description: "**SecAction** executes actions unconditionally without inspecting any variable.\n" +
			"Useful for initialization, setting transaction variables, or unconditional logging.\n\n" +
			"Actions must include `id` and `phase`. Use `pass` to continue processing.",
	},
	{
		Name:    "SecDefaultAction",
		Summary: "Set the default action list inherited by subsequent SecRule directives",
		Syntax:  `SecDefaultAction "ACTIONS"`,
		Example: `SecDefaultAction "phase:2,log,auditlog,deny,status:403"`,
		Description: "**SecDefaultAction** sets the default action list for all subsequent `SecRule` directives\n" +
			"that do not explicitly override these actions.\n\n" +
			"**Requirements:** Must contain both a `phase` action and a disruptive action.\n" +
			"Rules inherit these defaults but can override individual actions.",
	},
	{
		Name:    "SecMarker",
		Summary: "Create a named marker for use with skipAfter action",
		Syntax:  `SecMarker MARKER_NAME`,
		Example: `SecMarker END_HOST_CHECK`,
		Description: "**SecMarker** creates a named anchor in the rule set. Rules using `skipAfter:MARKER_NAME`\n" +
			"jump execution to the rule immediately following this marker.\n\n" +
			"Markers are commonly used to implement conditional rule blocks where a preceding\n" +
			"rule skips a group of rules when a condition is not met.",
	},
	{
		Name:    "Include",
		Summary: "Load rules from an external file or glob pattern",
		Syntax:  `Include /path/to/file.conf`,
		Example: `Include /etc/coraza/rules/*.conf`,
		Description: "**Include** loads and processes additional configuration files. Supports glob patterns:\n" +
			"- `*` matches any sequence of non-separator characters\n" +
			"- `?` matches any single non-separator character\n" +
			"- `[seq]` matches any character in the set\n\n" +
			"Paths are relative to the current configuration file unless absolute.",
	},
	{
		Name:    "SecRuleEngine",
		Summary: "Enable, disable, or set detection-only mode for the WAF engine",
		Syntax:  `SecRuleEngine On|Off|DetectionOnly`,
		Example: `SecRuleEngine DetectionOnly`,
		Description: "**SecRuleEngine** controls how the WAF processes requests:\n" +
			"- **On** — inspect traffic and enforce rules (default)\n" +
			"- **Off** — disable all inspection\n" +
			"- **DetectionOnly** — inspect and log but never block requests\n\n" +
			"`DetectionOnly` is useful during initial deployment to assess impact before enabling enforcement.",
	},
	{
		Name:    "SecRequestBodyAccess",
		Summary: "Enable or disable buffering of request bodies for inspection",
		Syntax:  `SecRequestBodyAccess On|Off`,
		Example: `SecRequestBodyAccess On`,
		Description: "**SecRequestBodyAccess** controls whether request bodies are buffered for inspection.\n" +
			"When enabled, the `REQUEST_BODY`, `ARGS_POST`, and file upload variables become available.\n\n" +
			"Enabling this has a memory cost proportional to request body size.",
	},
	{
		Name:    "SecResponseBodyAccess",
		Summary: "Enable or disable buffering of response bodies for inspection",
		Syntax:  `SecResponseBodyAccess On|Off`,
		Example: `SecResponseBodyAccess On`,
		Description: "**SecResponseBodyAccess** controls whether response bodies are buffered for inspection.\n" +
			"When enabled, the `RESPONSE_BODY` variable becomes available.\n\n" +
			"Only MIME types listed in `SecResponseBodyMimeType` are inspected.",
	},
	{
		Name:    "SecRequestBodyLimit",
		Summary: "Set the maximum request body size to buffer (bytes)",
		Syntax:  `SecRequestBodyLimit BYTES`,
		Example: `SecRequestBodyLimit 13107200`,
		Description: "**SecRequestBodyLimit** sets the maximum number of bytes buffered for request body inspection.\n" +
			"Default is 128 MB. When exceeded, behaviour is controlled by `SecRequestBodyLimitAction`.",
	},
	{
		Name:    "SecRequestBodyLimitAction",
		Summary: "Control behaviour when request body exceeds the size limit",
		Syntax:  `SecRequestBodyLimitAction Reject|ProcessPartial`,
		Example: `SecRequestBodyLimitAction Reject`,
		Description: "**SecRequestBodyLimitAction** determines what happens when a request body exceeds `SecRequestBodyLimit`:\n" +
			"- **Reject** — return an error response (default)\n" +
			"- **ProcessPartial** — inspect only the buffered portion and continue",
	},
	{
		Name:    "SecRequestBodyInMemoryLimit",
		Summary: "Set the threshold above which request body is spooled to disk",
		Syntax:  `SecRequestBodyInMemoryLimit BYTES`,
		Example: `SecRequestBodyInMemoryLimit 131072`,
		Description: "**SecRequestBodyInMemoryLimit** sets the threshold (bytes) below which request bodies\n" +
			"are held in memory. Bodies exceeding this are spooled to temporary disk files. Default is 128 KB.",
	},
	{
		Name:    "SecRequestBodyNoFilesLimit",
		Summary: "Limit size of request body excluding file uploads",
		Syntax:  `SecRequestBodyNoFilesLimit BYTES`,
		Example: `SecRequestBodyNoFilesLimit 131072`,
		Description: "**SecRequestBodyNoFilesLimit** sets the maximum size for the non-file portion of a\n" +
			"multipart request body. Protects against large parameter floods.",
	},
	{
		Name:    "SecRequestBodyJsonDepthLimit",
		Summary: "Limit recursion depth for JSON body parsing",
		Syntax:  `SecRequestBodyJsonDepthLimit DEPTH`,
		Example: `SecRequestBodyJsonDepthLimit 512`,
		Description: "**SecRequestBodyJsonDepthLimit** controls how deep the JSON parser recurses.\n" +
			"Prevents stack overflow from deeply nested JSON. Default is 512.",
	},
	{
		Name:    "SecArgumentsLimit",
		Summary: "Limit the total number of request arguments processed",
		Syntax:  `SecArgumentsLimit NUMBER`,
		Example: `SecArgumentsLimit 1000`,
		Description: "**SecArgumentsLimit** sets the maximum number of arguments (GET + POST combined) to\n" +
			"process. Arguments beyond this limit are discarded. Default is 1000.\n\n" +
			"Prevents resource exhaustion from requests with very many parameters.",
	},
	{
		Name:    "SecResponseBodyLimit",
		Summary: "Set the maximum response body size to buffer (bytes)",
		Syntax:  `SecResponseBodyLimit BYTES`,
		Example: `SecResponseBodyLimit 524288`,
		Description: "**SecResponseBodyLimit** sets the maximum number of bytes buffered for response body inspection.\n" +
			"Default is 512 KB.",
	},
	{
		Name:    "SecResponseBodyLimitAction",
		Summary: "Control behaviour when response body exceeds the size limit",
		Syntax:  `SecResponseBodyLimitAction Reject|ProcessPartial`,
		Example: `SecResponseBodyLimitAction ProcessPartial`,
		Description: "**SecResponseBodyLimitAction** determines what happens when a response body exceeds `SecResponseBodyLimit`:\n" +
			"- **Reject** — return an error response\n" +
			"- **ProcessPartial** — inspect only the buffered portion (default)",
	},
	{
		Name:    "SecResponseBodyMimeType",
		Summary: "List MIME types whose response bodies will be inspected",
		Syntax:  `SecResponseBodyMimeType MIMETYPE [MIMETYPE ...]`,
		Example: `SecResponseBodyMimeType text/plain text/html text/xml application/json`,
		Description: "**SecResponseBodyMimeType** specifies which response MIME types are eligible for\n" +
			"body buffering and inspection. Multiple types are space-separated.",
	},
	{
		Name:    "SecResponseBodyMimeTypesClear",
		Summary: "Clear the list of response body MIME types to inspect",
		Syntax:  `SecResponseBodyMimeTypesClear`,
		Example: `SecResponseBodyMimeTypesClear`,
		Description: "**SecResponseBodyMimeTypesClear** resets the list of inspectable response MIME types\n" +
			"to empty. Use before `SecResponseBodyMimeType` to replace the default list entirely.",
	},
	{
		Name:    "SecAuditEngine",
		Summary: "Control audit logging mode",
		Syntax:  `SecAuditEngine On|Off|RelevantOnly`,
		Example: `SecAuditEngine RelevantOnly`,
		Description: "**SecAuditEngine** controls transaction-level audit logging:\n" +
			"- **On** — log all transactions\n" +
			"- **Off** — disable audit logging\n" +
			"- **RelevantOnly** — log only transactions that trigger rules or match `SecAuditLogRelevantStatus`",
	},
	{
		Name:    "SecAuditLog",
		Summary: "Set the path for the audit log file",
		Syntax:  `SecAuditLog /path/to/audit.log`,
		Example: `SecAuditLog /var/log/coraza/audit.log`,
		Description: "**SecAuditLog** specifies the file path for the audit log.",
	},
	{
		Name:    "SecAuditLogType",
		Summary: "Set the audit log storage mechanism",
		Syntax:  `SecAuditLogType Serial|Concurrent|HTTPS|Syslog`,
		Example: `SecAuditLogType Serial`,
		Description: "**SecAuditLogType** controls how audit log entries are stored:\n" +
			"- **Serial** — all entries in a single file\n" +
			"- **Concurrent** — each transaction in a separate file in `SecAuditLogStorageDir`\n" +
			"- **HTTPS** — send entries to a remote HTTPS endpoint\n" +
			"- **Syslog** — send entries to syslog",
	},
	{
		Name:    "SecAuditLogFormat",
		Summary: "Set the audit log entry format",
		Syntax:  `SecAuditLogFormat JSON|JsonLegacy|Native|OCSF`,
		Example: `SecAuditLogFormat JSON`,
		Description: "**SecAuditLogFormat** controls the format of audit log entries:\n" +
			"- **JSON** — structured JSON (recommended)\n" +
			"- **JsonLegacy** — legacy JSON for backwards compatibility\n" +
			"- **Native** — Apache-style multi-part format\n" +
			"- **OCSF** — Open Cybersecurity Schema Framework",
	},
	{
		Name:    "SecAuditLogParts",
		Summary: "Specify which sections of a transaction to include in audit logs",
		Syntax:  `SecAuditLogParts ABCDEFGHIJKZ`,
		Example: `SecAuditLogParts ABCEFHJKZ`,
		Description: "**SecAuditLogParts** uses a letter code to select transaction sections logged:\n" +
			"- **A** — audit log header, **B** — request headers, **C** — request body\n" +
			"- **E** — intended response body, **F** — final response headers\n" +
			"- **H** — audit log trailer, **I** — compact request body\n" +
			"- **J** — file upload info, **K** — matched rules, **Z** — final boundary",
	},
	{
		Name:    "SecAuditLogStorageDir",
		Summary: "Set the directory for concurrent audit log files",
		Syntax:  `SecAuditLogStorageDir /path/to/dir`,
		Example: `SecAuditLogStorageDir /var/log/coraza/audit`,
		Description: "**SecAuditLogStorageDir** specifies the root directory for concurrent audit log\n" +
			"storage (used with `SecAuditLogType Concurrent`).",
	},
	{
		Name:    "SecAuditLogRelevantStatus",
		Summary: "Regex pattern for HTTP status codes to include in audit log",
		Syntax:  `SecAuditLogRelevantStatus REGEX`,
		Example: `SecAuditLogRelevantStatus "^(?:5|4(?!04))"`,
		Description: "**SecAuditLogRelevantStatus** specifies a regex matched against the response status code.\n" +
			"Matching transactions are logged when `SecAuditEngine RelevantOnly` is active.",
	},
	{
		Name:    "SecDebugLog",
		Summary: "Set the path for the debug log file",
		Syntax:  `SecDebugLog /path/to/debug.log`,
		Example: `SecDebugLog /var/log/coraza/debug.log`,
		Description: "**SecDebugLog** specifies the file path for diagnostic debug output.\n" +
			"Verbosity is controlled by `SecDebugLogLevel`.",
	},
	{
		Name:    "SecDebugLogLevel",
		Summary: "Set the debug log verbosity level (0-9)",
		Syntax:  `SecDebugLogLevel 0-9`,
		Example: `SecDebugLogLevel 3`,
		Description: "**SecDebugLogLevel** controls debug log verbosity:\n" +
			"- **0** — no debug logging\n" +
			"- **1** — errors only\n" +
			"- **2** — warnings\n" +
			"- **3** — notices (default)\n" +
			"- **4** — informational\n" +
			"- **5–9** — increasingly verbose debug output",
	},
	{
		Name:    "SecComponentSignature",
		Summary: "Add a component signature to the audit log",
		Syntax:  `SecComponentSignature "COMPONENT/X.Y.Z"`,
		Example: `SecComponentSignature "OWASP_CRS/4.0.0"`,
		Description: "**SecComponentSignature** appends a component identification string to the WAF\n" +
			"signature in the audit log header.",
	},
	{
		Name:    "SecRuleRemoveById",
		Summary: "Remove a rule or range of rules by ID",
		Syntax:  `SecRuleRemoveById ID|ID-ID [ID|ID-ID ...]`,
		Example: `SecRuleRemoveById 981000-981999`,
		Description: "**SecRuleRemoveById** permanently removes rules from the rule set by ID or ID range.\n" +
			"Ranges use hyphen notation: `1000-1999`.\n\n" +
			"Must be placed **after** the `Include` that loads the rules to be removed.",
	},
	{
		Name:    "SecRuleRemoveByMsg",
		Summary: "Remove rules whose msg action matches a regex",
		Syntax:  `SecRuleRemoveByMsg REGEX`,
		Example: `SecRuleRemoveByMsg "SQL Injection"`,
		Description: "**SecRuleRemoveByMsg** removes rules whose `msg` action value matches the given regex.",
	},
	{
		Name:    "SecRuleRemoveByTag",
		Summary: "Remove rules that have a specific tag",
		Syntax:  `SecRuleRemoveByTag TAG`,
		Example: `SecRuleRemoveByTag "attack-sqli"`,
		Description: "**SecRuleRemoveByTag** removes all rules that contain a matching `tag` action value.",
	},
	{
		Name:    "SecRuleUpdateActionById",
		Summary: "Update the action list of an existing rule by ID",
		Syntax:  `SecRuleUpdateActionById ID "ACTIONS"`,
		Example: `SecRuleUpdateActionById 981000 "pass,nolog"`,
		Description: "**SecRuleUpdateActionById** modifies the action list of an existing rule identified by\n" +
			"its numeric ID. Provided actions are merged into the rule's existing actions.",
	},
	{
		Name:    "SecRuleUpdateTargetById",
		Summary: "Add variables to an existing rule by ID",
		Syntax:  `SecRuleUpdateTargetById ID "VARIABLES"`,
		Example: `SecRuleUpdateTargetById 981000 "!ARGS:safe_param"`,
		Description: "**SecRuleUpdateTargetById** appends additional variables (or exclusions) to an existing\n" +
			"rule's variable list. Useful for excluding specific parameters from CRS rules.",
	},
	{
		Name:    "SecRuleUpdateTargetByMsg",
		Summary: "Add variables to rules matching a msg regex (no-op in Coraza)",
		Syntax:  `SecRuleUpdateTargetByMsg REGEX "VARIABLES"`,
		Example: `SecRuleUpdateTargetByMsg "SQL Injection" "!ARGS:id"`,
		Description: "**SecRuleUpdateTargetByMsg** is intended to append variables to all rules whose `msg`\n" +
			"matches the given regex.\n\n" +
			"**Note:** Coraza v3.5.0 maps this directive to `directiveUnsupported` " +
			"(internal/seclang/directivesmap.gen.go) — it is accepted at parse time but does nothing. " +
			"Unlike `SecRuleUpdateTargetById` and `SecRuleUpdateTargetByTag`, which are fully functional, " +
			"target exclusions written with this directive will silently have no effect.",
		Deprecated: true,
	},
	{
		Name:    "SecRuleUpdateTargetByTag",
		Summary: "Add variables to rules that have a specific tag",
		Syntax:  `SecRuleUpdateTargetByTag TAG "VARIABLES"`,
		Example: `SecRuleUpdateTargetByTag "attack-sqli" "!ARGS:id"`,
		Description: "**SecRuleUpdateTargetByTag** appends variables to all rules that contain the given tag.",
	},
	// Identity & Application
	{
		Name:    "SecWebAppID",
		Summary: "Assign a web application identifier for this configuration",
		Syntax:  `SecWebAppID "APP_NAME"`,
		Example: `SecWebAppID "myapp"`,
		Description: "**SecWebAppID** assigns a unique application identifier to the WAF instance.\n" +
			"The identifier appears in audit log entries and is used to key the `APPLICATION` persistent collection.\n\n" +
			"Useful when a single WAF instance protects multiple applications.",
	},
	{
		Name:    "SecServerSignature",
		Summary: "Override the Server response header value",
		Syntax:  `SecServerSignature "VALUE"`,
		Example: `SecServerSignature "Apache"`,
		Description: "**SecServerSignature** replaces the value of the `Server` response header when\n" +
			"`SecResponseBodyAccess On` is active.\n\n" +
			"Use to obscure the actual server software version from attackers.",
	},
	{
		Name:    "SecSensorID",
		Summary: "Assign a unique sensor identifier for this WAF instance",
		Syntax:  `SecSensorID "IDENTIFIER"`,
		Example: `SecSensorID "waf-node-01"`,
		Description: "**SecSensorID** sets an identifier for this WAF sensor node. The identifier is included\n" +
			"in audit log entries, making it easier to trace which WAF instance generated an alert in\n" +
			"multi-node deployments.",
	},
	// Connection Engine
	{
		Name:    "SecConnEngine",
		Summary: "Enable or disable connection-level tracking",
		Syntax:  `SecConnEngine On|Off|DetectionOnly`,
		Example: `SecConnEngine On`,
		Description: "**SecConnEngine** controls the connection-level rule processing engine:\n" +
			"- **On** — enable connection tracking and enforce connection rules\n" +
			"- **Off** — disable connection tracking\n" +
			"- **DetectionOnly** — track connections but do not enforce blocking rules",
	},
	{
		Name:    "SecConnReadStateLimit",
		Summary: "Limit concurrent connections per IP in read state",
		Syntax:  `SecConnReadStateLimit NUMBER [COLLECTION.VARIABLE]`,
		Example: `SecConnReadStateLimit 100`,
		Description: "**SecConnReadStateLimit** sets the maximum number of concurrent connections from a\n" +
			"single IP address that can be in the read state (receiving data). Exceeding the limit\n" +
			"triggers the configured action (typically block).\n\n" +
			"Requires `SecConnEngine On`.",
	},
	{
		Name:    "SecConnWriteStateLimit",
		Summary: "Limit concurrent connections per IP in write state",
		Syntax:  `SecConnWriteStateLimit NUMBER [COLLECTION.VARIABLE]`,
		Example: `SecConnWriteStateLimit 100`,
		Description: "**SecConnWriteStateLimit** sets the maximum number of concurrent connections from a\n" +
			"single IP address that can be in the write state (sending data). Exceeding the limit\n" +
			"triggers the configured action.\n\n" +
			"Requires `SecConnEngine On`.",
	},
	// Persistent Collections
	{
		Name:    "SecCollectionTimeout",
		Summary: "Set the default expiry time for persistent collection data",
		Syntax:  `SecCollectionTimeout SECONDS`,
		Example: `SecCollectionTimeout 3600`,
		Description: "**SecCollectionTimeout** specifies the default number of seconds after which\n" +
			"entries in persistent collections (`IP`, `SESSION`, `USER`) expire if not explicitly\n" +
			"set with `expirevar`. Default is 3600 (1 hour).",
	},
	// Datasets
	{
		Name:    "SecDataset",
		Summary: "Define a named in-memory dataset for use with dataset operators",
		Syntax:  `SecDataset NAME "VALUE1\nVALUE2\n..."`,
		Example: `SecDataset bad-agents "sqlmap\nnikto\nnmap"`,
		Description: "**SecDataset** creates a named dataset loaded into memory at startup.\n" +
			"Datasets can be referenced by the `@pmFromDataset` and `@ipMatchFromDataset` operators.\n\n" +
			"Values are newline-separated within the quoted string, or load from a file with:\n" +
			"`SecDataset name type:file /path/to/file.txt`",
	},
	// Remote Rules
	{
		Name:    "SecRemoteRules",
		Summary: "Load rules from a remote HTTPS endpoint",
		Syntax:  `SecRemoteRules KEY https://example.com/rules.conf`,
		Example: `SecRemoteRules mykey https://rules.example.com/crs.conf`,
		Description: "**SecRemoteRules** downloads and loads a rule file from a remote HTTPS URL.\n" +
			"The `KEY` parameter is used for authentication with the remote server.\n\n" +
			"Rules are fetched at startup and cached. Use `SecRemoteRulesFailAction` to control\n" +
			"behaviour when the fetch fails.",
	},
	{
		Name:    "SecRemoteRulesFailAction",
		Summary: "Control behaviour when SecRemoteRules fetch fails",
		Syntax:  `SecRemoteRulesFailAction Abort|Warn`,
		Example: `SecRemoteRulesFailAction Warn`,
		Description: "**SecRemoteRulesFailAction** determines what happens when `SecRemoteRules` cannot\n" +
			"download rules from the remote endpoint:\n" +
			"- **Abort** — fail to start the WAF (default, safe)\n" +
			"- **Warn** — log a warning and continue without the remote rules",
	},
	// Miscellaneous Configuration
	{
		Name:    "SecIgnoreRuleCompilationErrors",
		Summary: "Continue loading rules even if some fail to compile",
		Syntax:  `SecIgnoreRuleCompilationErrors On|Off`,
		Example: `SecIgnoreRuleCompilationErrors On`,
		Description: "**SecIgnoreRuleCompilationErrors** controls whether the WAF aborts startup when\n" +
			"a rule fails to compile (e.g. invalid regex or unknown operator):\n" +
			"- **On** — log the error and skip the rule, continue loading\n" +
			"- **Off** — abort startup on any rule compilation error (default, recommended for production)",
	},
	// PCRE Limits
	{
		Name:    "SecPcreMatchLimit",
		Summary: "Set the PCRE match limit to prevent catastrophic backtracking",
		Syntax:  `SecPcreMatchLimit NUMBER`,
		Example: `SecPcreMatchLimit 100000`,
		Description: "**SecPcreMatchLimit** sets the maximum number of internal PCRE matching steps.\n" +
			"Prevents ReDoS (Regular Expression Denial of Service) through catastrophic backtracking.\n" +
			"When exceeded, the match returns false and an error is logged.",
	},
	{
		Name:    "SecPcreMatchLimitRecursion",
		Summary: "Set the PCRE recursion limit to prevent stack overflow",
		Syntax:  `SecPcreMatchLimitRecursion NUMBER`,
		Example: `SecPcreMatchLimitRecursion 100000`,
		Description: "**SecPcreMatchLimitRecursion** limits the recursion depth for PCRE matching.\n" +
			"Prevents stack overflow from deeply recursive regex patterns.\n" +
			"When exceeded, the match returns false.",
	},
	// Hash / HMAC Engine
	{
		Name:    "SecHashEngine",
		Summary: "Enable or disable the HMAC hash injection engine",
		Syntax:  `SecHashEngine On|Off`,
		Example: `SecHashEngine On`,
		Description: "**SecHashEngine** enables the hash injection and validation engine, which adds\n" +
			"HMAC tokens to outgoing HTML to protect against CSRF and parameter tampering.",
	},
	{
		Name:    "SecHashKey",
		Summary: "Set the secret key used for HMAC hash generation",
		Syntax:  `SecHashKey "SECRET_KEY" [Rand|Fixed]`,
		Example: `SecHashKey "mysecret" Rand`,
		Description: "**SecHashKey** sets the secret key used for HMAC token generation.\n" +
			"- **Rand** — generate a random suffix per request (more secure)\n" +
			"- **Fixed** — use the key as-is",
	},
	{
		Name:    "SecHashParam",
		Summary: "Set the query parameter name used for the HMAC token",
		Syntax:  `SecHashParam PARAM_NAME`,
		Example: `SecHashParam __csrf_token`,
		Description: "**SecHashParam** sets the name of the query string parameter (or form field)\n" +
			"that carries the HMAC token injected by the hash engine.",
	},
	{
		Name:    "SecHashMethodPm",
		Summary: "Define URL patterns for HMAC injection using phrase matching",
		Syntax:  `SecHashMethodPm TYPE "PATTERN1 PATTERN2 ..."`,
		Example: `SecHashMethodPm HashHref "logout.php change-password.php"`,
		Description: "**SecHashMethodPm** configures which outgoing links or forms receive HMAC tokens,\n" +
			"matched by phrase (substring) patterns.\n\n" +
			"TYPE selects the injection point: `HashHref`, `HashFormAction`, `HashIframeSrc`, `HashLocation`.",
	},
	{
		Name:    "SecHashMethodRx",
		Summary: "Define URL patterns for HMAC injection using regex matching",
		Syntax:  `SecHashMethodRx TYPE "REGEX"`,
		Example: `SecHashMethodRx HashHref "^/sensitive/"`,
		Description: "**SecHashMethodRx** configures which outgoing links or forms receive HMAC tokens,\n" +
			"matched by regular expression.\n\n" +
			"TYPE selects the injection point: `HashHref`, `HashFormAction`, `HashIframeSrc`, `HashLocation`.",
	},
	// HTTP BL & GSB
	{
		Name:    "SecHTTPBlKey",
		Summary: "Set the Project Honey Pot HTTP BL API key",
		Syntax:  `SecHTTPBlKey "API_KEY"`,
		Example: `SecHTTPBlKey "abc123xyz"`,
		Description: "**SecHTTPBlKey** sets the API key for querying the Project Honey Pot\n" +
			"HTTP Blacklist (http:BL) DNS service. Required for using the `@rbl` operator\n" +
			"with the http:BL service.",
	},
	{
		Name:    "SecGsbLookupDb",
		Summary: "Set the path to the Google Safe Browsing database",
		Syntax:  `SecGsbLookupDb /path/to/gsb.db`,
		Example: `SecGsbLookupDb /var/lib/coraza/safebrowsing.db`,
		Description: "**SecGsbLookupDb** specifies the path to a local Google Safe Browsing database file.\n" +
			"Used by URL reputation operators to check URLs against known malware/phishing sites.",
	},
	// File & Data Directory
	{
		Name:    "SecDataDir",
		Summary: "Set the directory for persistent collection storage",
		Syntax:  `SecDataDir /path/to/dir`,
		Example: `SecDataDir /var/lib/coraza/data`,
		Description: "**SecDataDir** specifies the directory where Coraza stores persistent collection\n" +
			"data files (IP, SESSION, USER collections). The directory must be writable by the\n" +
			"web server process.",
	},
	{
		Name:    "SecUploadDir",
		Summary: "Set the directory for temporary uploaded file storage",
		Syntax:  `SecUploadDir /path/to/dir`,
		Example: `SecUploadDir /tmp/coraza-upload`,
		Description: "**SecUploadDir** specifies the directory where Coraza stores temporary copies\n" +
			"of uploaded files for inspection. Required for `@inspectFile` to work.\n\n" +
			"The directory must be writable by the web server process.",
	},
	{
		Name:    "SecUploadFileLimit",
		Summary: "Set the maximum number of uploaded files to process per request",
		Syntax:  `SecUploadFileLimit NUMBER`,
		Example: `SecUploadFileLimit 10`,
		Description: "**SecUploadFileLimit** sets the maximum number of uploaded files that will be\n" +
			"processed per multipart request. Additional files beyond this limit are ignored.\n" +
			"Default is 100.",
	},
	{
		Name:    "SecUploadFileMode",
		Summary: "Set the file permission mode for stored upload files",
		Syntax:  `SecUploadFileMode OCTAL`,
		Example: `SecUploadFileMode 0600`,
		Description: "**SecUploadFileMode** sets the Unix permission mode (in octal) for temporary\n" +
			"upload files stored in `SecUploadDir`. Default is 0600 (owner read/write only).",
	},
	{
		Name:    "SecUploadKeepFiles",
		Summary: "Control whether uploaded files are kept after processing",
		Syntax:  `SecUploadKeepFiles On|Off|RelevantOnly`,
		Example: `SecUploadKeepFiles RelevantOnly`,
		Description: "**SecUploadKeepFiles** determines whether temporary upload files are retained\n" +
			"after the transaction is complete:\n" +
			"- **On** — keep all uploaded files\n" +
			"- **Off** — delete all uploaded files after processing (default)\n" +
			"- **RelevantOnly** — keep files only when the transaction triggers a rule",
	},
	// Audit Log Directory/File Modes
	{
		Name:    "SecAuditLogDirMode",
		Summary: "Set the directory permission mode for concurrent audit log directories",
		Syntax:  `SecAuditLogDirMode OCTAL`,
		Example: `SecAuditLogDirMode 0750`,
		Description: "**SecAuditLogDirMode** sets the Unix permission mode for directories created\n" +
			"under `SecAuditLogStorageDir` when using `SecAuditLogType Concurrent`. Default is 0755.",
	},
	{
		Name:    "SecAuditLogFileMode",
		Summary: "Set the file permission mode for concurrent audit log entries",
		Syntax:  `SecAuditLogFileMode OCTAL`,
		Example: `SecAuditLogFileMode 0640`,
		Description: "**SecAuditLogFileMode** sets the Unix permission mode for individual audit log\n" +
			"files created under `SecAuditLogStorageDir`. Default is 0600.",
	},
	// Accepted-but-ignored directives.
	//
	// Coraza v3.5.0 registers the following directive names in
	// internal/seclang/directivesmap.gen.go but maps each to
	// `directiveUnsupported`, which `return nil`s without doing anything. They
	// are listed here (rather than omitted) so the LSP does NOT emit a spurious
	// "unknown directive" diagnostic for configs ported from ModSecurity — while
	// the descriptions and Deprecated flag make clear they have no effect in
	// Coraza. (Note: ModSecurity's SecRxPreFilter is NOT in Coraza v3.5.0's map
	// and is intentionally not listed.)
	{
		Name:    "SecArgumentSeparator",
		Summary: "Set the argument separator for application/x-www-form-urlencoded data (no-op in Coraza)",
		Syntax:  `SecArgumentSeparator CHAR`,
		Example: `SecArgumentSeparator &`,
		Description: "**SecArgumentSeparator** defines the character used to separate query-string and\n" +
			"form arguments (ModSecurity default `&`).\n\n" +
			"**Note:** Coraza v3.5.0 accepts this directive for compatibility but ignores it " +
			"(`directiveUnsupported`); the separator is not configurable.",
		Deprecated: true,
	},
	{
		Name:    "SecCookieFormat",
		Summary: "Select the cookie parsing format, 0 (Netscape) or 1 (RFC 2965) (no-op in Coraza)",
		Syntax:  `SecCookieFormat 0|1`,
		Example: `SecCookieFormat 0`,
		Description: "**SecCookieFormat** selects how request cookies are parsed in ModSecurity.\n\n" +
			"**Note:** Coraza v3.5.0 accepts this directive for compatibility but ignores it " +
			"(`directiveUnsupported`).",
		Deprecated: true,
	},
	{
		Name:    "SecUnicodeMap",
		Summary: "Configure the Unicode mapping file and code page (no-op in Coraza)",
		Syntax:  `SecUnicodeMap FILE [CODEPAGE]`,
		Example: `SecUnicodeMap unicode.mapping 20127`,
		Description: "**SecUnicodeMap** specifies the Unicode mapping file used by the `urlDecodeUni`\n" +
			"and `utf8toUnicode` transformations in ModSecurity.\n\n" +
			"**Note:** Coraza v3.5.0 accepts this directive for compatibility but ignores it " +
			"(`directiveUnsupported`).",
		Deprecated: true,
	},
	{
		Name:    "SecTmpDir",
		Summary: "Set the directory for temporary files (no-op in Coraza)",
		Syntax:  `SecTmpDir /path/to/dir`,
		Example: `SecTmpDir /tmp`,
		Description: "**SecTmpDir** sets the directory ModSecurity uses for temporary files when data\n" +
			"must be swapped to disk.\n\n" +
			"**Note:** Coraza v3.5.0 accepts this directive for compatibility but ignores it " +
			"(`directiveUnsupported`). Use `SecUploadDir` for uploaded-file storage.",
		Deprecated: true,
	},
	{
		Name:    "SecRuleScript",
		Summary: "Define a rule whose logic is implemented by an external script (no-op in Coraza)",
		Syntax:  `SecRuleScript /path/to/script.lua "ACTIONS"`,
		Example: `SecRuleScript "/etc/coraza/check.lua" "id:9000,phase:2,deny"`,
		Description: "**SecRuleScript** runs an external (e.g. Lua) script as a rule in ModSecurity.\n\n" +
			"**Note:** Coraza v3.5.0 accepts this directive for compatibility but ignores it " +
			"(`directiveUnsupported`); scripted rules are not executed.",
		Deprecated: true,
	},
	{
		Name:    "SecRulePerfTime",
		Summary: "Set a per-rule performance-time logging threshold in microseconds (no-op in Coraza)",
		Syntax:  `SecRulePerfTime MICROSECONDS`,
		Example: `SecRulePerfTime 1000`,
		Description: "**SecRulePerfTime** configures the threshold above which ModSecurity records\n" +
			"per-rule performance timing.\n\n" +
			"**Note:** Coraza v3.5.0 accepts this directive for compatibility but ignores it " +
			"(`directiveUnsupported`).",
		Deprecated: true,
	},
}

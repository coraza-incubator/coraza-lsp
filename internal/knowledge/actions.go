// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package knowledge

// allActions contains all known SecLang rule actions with full documentation.
var allActions = []Item{
	// Disruptive actions
	{
		Name:       "deny",
		ActionType: "disruptive",
		Summary:    "Block the request and return an error response",
		Syntax:     "deny",
		Example:    `SecRule ARGS "@detectSQLi" "id:1,phase:2,deny,status:403"`,
		Description: "**deny** stops rule processing and returns an HTTP error response to the client.\n" +
			"Use `status` to set the response code (default: 403).\n\n" +
			"Only one disruptive action is allowed per rule (or chain starter).",
	},
	{
		Name:       "block",
		ActionType: "disruptive",
		Summary:    "Execute the disruptive action defined in SecDefaultAction",
		Syntax:     "block",
		Example:    `SecRule ARGS "@detectXSS" "id:2,phase:2,block"`,
		Description: "**block** triggers the disruptive action configured in `SecDefaultAction`.\n" +
			"Allows centralized control — change `SecDefaultAction` to switch all `block` rules\n" +
			"between deny and pass without modifying each rule.",
	},
	{
		Name:       "allow",
		ActionType: "disruptive",
		Summary:    "Stop rule processing and allow the request to proceed",
		Syntax:     "allow",
		Example:    `SecRule REMOTE_ADDR "@ipMatch 10.0.0.0/8" "id:3,phase:1,allow"`,
		Description: "**allow** stops all rule processing for the current phase and allows the\n" +
			"request/response to proceed without further inspection.\n\n" +
			"In phase 1, also skips phases 2–5 for the request.",
	},
	{
		Name:       "pass",
		ActionType: "disruptive",
		Summary:    "Continue rule processing without blocking",
		Syntax:     "pass",
		Example:    `SecRule ARGS:debug "@streq 1" "id:4,phase:1,pass,log,msg:'Debug mode enabled'"`,
		Description: "**pass** is a non-blocking action that simply continues processing.\n" +
			"Use when you want to log or set variables but not block the request.",
	},
	{
		Name:       "drop",
		ActionType: "disruptive",
		Summary:    "Immediately close the TCP connection",
		Syntax:     "drop",
		Example:    `SecRule REMOTE_ADDR "@ipMatch 1.2.3.4" "id:5,phase:1,drop"`,
		Description: "**drop** immediately closes the TCP connection without sending any response.\n" +
			"More abrupt than `deny`; useful against scanners and crawlers.",
	},
	{
		Name:       "redirect",
		ActionType: "disruptive",
		Summary:    "Redirect the client to a different URL",
		Syntax:     "redirect:URL",
		Example:    `SecRule REQUEST_URI "@rx /old-path" "id:6,phase:1,redirect:https://example.com/new-path"`,
		Description: "**redirect** stops rule processing and issues an HTTP redirect (default 302)\n" +
			"to the specified URL. Use `status:301` for permanent redirects.",
	},
	// Note: ModSecurity 2.x `proxy` and `pause` actions are intentionally NOT
	// listed here. Coraza v3.7.0 does not register them and rejects them at
	// parse time with `invalid action "proxy"` / `invalid action "pause"`
	// (internal/actions/actions.go Get + appendRuleAction return the error).
	// Listing them would suppress a correct unknown-action diagnostic.
	// Metadata actions
	{
		Name:       "id",
		ActionType: "metadata",
		Summary:    "Unique numeric identifier for this rule (required)",
		Syntax:     "id:NUMBER",
		Example:    "id:1001",
		Description: "**id** assigns a unique numeric identifier to the rule. Required for all `SecRule`\n" +
			"and `SecAction` directives.\n\n" +
			"By convention:\n" +
			"- 1–99,999 — reserved for local rules\n" +
			"- 100,000–199,999 — user rules\n" +
			"- 900,000–999,999 — OWASP CRS exclusion rules",
	},
	{
		Name:       "phase",
		ActionType: "metadata",
		Summary:    "Execution phase for this rule (1–5)",
		Syntax:     "phase:NUMBER",
		Example:    "phase:2",
		Description: "**phase** specifies when the rule is evaluated:\n" +
			"- **1** — Request headers (before body is read)\n" +
			"- **2** — Request body (after complete request is received)\n" +
			"- **3** — Response headers\n" +
			"- **4** — Response body\n" +
			"- **5** — Logging (after response is sent)",
	},
	{
		Name:       "msg",
		ActionType: "metadata",
		Summary:    "Human-readable message describing why the rule matched",
		Syntax:     "msg:'TEXT'",
		Example:    "msg:'SQL Injection Attempt'",
		Description: "**msg** sets a descriptive message that appears in logs when the rule fires.\n" +
			"Supports macro expansion: `msg:'Attack from %{REMOTE_ADDR}'`.",
	},
	{
		Name:       "tag",
		ActionType: "metadata",
		Summary:    "Categorization tag for the rule",
		Syntax:     "tag:'CATEGORY'",
		Example:    "tag:'attack-sqli'",
		Description: "**tag** assigns a category label to the rule. Multiple `tag` actions are allowed\n" +
			"on a single rule. OWASP CRS uses CAPEC, OWASP, and technique tags.",
	},
	{
		Name:       "severity",
		ActionType: "metadata",
		Summary:    "Rule severity level",
		Syntax:     "severity:LEVEL",
		Example:    "severity:CRITICAL",
		Description: "**severity** classifies the rule's severity. Accepted values (name or number):\n" +
			"- **EMERGENCY** (0), **ALERT** (1), **CRITICAL** (2), **ERROR** (3)\n" +
			"- **WARNING** (4), **NOTICE** (5), **INFO** (6), **DEBUG** (7)",
	},
	{
		Name:        "rev",
		ActionType:  "metadata",
		Summary:     "Rule revision number",
		Syntax:      "rev:NUMBER",
		Example:     "rev:2",
		Description: "**rev** indicates the revision number of the rule. Increment when updating a rule.",
	},
	{
		Name:        "ver",
		ActionType:  "metadata",
		Summary:     "Rule set version string",
		Syntax:      "ver:'VERSION'",
		Example:     "ver:'OWASP_CRS/4.0.0'",
		Description: "**ver** identifies the version of the rule set that contains this rule.",
	},
	{
		Name:        "maturity",
		ActionType:  "metadata",
		Summary:     "Rule maturity level (1–9)",
		Syntax:      "maturity:NUMBER",
		Example:     "maturity:9",
		Description: "**maturity** rates how well-tested the rule is: 1 (experimental) to 9 (production-ready).",
	},
	// Note: ModSecurity's `accuracy` metadata action is intentionally NOT listed
	// here. Coraza v3.7.0 does not register it (it appears only inside a comment
	// in internal/actions/maturity.go) and rejects it at parse time with
	// `invalid action "accuracy"`. Modern OWASP CRS v4 no longer emits `accuracy`,
	// so dropping it does not introduce false positives on CRS.
	// `maturity`, `rev`, and `ver` ARE registered by Coraza and are kept above.
	// Non-disruptive actions
	{
		Name:       "log",
		ActionType: "non-disruptive",
		Summary:    "Log the rule match to the error log",
		Syntax:     "log",
		Example:    `SecRule ARGS "@rx union" "id:20,phase:2,pass,log,msg:'SQL keyword detected'"`,
		Description: "**log** causes the rule match to be recorded in the error log.\n" +
			"Overrides `nolog` from `SecDefaultAction`.",
	},
	{
		Name:       "nolog",
		ActionType: "non-disruptive",
		Summary:    "Suppress logging for this rule match",
		Syntax:     "nolog",
		Example:    `SecAction "id:21,phase:1,pass,nolog"`,
		Description: "**nolog** prevents the rule match from being written to the error log.\n" +
			"Also disables audit logging. Use `noauditlog` alone to suppress only the audit log.",
	},
	{
		Name:       "auditlog",
		ActionType: "non-disruptive",
		Summary:    "Include this transaction in the audit log",
		Syntax:     "auditlog",
		Example:    `SecRule ARGS "@detectSQLi" "id:22,phase:2,deny,auditlog"`,
		Description: "**auditlog** marks this transaction for inclusion in the audit log,\n" +
			"overriding `noauditlog` from `SecDefaultAction`.",
	},
	{
		Name:       "noauditlog",
		ActionType: "non-disruptive",
		Summary:    "Exclude this transaction from the audit log",
		Syntax:     "noauditlog",
		Example:    `SecRule ARGS:debug "@streq 1" "id:23,phase:2,pass,nolog,noauditlog"`,
		Description: "**noauditlog** prevents this transaction from being included in the audit log.\n" +
			"The error log entry (if `log` is set) is not affected.",
	},
	{
		Name:       "capture",
		ActionType: "non-disruptive",
		Summary:    "Capture regex groups into TX:0 through TX:9",
		Syntax:     "capture",
		Example:    `SecRule ARGS "@rx (union).*?(select)" "id:24,phase:2,deny,capture,logdata:'%{TX.1} %{TX.2}'"`,
		Description: "**capture** saves regex capture groups from `@rx` matches into `TX:0` through `TX:9`.\n" +
			"`TX:0` contains the full match; `TX:1`–`TX:9` contain capture groups.",
	},
	{
		Name:       "setvar",
		ActionType: "non-disruptive",
		Summary:    "Create, update, or delete a collection variable",
		Syntax:     "setvar:COLLECTION.VARIABLE[=VALUE]",
		Example:    "setvar:TX.anomaly_score=+5",
		Description: "**setvar** creates or modifies a variable in a collection:\n" +
			"- `setvar:TX.foo=bar` — set to value\n" +
			"- `setvar:TX.score=+5` — increment by 5\n" +
			"- `setvar:TX.score=-1` — decrement by 1\n" +
			"- `setvar:!TX.foo` — delete the variable\n\n" +
			"Supports macro expansion: `setvar:TX.msg=%{MATCHED_VAR}`.",
	},
	{
		Name:       "logdata",
		ActionType: "non-disruptive",
		Summary:    "Log additional data with the alert message",
		Syntax:     "logdata:'TEXT'",
		Example:    "logdata:'Matched data: %{MATCHED_VAR} in %{MATCHED_VAR_NAME}'",
		Description: "**logdata** appends additional data to the log entry for this rule match.\n" +
			"Supports macro expansion. Typically used to record the matched value.",
	},
	{
		Name:        "setenv",
		ActionType:  "non-disruptive",
		Summary:     "Create or update a server environment variable",
		Syntax:      "setenv:NAME=VALUE",
		Example:     "setenv:SUSPICIOUS=1",
		Description: "**setenv** sets a server-side environment variable available to the web application.",
	},
	{
		Name:       "expirevar",
		ActionType: "non-disruptive",
		Summary:    "Set an expiry time on a persistent collection variable",
		Syntax:     "expirevar:COLLECTION.VARIABLE=SECONDS",
		Example:    "expirevar:IP.block=3600",
		Description: "**expirevar** schedules the deletion of a persistent collection variable after\n" +
			"the specified number of seconds.",
	},
	{
		Name:       "initcol",
		ActionType: "non-disruptive",
		Summary:    "Initialize a persistent collection",
		Syntax:     "initcol:COLLECTION=KEY",
		Example:    "initcol:IP=%{REMOTE_ADDR}",
		Description: "**initcol** creates or loads a persistent collection identified by the given key.\n" +
			"Must be called before accessing the collection's variables.",
	},
	{
		Name:       "multiMatch",
		Aliases:    []string{"multimatch"},
		ActionType: "non-disruptive",
		Summary:    "Apply each transformation step and match after each one",
		Syntax:     "multiMatch",
		Example:    `SecRule ARGS "@rx <script" "id:40,phase:2,deny,t:none,t:htmlEntityDecode,t:jsDecode,multiMatch"`,
		Description: "**multiMatch** causes the operator to be invoked after each transformation in the\n" +
			"pipeline, not just after all transformations. This catches evasion through encoding.",
	},
	// Flow actions
	{
		Name:       "chain",
		ActionType: "flow",
		Summary:    "Chain this rule with the following rule (both must match)",
		Syntax:     "chain",
		Example:    "SecRule REQUEST_HEADERS:Host \"@rx evil\" \"id:50,phase:1,chain,deny\"\nSecRule REMOTE_ADDR \"!@ipMatch 127.0.0.1\"",
		Description: "**chain** links this rule with the immediately following `SecRule`. All rules in\n" +
			"the chain must match for the starter rule's disruptive action to fire.\n\n" +
			"The `chain` action goes on the chain starter rule, which also carries the disruptive action.",
	},
	{
		Name:       "skip",
		ActionType: "flow",
		Summary:    "Skip the next N rules on match",
		Syntax:     "skip:NUMBER",
		Example:    `SecRule TX:is_admin "@eq 1" "id:51,phase:1,pass,skip:3"`,
		Description: "**skip** skips the specified number of subsequent rules when this rule matches.\n" +
			"Useful for implementing conditional rule groups.",
	},
	{
		Name:       "skipAfter",
		Aliases:    []string{"skipafter"},
		ActionType: "flow",
		Summary:    "Jump to the first rule after a named SecMarker on match",
		Syntax:     "skipAfter:MARKER_NAME",
		Example:    `SecRule TX:whitelisted "@eq 1" "id:52,phase:2,pass,skipAfter:END_SQL_CHECKS"`,
		Description: "**skipAfter** jumps execution to the first rule after the named `SecMarker` when\n" +
			"this rule matches. The marker must appear later in the same configuration.",
	},
	// Data actions (status is the only Coraza ActionTypeData action;
	// `t` and `ctl` below are ActionTypeNondisruptive in Coraza v3.7.0)
	{
		Name:       "status",
		ActionType: "data",
		Summary:    "Set the HTTP response status code",
		Syntax:     "status:NUMBER",
		Example:    "status:403",
		Description: "**status** sets the HTTP response status code returned when a disruptive action fires.\n" +
			"Common values: 403 (Forbidden), 400 (Bad Request), 429 (Too Many Requests).",
	},
	{
		Name:       "t",
		ActionType: "non-disruptive",
		Summary:    "Apply a transformation function before matching",
		Syntax:     "t:TRANSFORMATION",
		Example:    "t:lowercase,t:urlDecode",
		Description: "**t** applies a named transformation to the variable value before matching.\n" +
			"Multiple `t` actions are applied in order: `t:none,t:lowercase,t:urlDecode`.\n\n" +
			"Use `t:none` first to clear inherited transformations from `SecDefaultAction`.",
	},
	{
		Name:       "ctl",
		ActionType: "non-disruptive",
		Summary:    "Change a WAF configuration option for this transaction",
		Syntax:     "ctl:OPTION=VALUE",
		Example:    "ctl:requestBodyProcessor=JSON",
		Description: "**ctl** modifies a WAF configuration option for the current transaction only.\n" +
			"Common uses:\n" +
			"- `ctl:ruleEngine=Off` — disable the engine for this request\n" +
			"- `ctl:requestBodyProcessor=JSON` — force JSON parsing\n" +
			"- `ctl:ruleRemoveById=981000-981999` — disable rules for this request",
	},
	{
		Name:       "exec",
		ActionType: "non-disruptive",
		Summary:    "Execute an external script when the rule matches",
		Syntax:     "exec:/path/to/script",
		Example:    `SecRule ARGS "@detectSQLi" "id:200,phase:2,deny,exec:/usr/local/bin/alert.sh"`,
		Description: "**exec** runs an external script or program when the rule matches.\n" +
			"The script receives the transaction data via environment variables.\n\n" +
			"This is a non-disruptive action — it does not block the request by itself. " +
			"Combine with `deny` or another disruptive action to block as well.\n\n" +
			"The script must be executable and return within the configured timeout.",
	},
}

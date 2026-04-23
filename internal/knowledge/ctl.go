// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package knowledge

import "strings"

// CtlOption describes a single ctl action sub-option.
type CtlOption struct {
	Key     string
	Summary string
	Values  []string // valid enum values; nil = free-form input accepted
	NoValue bool     // true for options that take no = and no value (e.g. noAuditLog)
}

// CtlOptions lists all recognised ctl sub-options in canonical casing.
var CtlOptions = []CtlOption{
	{
		Key:     "ruleEngine",
		Summary: "Override the WAF engine mode for this transaction",
		Values:  []string{"On", "Off", "DetectionOnly"},
	},
	{
		Key:     "ruleRemoveById",
		Summary: "Remove a rule (or ID range) for this transaction, e.g. 1001 or 1000-1999",
	},
	{
		Key:     "ruleRemoveByTag",
		Summary: "Remove all rules with the given tag for this transaction",
	},
	{
		Key:     "ruleRemoveTargetById",
		Summary: "Remove a specific inspection target from a rule by ID (format: id/VARIABLE[/key])",
	},
	{
		Key:     "ruleRemoveTargetByTag",
		Summary: "Remove a specific inspection target from all rules with a tag (format: tag/VARIABLE[/key])",
	},
	{
		Key:     "requestBodyAccess",
		Summary: "Enable or disable request body inspection for this transaction",
		Values:  []string{"On", "Off"},
	},
	{
		Key:     "requestBodyLimit",
		Summary: "Maximum request body size in bytes for this transaction",
	},
	{
		Key:     "requestBodyProcessor",
		Summary: "Force a specific request body parser for this transaction",
		Values:  []string{"URLENCODED", "MULTIPART", "XML", "JSON"},
	},
	{
		Key:     "forceRequestBodyVariable",
		Summary: "Force population of REQUEST_BODY even without a recognised Content-Type",
		Values:  []string{"On", "Off"},
	},
	{
		Key:     "responseBodyAccess",
		Summary: "Enable or disable response body inspection for this transaction",
		Values:  []string{"On", "Off"},
	},
	{
		Key:     "responseBodyLimit",
		Summary: "Maximum response body size in bytes for this transaction",
	},
	{
		Key:     "auditEngine",
		Summary: "Override the audit engine setting for this transaction",
		Values:  []string{"On", "Off", "RelevantOnly"},
	},
	{
		Key:     "noAuditLog",
		Summary: "Suppress the audit log entry for this transaction (no value required)",
		NoValue: true,
	},
	{
		Key:     "debugLogLevel",
		Summary: "Per-transaction debug log verbosity (0 = off … 9 = highest)",
	},
}

// CtlOptionsByKey maps lowercase key → *CtlOption for O(1) lookup.
var CtlOptionsByKey = func() map[string]*CtlOption {
	m := make(map[string]*CtlOption, len(CtlOptions))
	for i := range CtlOptions {
		m[strings.ToLower(CtlOptions[i].Key)] = &CtlOptions[i]
	}
	return m
}()

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
	NoValue bool     // true for options that take no = and no value
}

// CtlOptions lists all recognised ctl sub-options in canonical casing.
//
// This set is the authoritative one accepted by Coraza v3.7.0's ctl action,
// taken from the string switch in internal/actions/ctl.go (Init: the `switch
// action` block, ~lines 433-475). Any name outside this set makes Coraza fail
// with `unknown ctl action %q`, so adding speculative options here would
// suppress a correct unknown-ctl-option diagnostic. Note: ModSecurity's
// `ctl:noAuditLog` is intentionally absent — Coraza does NOT register it.
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
		Key:     "ruleRemoveByMsg",
		Summary: "Remove all rules whose msg matches the given value for this transaction",
	},
	{
		Key:     "ruleRemoveByTag",
		Summary: "Remove all rules with the given tag for this transaction",
	},
	{
		Key:     "ruleRemoveTargetById",
		Summary: "Remove a specific inspection target from a rule by ID (format: id;VARIABLE)",
	},
	{
		Key:     "ruleRemoveTargetByMsg",
		Summary: "Remove a specific inspection target from rules matching a msg (format: msg;VARIABLE)",
	},
	{
		Key:     "ruleRemoveTargetByTag",
		Summary: "Remove a specific inspection target from all rules with a tag (format: tag;VARIABLE)",
	},
	{
		Key:     "auditEngine",
		Summary: "Override the audit engine setting for this transaction",
		Values:  []string{"On", "Off", "RelevantOnly"},
	},
	{
		Key:     "auditLogParts",
		Summary: "Override which audit log parts are recorded for this transaction (e.g. +E)",
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
		Key:     "responseBodyProcessor",
		Summary: "Force a specific response body parser for this transaction",
		Values:  []string{"URLENCODED", "MULTIPART", "XML", "JSON"},
	},
	{
		Key:     "forceResponseBodyVariable",
		Summary: "Force population of RESPONSE_BODY even without a recognised Content-Type",
		Values:  []string{"On", "Off"},
	},
	{
		Key:     "hashEngine",
		Summary: "Enable or disable the hash engine for this transaction",
		Values:  []string{"On", "Off"},
	},
	{
		Key:     "hashEnforcement",
		Summary: "Enable or disable hash enforcement for this transaction",
		Values:  []string{"On", "Off"},
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

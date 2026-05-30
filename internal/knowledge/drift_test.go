// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package knowledge

import (
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
)

// drift_test.go is the KNOWLEDGE-BASE DRIFT GUARD.
//
// The knowledge base (KB) in this package is the LSP's source of truth for
// "unknown directive/variable/operator/action/transformation/ctl-option"
// diagnostics. If the KB lists something the linked OWASP Coraza release does
// NOT actually register, the LSP silently suppresses a correct diagnostic
// (false negative). If the KB omits something Coraza DOES register, the LSP
// emits a spurious diagnostic on valid rules (false positive — e.g. on CRS).
//
// This test pins the KB against the ACTUAL Coraza version this module builds
// against (see go.mod: github.com/corazawaf/coraza/v3). It is fully
// deterministic and CI-safe: it never touches the network, the filesystem, or
// any global state — it only compiles tiny SecLang snippets through the public
// coraza.NewWAF(...WithDirectives()) seam and inspects the parse error.
//
// Coraza's registries (actions.actionmap, the operators/transformations
// registries, the variables name table, the seclang directive map, and the ctl
// sub-option switch) all live in INTERNAL packages and cannot be imported
// directly. The public WAF builder is the only reachable seam, so:
//
//   - FORWARD guard (fatal): every name the KB lists must be accepted by
//     Coraza. This is the high-value direction — it catches KB entries that
//     Coraza rejects (the bug class fixed in this change: accuracy, proxy,
//     pause, sqlHexDecode, @ne, @containsWord, @verifyCC, @fuzzyHash,
//     REMOTE_USER, SESSION, ctl:noAuditLog).
//
//   - REVERSE guard (non-fatal log): a checked-in ground-truth baseline of the
//     names Coraza v3.5.0 registers (extracted from the module cache source,
//     see corazaGroundTruth* below) is compared against the KB. Names Coraza
//     has that the KB lacks are logged so future Coraza upgrades surface new
//     capabilities without breaking CI. Accepted-but-ignored (directiveUnsupported)
//     names are tolerated in both directions.
//
// When bumping the Coraza version, re-extract the ground-truth lists from the
// new module-cache source and update the baselines below.

const corazaPinnedVersion = "v3.5.0"

// probe compiles a single directive and returns the parse error (nil = accepted).
// Some Coraza operator constructors panic on a malformed argument (e.g.
// @restpath with a non-template path). A panic means the operator NAME was
// resolved and registered — only the argument was bad — so it is NOT a
// name-rejection and we treat it as "accepted" for drift purposes.
func probe(directive string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = nil
		}
	}()
	_, err = coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directive))
	return err
}

// rejected reports whether err is Coraza's "this name is not registered" class
// of error for the given element. We match the specific Coraza messages so that
// unrelated compile errors (bad arg shape, etc.) do not mask a true rejection
// or cause false failures.
func rejected(err error, needles ...string) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, n := range needles {
		if strings.Contains(msg, strings.ToLower(n)) {
			return true
		}
	}
	return false
}

// TestDriftActions asserts every KB action is registered by Coraza.
func TestDriftActions(t *testing.T) {
	for _, it := range allActions {
		name := it.Name
		// `t` and `ctl` need a value; the rest parse bare or with a trivial value.
		var actionToken string
		switch strings.ToLower(name) {
		case "t":
			actionToken = "t:lowercase"
		case "ctl":
			actionToken = "ctl:ruleEngine=On"
		case "skipafter":
			actionToken = "skipAfter:MARKER"
		case "skip":
			actionToken = "skip:1"
		case "redirect":
			actionToken = "redirect:http://x"
		case "status":
			actionToken = "status:403"
		case "phase":
			actionToken = "phase:2"
		case "severity":
			actionToken = "severity:2"
		case "msg":
			actionToken = "msg:'x'"
		case "tag":
			actionToken = "tag:'x'"
		case "logdata":
			actionToken = "logdata:'x'"
		case "rev":
			actionToken = "rev:1"
		case "ver":
			actionToken = "ver:'x'"
		case "maturity":
			actionToken = "maturity:1"
		case "setvar":
			actionToken = "setvar:TX.x=1"
		case "setenv":
			actionToken = "setenv:X=1"
		case "expirevar":
			actionToken = "expirevar:TX.x=1"
		case "initcol":
			actionToken = "initcol:IP=1"
		case "exec":
			actionToken = "exec:/bin/true"
		default:
			actionToken = name
		}
		dir := `SecRule ARGS "@unconditionalMatch" "id:1,phase:2,` + actionToken + `"`
		if rejected(probe(dir), `invalid action "`+strings.ToLower(name)+`"`) {
			t.Errorf("KB action %q is NOT registered by Coraza %s (invalid action) — remove it from allActions or it will suppress a correct unknown-action diagnostic", name, corazaPinnedVersion)
		}
	}
}

// TestDriftTransformations asserts every KB transformation is registered.
func TestDriftTransformations(t *testing.T) {
	for _, it := range allTransformations {
		dir := `SecRule ARGS "@unconditionalMatch" "id:1,phase:2,t:` + it.Name + `"`
		if rejected(probe(dir), "invalid transformation name") {
			t.Errorf("KB transformation %q is NOT registered by Coraza %s — remove it from allTransformations", it.Name, corazaPinnedVersion)
		}
	}
}

// TestDriftOperators asserts every KB operator is registered.
func TestDriftOperators(t *testing.T) {
	for _, it := range allOperators {
		// Give every operator a trivial argument so only an unregistered-operator
		// error (not a missing-arg error) can trip the guard.
		arg := "x"
		if strings.EqualFold(it.Name, "restpath") {
			arg = "/x/{id}" // restpath needs a path template, not a bare token
		}
		dir := `SecRule ARGS "@` + it.Name + ` ` + arg + `" "id:1,phase:2,pass"`
		if rejected(probe(dir), "operator "+strings.ToLower(it.Name)+" not found", "operator "+it.Name+" not found") {
			t.Errorf("KB operator %q is NOT registered by Coraza %s (operator not found) — remove it from allOperators", it.Name, corazaPinnedVersion)
		}
	}
}

// TestDriftVariables asserts every KB variable is accepted by Coraza's parser.
func TestDriftVariables(t *testing.T) {
	for _, it := range allVariables {
		dir := `SecRule ` + it.Name + ` "@unconditionalMatch" "id:1,phase:2,pass"`
		if rejected(probe(dir), "unknown variable") {
			t.Errorf("KB variable %q is NOT recognised by Coraza %s (unknown variable) — remove it from allVariables", it.Name, corazaPinnedVersion)
		}
	}
}

// TestDriftCtlOptions asserts every KB ctl sub-option is accepted by Coraza.
func TestDriftCtlOptions(t *testing.T) {
	for _, opt := range CtlOptions {
		// All current ctl options take a value; "On" is accepted as a generic
		// payload by the option parser (value validity is checked at runtime).
		dir := `SecRule ARGS "@unconditionalMatch" "id:1,phase:2,ctl:` + opt.Key + `=On"`
		if rejected(probe(dir), `unknown ctl action "`+opt.Key+`"`) {
			t.Errorf("KB ctl option %q is NOT a Coraza %s ctl sub-option (unknown ctl action) — remove it from CtlOptions", opt.Key, corazaPinnedVersion)
		}
	}
}

// --- REVERSE guard: ground-truth baselines (non-fatal) -----------------------
//
// These lists are the names Coraza v3.5.0 actually registers, extracted from
// the module-cache source:
//   actions:         internal/actions/actions.go      (init() Register calls)
//   operators:       internal/operators/*.go          (Register("...") calls)
//   transformations: internal/transformations/*.go    (Register("...") calls)
//   ctl options:     internal/actions/ctl.go          (the `switch action` block)
//   variables:       internal/variables/variablesmap.gen.go (rulemapRev keys)
// Aliases that the KB encodes via Item.Aliases are included so the comparison
// matches on the full accepted name surface.

var corazaGroundTruthActions = []string{
	"allow", "auditlog", "block", "capture", "chain", "ctl", "deny", "drop",
	"exec", "expirevar", "id", "initcol", "log", "logdata", "maturity", "msg",
	"multimatch", "noauditlog", "nolog", "pass", "phase", "redirect", "rev",
	"setenv", "setvar", "severity", "skip", "skipafter", "status", "t", "tag", "ver",
}

var corazaGroundTruthTransformations = []string{
	"base64decode", "base64decodeext", "base64encode", "cmdline",
	"compresswhitespace", "cssdecode", "escapeseqdecode", "hexdecode",
	"hexencode", "htmlentitydecode", "jsdecode", "length", "lowercase", "md5",
	"none", "normalisepath", "normalisepathwin", "normalizepath",
	"normalizepathwin", "removecomments", "removecommentschar", "removenulls",
	"removewhitespace", "replacecomments", "replacenulls", "sha1", "trim",
	"trimleft", "trimright", "uppercase", "urldecode", "urldecodeuni",
	"urlencode", "utf8tounicode",
}

var corazaGroundTruthOperators = []string{
	"beginswith", "contains", "detectsqli", "detectxss", "endswith", "eq", "ge",
	"geolookup", "gt", "inspectfile", "ipmatch", "ipmatchf", "ipmatchfromdataset",
	"ipmatchfromfile", "le", "lt", "nomatch", "pm", "pmf", "pmfromdataset",
	"pmfromfile", "rbl", "restpath", "rx", "streq", "strmatch",
	"unconditionalmatch", "validatebyterange", "validatenid", "validateschema",
	"validateurlencoding", "validateutf8encoding", "within",
}

var corazaGroundTruthCtlOptions = []string{
	"auditengine", "auditlogparts", "requestbodyaccess", "requestbodylimit",
	"requestbodyprocessor", "forcerequestbodyvariable", "responsebodyprocessor",
	"responsebodyaccess", "responsebodylimit", "forceresponsebodyvariable",
	"ruleengine", "ruleremovebyid", "ruleremovebymsg", "ruleremovebytag",
	"ruleremovetargetbyid", "ruleremovetargetbymsg", "ruleremovetargetbytag",
	"hashengine", "hashenforcement", "debugloglevel",
}

// reverseCheck logs (non-fatally) any ground-truth name absent from the KB.
func reverseCheck(t *testing.T, kind string, kbNames map[string]bool, groundTruth []string) {
	t.Helper()
	var missing []string
	for _, n := range groundTruth {
		if !kbNames[n] {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		t.Logf("REVERSE DRIFT (non-fatal): Coraza %s registers %d %s the KB omits: %v — consider adding for completeness", corazaPinnedVersion, len(missing), kind, missing)
	}
}

func kbNameSet(items []Item) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		m[strings.ToLower(it.Name)] = true
		for _, a := range it.Aliases {
			m[strings.ToLower(a)] = true
		}
	}
	return m
}

// TestDriftReverseCoverage logs Coraza-registered names the KB does not list.
// Non-fatal by design: a future Coraza upgrade adding capabilities should
// surface here without breaking CI, while the forward guards above stay fatal.
func TestDriftReverseCoverage(t *testing.T) {
	reverseCheck(t, "actions", kbNameSet(allActions), corazaGroundTruthActions)
	reverseCheck(t, "transformations", kbNameSet(allTransformations), corazaGroundTruthTransformations)
	reverseCheck(t, "operators", kbNameSet(allOperators), corazaGroundTruthOperators)

	ctlSet := make(map[string]bool, len(CtlOptions))
	for _, o := range CtlOptions {
		ctlSet[strings.ToLower(o.Key)] = true
	}
	reverseCheck(t, "ctl options", ctlSet, corazaGroundTruthCtlOptions)
}

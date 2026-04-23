// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

// Package analysis provides SecLang source validation through two stages:
//
//  1. Fast AST-level checks (synchronous) — detects structural errors like
//     missing id/phase, duplicate ids, invalid phase values.
//  2. Coraza validation oracle (asynchronous, debounced) — uses the Coraza WAF
//     public API to validate the full rule set and catch semantic errors.
//
// Performance note: Stage 1 runs inline on every document change.
// Stage 2 is debounced (300 ms) to avoid creating a new Coraza WAF on every keystroke.
package analysis

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	protocol_3_16 "github.com/tliron/glsp/protocol_3_16"

	"github.com/coraza-incubator/coraza-lsp/internal/knowledge"
	"github.com/coraza-incubator/coraza-lsp/internal/parser"
)

// DiagnosticCode identifies the kind of diagnostic for use by code actions.
type DiagnosticCode = string

const (
	CodeMissingID         DiagnosticCode = "missing-id"
	CodeMissingPhase      DiagnosticCode = "missing-phase"
	CodeInvalidPhase      DiagnosticCode = "invalid-phase"
	CodeInvalidID         DiagnosticCode = "invalid-id"
	CodeDuplicateID       DiagnosticCode = "duplicate-id"
	CodeUnknownDirective  DiagnosticCode = "unknown-directive"
	CodeUnknownVariable   DiagnosticCode = "unknown-variable"
	CodeUnknownCtlOption  DiagnosticCode = "unknown-ctl-option"
	CodeInvalidCtlValue   DiagnosticCode = "invalid-ctl-value"
	CodeSkipAfterNotFound    DiagnosticCode = "skipafter-not-found"
	CodeInvalidMacro         DiagnosticCode = "invalid-macro"
	CodeUnknownAction        DiagnosticCode = "unknown-action"
	CodeUnknownTransformation  DiagnosticCode = "unknown-transformation"
	CodeMissingTransformation  DiagnosticCode = "missing-transformation"
	CodeInvalidSeverity      DiagnosticCode = "invalid-severity"
	CodeUnknownOperator      DiagnosticCode = "unknown-operator"
	CodeParseError           DiagnosticCode = "parse-error"
	CodeCorazaError          DiagnosticCode = "coraza-error"
)

// knownDirectives is the set of directive names recognized by Coraza, derived
// from the knowledge base so it stays in sync automatically.
var knownDirectives = func() map[string]bool {
	m := make(map[string]bool, len(knowledge.Default.DirectivesByName))
	for name := range knowledge.Default.DirectivesByName {
		m[name] = true
	}
	return m
}()

// knownVariables is the set of collection/variable names recognized by Coraza.
var knownVariables = func() map[string]bool {
	m := make(map[string]bool, len(knowledge.Default.VariablesByName))
	for name := range knowledge.Default.VariablesByName {
		m[name] = true
	}
	return m
}()

// knownActions is the set of rule action names recognized by Coraza.
var knownActions = func() map[string]bool {
	m := make(map[string]bool, len(knowledge.Default.ActionsByName))
	for name := range knowledge.Default.ActionsByName {
		m[name] = true
	}
	return m
}()

// knownTransformations is the set of transformation names recognized by Coraza.
var knownTransformations = func() map[string]bool {
	m := make(map[string]bool, len(knowledge.Default.TransformationsByName))
	for name := range knowledge.Default.TransformationsByName {
		m[name] = true
	}
	return m
}()

// knownOperators is the set of operator names recognized by Coraza.
var knownOperators = func() map[string]bool {
	m := make(map[string]bool, len(knowledge.Default.OperatorsByName))
	for name := range knowledge.Default.OperatorsByName {
		m[name] = true
	}
	return m
}()

// validSeverities is the set of accepted severity values (lowercase).
var validSeverities = map[string]bool{
	"emergency": true,
	"alert":     true,
	"critical":  true,
	"error":     true,
	"warning":   true,
	"notice":    true,
	"info":      true,
	"debug":     true,
	"0": true, "1": true, "2": true, "3": true, "4": true, "5": true, "6": true, "7": true,
}

// Analyze runs Stage 1 (AST-level) diagnostics synchronously and returns results immediately.
// This function is safe to call from multiple goroutines.
func Analyze(f *parser.File) []protocol_3_16.Diagnostic {
	var diags []protocol_3_16.Diagnostic

	// Collect parse errors from the AST.
	for _, pe := range f.Errors {
		diags = append(diags, protocol_3_16.Diagnostic{
			Range:    toProtocolRange(pe.Range),
			Severity: severityPtr(protocol_3_16.DiagnosticSeverityError),
			Source:   strPtr("coraza-lsp"),
			Code:     &protocol_3_16.IntegerOrString{Value: CodeParseError},
			Message:  pe.Message,
		})
	}

	// Track IDs for duplicate detection.
	seenIDs := make(map[string]parser.Range)

	for _, node := range f.Nodes {
		rule, ok := node.(*parser.RuleNode)
		if !ok {
			continue
		}

		// Generic directive: check if it's known.
		if gen, ok := node.(*parser.GenericDirectiveNode); ok {
			if !knownDirectives[strings.ToLower(gen.Name)] {
				diags = append(diags, protocol_3_16.Diagnostic{
					Range:    toProtocolRange(gen.NameRange),
					Severity: severityPtr(protocol_3_16.DiagnosticSeverityWarning),
					Source:   strPtr("coraza-lsp"),
					Code:     &protocol_3_16.IntegerOrString{Value: CodeUnknownDirective},
					Message:  fmt.Sprintf("unknown directive %q", gen.Name),
				})
			}
		}

		if rule == nil {
			continue
		}

		directive := rule.Directive
		if directive != "secrule" && directive != "secaction" && directive != "secdefaultaction" {
			continue
		}

		// Skip semantic action checks when the rule has parse errors — the
		// action list may be incomplete (e.g. unclosed string), so missing-id /
		// missing-phase would be spurious noise until the syntax is fixed.
		if len(rule.ParseErrors) > 0 {
			continue
		}

		// Chained rules inherit id and phase from the base rule — they must not
		// have their own id or phase and must not be checked for their absence.
		if !rule.IsChained {
			// SecDefaultAction does not take an id — it sets defaults that individual
			// rules inherit. Only secrule and secaction require a rule id.
			if directive == "secrule" || directive == "secaction" {
				idAction := rule.FindAction("id")
				if idAction == nil {
					diags = append(diags, protocol_3_16.Diagnostic{
						Range:    toProtocolRange(rule.NameRange),
						Severity: severityPtr(protocol_3_16.DiagnosticSeverityError),
						Source:   strPtr("coraza-lsp"),
						Code:     &protocol_3_16.IntegerOrString{Value: CodeMissingID},
						Message:  fmt.Sprintf("%s is missing required action: id", rule.Directive),
					})
				} else {
					idVal := strings.TrimSpace(idAction.Value)
					n, err := strconv.Atoi(idVal)
					if err != nil || n <= 0 {
						diags = append(diags, protocol_3_16.Diagnostic{
							Range:    toProtocolRange(idAction.Range),
							Severity: severityPtr(protocol_3_16.DiagnosticSeverityError),
							Source:   strPtr("coraza-lsp"),
							Code:     &protocol_3_16.IntegerOrString{Value: CodeInvalidID},
							Message:  fmt.Sprintf("rule id must be a positive integer, got %q", idVal),
						})
					} else if prev, dup := seenIDs[idVal]; dup {
						diags = append(diags, protocol_3_16.Diagnostic{
							Range:    toProtocolRange(idAction.Range),
							Severity: severityPtr(protocol_3_16.DiagnosticSeverityError),
							Source:   strPtr("coraza-lsp"),
							Code:     &protocol_3_16.IntegerOrString{Value: CodeDuplicateID},
							Message:  fmt.Sprintf("duplicate rule id %s (also defined at line %d)", idVal, prev.Start.Line+1),
						})
					} else {
						seenIDs[idVal] = idAction.Range
					}
				}
			}

			// Check for missing phase.
			phaseAction := rule.FindAction("phase")
			if phaseAction == nil {
				diags = append(diags, protocol_3_16.Diagnostic{
					Range:    toProtocolRange(rule.NameRange),
					Severity: severityPtr(protocol_3_16.DiagnosticSeverityWarning),
					Source:   strPtr("coraza-lsp"),
					Code:     &protocol_3_16.IntegerOrString{Value: CodeMissingPhase},
					Message:  fmt.Sprintf("%s is missing recommended action: phase", rule.Directive),
				})
			} else {
				// Validate phase value.
				phaseVal := strings.TrimSpace(phaseAction.Value)
				n, err := strconv.Atoi(phaseVal)
				if err != nil || n < 1 || n > 5 {
					diags = append(diags, protocol_3_16.Diagnostic{
						Range:    toProtocolRange(phaseAction.Range),
						Severity: severityPtr(protocol_3_16.DiagnosticSeverityError),
						Source:   strPtr("coraza-lsp"),
						Code:     &protocol_3_16.IntegerOrString{Value: CodeInvalidPhase},
						Message:  fmt.Sprintf("phase must be between 1 and 5, got %q", phaseVal),
					})
				}
			}
		}

		// Check variable names against the knowledge base.
		// Catches typos like ARGS.yyy (should be ARGS:yyy) which parse without
		// error but produce a vague "unknown variable" from Coraza at Stage 2.
		for _, varExpr := range rule.Variables {
			if !knownVariables[strings.ToLower(varExpr.Name)] {
				diags = append(diags, protocol_3_16.Diagnostic{
					Range:    toProtocolRange(varExpr.Range),
					Severity: severityPtr(protocol_3_16.DiagnosticSeverityWarning),
					Source:   strPtr("coraza-lsp"),
					Code:     &protocol_3_16.IntegerOrString{Value: CodeUnknownVariable},
					Message:  unknownVariableMessage(varExpr.Name),
				})
			}
		}

		// Check action names, values, skipAfter targets, ctl options, and macros.
		for _, action := range rule.Actions {
			lower := action.LowerName()

			// Unknown action name.
			if !knownActions[lower] {
				diags = append(diags, protocol_3_16.Diagnostic{
					Range:    toProtocolRange(action.Range),
					Severity: severityPtr(protocol_3_16.DiagnosticSeverityWarning),
					Source:   strPtr("coraza-lsp"),
					Code:     &protocol_3_16.IntegerOrString{Value: CodeUnknownAction},
					Message:  fmt.Sprintf("unknown action %q", action.Name),
				})
				continue
			}

			switch lower {
			case "skipafter":
				if f.FindMarker(action.Value) == nil {
					// The target marker may legitimately live in another file that
					// is Include'd at runtime — this LSP does not resolve Includes
					// across files. Keep it at Information severity so it doesn't
					// look like a bug in multi-file rule sets.
					diags = append(diags, protocol_3_16.Diagnostic{
						Range:    toProtocolRange(action.Range),
						Severity: severityPtr(protocol_3_16.DiagnosticSeverityInformation),
						Source:   strPtr("coraza-lsp"),
						Code:     &protocol_3_16.IntegerOrString{Value: CodeSkipAfterNotFound},
						Message:  fmt.Sprintf("skipAfter target %q not found in this file (may be defined in an Included file)", action.Value),
					})
				}
			case "ctl":
				diags = append(diags, validateCtlAction(&action)...)
			case "t":
				// "t" must have a colon and a non-empty name: t:lowercase, t:none, etc.
				if !action.HasColon || strings.TrimSpace(action.Value) == "" {
					diags = append(diags, protocol_3_16.Diagnostic{
						Range:    toProtocolRange(action.Range),
						Severity: severityPtr(protocol_3_16.DiagnosticSeverityError),
						Source:   strPtr("coraza-lsp"),
						Code:     &protocol_3_16.IntegerOrString{Value: CodeMissingTransformation},
						Message:  "t requires a transformation name (e.g. t:lowercase)",
					})
				} else if !knownTransformations[strings.ToLower(action.Value)] {
					// Unknown but syntactically valid — warn rather than error, because
					// custom/vendor transformations not in the knowledge base may exist.
					diags = append(diags, protocol_3_16.Diagnostic{
						Range:    toProtocolRange(action.Range),
						Severity: severityPtr(protocol_3_16.DiagnosticSeverityWarning),
						Source:   strPtr("coraza-lsp"),
						Code:     &protocol_3_16.IntegerOrString{Value: CodeUnknownTransformation},
						Message:  fmt.Sprintf("unknown transformation %q", action.Value),
					})
				}
			case "severity":
				// Validate severity value: name (CRITICAL etc.) or number 0-7.
				if action.Value != "" && !validSeverities[strings.ToLower(strings.TrimSpace(action.Value))] {
					diags = append(diags, protocol_3_16.Diagnostic{
						Range:    toProtocolRange(action.Range),
						Severity: severityPtr(protocol_3_16.DiagnosticSeverityWarning),
						Source:   strPtr("coraza-lsp"),
						Code:     &protocol_3_16.IntegerOrString{Value: CodeInvalidSeverity},
						Message:  fmt.Sprintf("invalid severity %q; valid values: EMERGENCY, ALERT, CRITICAL, ERROR, WARNING, NOTICE, INFO, DEBUG (or 0-7)", action.Value),
					})
				}
			}
			// Check macro expansions in action values that support them.
			if macroCapableAction(lower) && action.Value != "" {
				diags = append(diags, checkMacros(action.Value, action.Range)...)
			}
		}

		// Validate operator name.
		if rule.Operator != nil && rule.Operator.Name != "" {
			if !knownOperators[strings.ToLower(rule.Operator.Name)] {
				diags = append(diags, protocol_3_16.Diagnostic{
					Range:    toProtocolRange(rule.Operator.NameRange),
					Severity: severityPtr(protocol_3_16.DiagnosticSeverityWarning),
					Source:   strPtr("coraza-lsp"),
					Code:     &protocol_3_16.IntegerOrString{Value: CodeUnknownOperator},
					Message:  fmt.Sprintf("unknown operator %q", rule.Operator.Name),
				})
			}
		}

		// Check macro expansions in operator argument.
		if rule.Operator != nil && rule.Operator.Argument != "" {
			diags = append(diags, checkMacros(rule.Operator.Argument, rule.Operator.Range)...)
		}
	}

	// Check generic directives for unknown names, unclosed strings, and
	// directive-specific semantic errors.
	for _, node := range f.Nodes {
		gen, ok := node.(*parser.GenericDirectiveNode)
		if !ok {
			continue
		}
		lower := strings.ToLower(gen.Name)

		if !knownDirectives[lower] {
			diags = append(diags, protocol_3_16.Diagnostic{
				Range:    toProtocolRange(gen.NameRange),
				Severity: severityPtr(protocol_3_16.DiagnosticSeverityWarning),
				Source:   strPtr("coraza-lsp"),
				Code:     &protocol_3_16.IntegerOrString{Value: CodeUnknownDirective},
				Message:  fmt.Sprintf("unknown directive %q", gen.Name),
			})
		}

		// Unclosed quoted strings are already reported as parse errors via
		// gen.ParseErrors → file.Errors → the parse-error loop at the top of
		// Analyze(). No need to re-report them here.

		// Directive-specific semantic validation.
		switch lower {
		case "secruleupdatetargetbyid":
			diags = append(diags, validateUpdateTargetById(gen)...)
		}
	}

	return diags
}

// ValidateWithCoraza runs Stage 2 validation using the Coraza WAF public API.
// It creates a fresh WAF instance for every call — this is safe to call concurrently
// but each call is ~5ms. Always debounce before calling.
//
// dir is the directory of the file being validated. When non-empty, Coraza uses
// it as the root filesystem so that relative data-file paths (e.g. @pmFromFile
// php-variables.data) resolve correctly. Pass "" when no file path is known.
func ValidateWithCoraza(source, dir string) []protocol_3_16.Diagnostic {
	cfg := coraza.NewWAFConfig().
		WithDirectives(source).
		WithErrorCallback(func(mr types.MatchedRule) {}) // suppress runtime alerts

	if dir != "" {
		cfg = cfg.WithRootFS(os.DirFS(dir))
	}

	_, err := coraza.NewWAF(cfg)
	if err == nil {
		return nil
	}

	errMsg := err.Error()

	// Suppress errors for @-prefixed virtual paths (e.g. "Include @coreruleset").
	// These are runtime mount points that cannot be resolved in single-file mode.
	// Use filepath.Base so the check works whether or not a dir prefix was added
	// by WithRootFS (e.g. "/rules/@coreruleset" → base "@coreruleset").
	if p := extractReadfilePathFromError(errMsg); p != "" && strings.HasPrefix(filepath.Base(p), "@") {
		return nil
	}

	// Suppress "rule not found" errors from cross-file rule-update directives
	// (SecRuleUpdateTargetById, SecRuleUpdateActionById, SecRuleRemoveById,
	// SecRuleRemoveByTag). The referenced rules are typically defined in other
	// files loaded at runtime — single-file validation cannot resolve them.
	if isRuleNotFoundError(errMsg) {
		return nil
	}

	return []protocol_3_16.Diagnostic{
		{
			Range: toProtocolRange(locateCorazaError(errMsg, source)),
			// Stage 2 is best-effort: Coraza runs without the full deployment
			// context (data files, included configs), so its errors are advisory.
			Severity: severityPtr(protocol_3_16.DiagnosticSeverityWarning),
			Source:   strPtr("coraza"),
			Code:     &protocol_3_16.IntegerOrString{Value: CodeCorazaError},
			Message:  cleanCorazaMessage(errMsg),
		},
	}
}

// locateCorazaError searches source lines for the directive named in a Coraza
// error message and returns a Range.
//
// For "failed to compile" / "error compiling" errors the problem is the value,
// so the range covers the value token and we try to find the specific occurrence
// whose value matches the bad value embedded in the error message (handles the
// case where the same directive appears multiple times — e.g. SecRuleEngine On
// on line 0 and SecRuleEngine XXX on line 5). Falls back to the first occurrence
// when no value match is possible (e.g. "invalid log level" carries no value).
//
// For unknown/invalid directive errors the range covers the directive name token.
// Falls back to line 0 when no match is found.
func locateCorazaError(errMsg, source string) parser.Range {
	directive := extractDirectiveFromError(errMsg)
	if directive == "" {
		// Locate the file reference (Include directive or @pmFromFile operand).
		if p := extractReadfilePathFromError(errMsg); p != "" {
			return findFileReference(p, source)
		}
		return parser.Range{}
	}

	lower := strings.ToLower(errMsg)
	isCompile := strings.Contains(lower, `failed to compile the directive "`) ||
		strings.Contains(lower, `error compiling directive "`)

	badVal := ""
	ruleID := ""
	if isCompile {
		switch directive {
		case "secrule", "secaction", "secdefaultaction":
			// For rule directives the bad value is not a simple token; instead we
			// try to match by the rule ID embedded in the Coraza error message.
			ruleID = extractRuleIDFromError(errMsg)
		default:
			badVal = extractBadValueFromError(errMsg)
		}
	}

	lines := strings.Split(source, "\n")

	// For non-compile errors return the first directive occurrence immediately.
	// For compile errors we scan all occurrences looking for a match, then fall
	// back to the first occurrence.
	firstRange := parser.Range{}
	firstFound := false

	for i, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		token := firstToken(trimmed)
		lowerToken := strings.ToLower(token)
		if lowerToken != directive {
			continue
		}

		col := max(strings.Index(strings.ToLower(raw), lowerToken), 0)

		nameRange := parser.Range{
			Start: parser.Position{Line: i, Character: col},
			End:   parser.Position{Line: i, Character: col + len(token)},
		}

		if !isCompile {
			return nameRange
		}

		// Rule directives: match by embedded rule ID.
		if ruleID != "" {
			if !firstFound {
				firstRange = nameRange
				firstFound = true
			}
			if ruleContainsID(lines, i, ruleID) {
				return nameRange
			}
			continue
		}

		// Simple directives: match by value token.
		valStart, valEnd, ok := valueTokenPosition(raw, col+len(token))
		if !ok {
			if !firstFound {
				firstRange = nameRange
				firstFound = true
			}
			continue
		}

		r := parser.Range{
			Start: parser.Position{Line: i, Character: valStart},
			End:   parser.Position{Line: i, Character: valEnd},
		}

		if !firstFound {
			firstRange = r
			firstFound = true
		}

		// Strip surrounding quotes from the source token before comparing —
		// `SecRuleEngine "XXX"` produces token `"XXX"` but the error says `XXX`.
		if badVal != "" && strings.EqualFold(stripQuotes(raw[valStart:valEnd]), badVal) {
			return r
		}
	}

	// For rule-directive "unknown variable" errors with no rule ID, the line-scan
	// above always falls back to firstRange (first directive occurrence). Try a
	// smarter match: parse the source and return the first SecRule/SecAction that
	// contains either an unrecognised variable name or a wildcard (COLLECTION*)
	// form that Coraza does not support.
	if isCompile && ruleID == "" &&
		(directive == "secrule" || directive == "secaction" || directive == "secdefaultaction") &&
		strings.Contains(lower, "unknown variable") {
		if r, ok := findFirstRuleWithVariableIssue(source); ok {
			return r
		}
	}

	return firstRange
}

// findFirstRuleWithVariableIssue parses source and returns the range of the
// first variable in a rule that Coraza would consider unknown. Two cases:
//  1. The variable name is not in the LSP knowledge base (e.g. "FOOBAR").
//  2. The variable uses the wildcard suffix form (COLLECTION*) that Coraza does
//     not support — these parse to Key=="*" by the LSP parser.
//
// Returns the variable's source range and true when found, or zero range and
// false when no problematic variable is found.
func findFirstRuleWithVariableIssue(source string) (parser.Range, bool) {
	f := parser.Parse("", source)
	for _, node := range f.Nodes {
		rule, ok := node.(*parser.RuleNode)
		if !ok {
			continue
		}
		for i := range rule.Variables {
			v := &rule.Variables[i]
			// Unknown variable name (not in knowledge base).
			if knowledge.Variable(v.Name) == nil {
				return v.Range, true
			}
			// COLLECTION* form (Key=="*") — Coraza does not support the bare * suffix.
			if v.Key == "*" {
				return v.Range, true
			}
		}
	}
	return parser.Range{}, false
}

// ruleContainsID reports whether the rule starting at line i (including any
// backslash-continuation lines) contains "id:NNN" in its raw text.
func ruleContainsID(lines []string, i int, ruleID string) bool {
	needle := strings.ToLower("id:" + ruleID)
	for j := i; j < len(lines); j++ {
		if strings.Contains(strings.ToLower(lines[j]), needle) {
			return true
		}
		// Stop once we leave the continuation block.
		if !strings.HasSuffix(strings.TrimRight(lines[j], "\r"), "\\") {
			break
		}
	}
	return false
}

// extractRuleIDFromError looks for "id:NNN" inside a Coraza SecRule/SecAction
// error message and returns the numeric ID string (e.g. "1002"), or empty.
//
// Coraza embeds the rule's raw content in messages like:
//
//	invalid actions for rule with operator: "ARGS "@rx b" "id:1002,phase:2,..."
func extractRuleIDFromError(errMsg string) string {
	lower := strings.ToLower(errMsg)
	i := 0
	for i < len(lower) {
		idx := strings.Index(lower[i:], "id:")
		if idx == -1 {
			break
		}
		abs := i + idx
		rest := errMsg[abs+3:]
		end := 0
		for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
			end++
		}
		if end > 0 {
			return rest[:end]
		}
		i = abs + 3
	}
	return ""
}

// extractBadValueFromError tries to pull the offending value out of a Coraza
// compile-error message so locateCorazaError can find the right occurrence when
// the same directive appears multiple times.
//
// Handled patterns (all after the directive name):
//   - strconv.*: parsing "VALUE": ...   → VALUE
//   - *status: "VALUE"                  → VALUE  (rule/audit engine)
//   - *status: VALUE                    → VALUE  (audit engine, unquoted)
func extractBadValueFromError(errMsg string) string {
	// strconv.*: parsing "VALUE": invalid syntax
	if _, rest, ok := strings.Cut(errMsg, `parsing "`); ok {
		if val, _, ok := strings.Cut(rest, `"`); ok {
			return val
		}
	}
	// invalid * status: "VALUE"
	if _, rest, ok := strings.Cut(errMsg, `status: "`); ok {
		if val, _, ok := strings.Cut(rest, `"`); ok {
			return val
		}
	}
	// invalid * status: VALUE  (no quotes — e.g. audit engine)
	if _, rest, ok := strings.Cut(errMsg, `status: `); ok {
		return firstToken(strings.TrimSpace(rest))
	}
	return ""
}

// valueTokenPosition finds the first non-whitespace token starting after offset
// in line and returns (start, end, true), or (0, 0, false) if none.
func valueTokenPosition(line string, offset int) (int, int, bool) {
	for offset < len(line) && (line[offset] == ' ' || line[offset] == '\t') {
		offset++
	}
	if offset >= len(line) {
		return 0, 0, false
	}
	start := offset
	for offset < len(line) && line[offset] != ' ' && line[offset] != '\t' {
		offset++
	}
	return start, offset, true
}

// cleanCorazaMessage converts raw Coraza error strings into human-friendly
// diagnostic messages, stripping internal Go parsing noise.
func cleanCorazaMessage(errMsg string) string {
	// Strip the outer "invalid WAF config from string: " wrapper that Coraza
	// always adds — the inner message is more informative on its own.
	const wafWrapper = "invalid WAF config from string: "
	if after, ok := strings.CutPrefix(errMsg, wafWrapper); ok {
		errMsg = after
	}

	lower := strings.ToLower(errMsg)

	// Extract the reason after `failed to compile the directive "NAME": `.
	for _, marker := range []string{`failed to compile the directive "`, `error compiling directive "`} {
		idx := strings.Index(lower, marker)
		if idx == -1 {
			continue
		}
		rest := errMsg[idx+len(marker):]
		_, after, ok := strings.Cut(rest, `"`)
		if !ok {
			continue
		}
		return cleanStrconvNoise(strings.TrimPrefix(after, ": "))
	}
	return errMsg
}

// isRuleNotFoundError reports whether a Coraza error comes from a cross-file
// rule-update directive (SecRuleUpdateTargetById, SecRuleUpdateActionById,
// SecRuleRemoveById, SecRuleRemoveByTag) that cannot find its target because
// the referenced rule is defined in a different file. Single-file validation
// cannot resolve cross-file rule references, so these are suppressed.
func isRuleNotFoundError(errMsg string) bool {
	lower := strings.ToLower(errMsg)
	if !strings.Contains(lower, "not found") {
		return false
	}
	for _, d := range []string{
		"secruleupdatetargetbyid",
		"secruleupdateactionbyid",
		"secruleremovebyid",
		"secruleremovebytag",
	} {
		if strings.Contains(lower, d) {
			return true
		}
	}
	return false
}

// extractReadfilePathFromError extracts the file path from a Coraza
// "failed to readfile: open PATH: ..." error message.
// Returns empty string if the message does not match this pattern.
func extractReadfilePathFromError(errMsg string) string {
	// Pattern: "... open PATH: no such file or directory"
	_, rest, ok := strings.Cut(errMsg, "open ")
	if !ok {
		return ""
	}
	if path, _, ok := strings.Cut(rest, ": "); ok {
		return path
	}
	return rest
}

// findFileReference searches source lines for the first non-comment line that
// references path or its base name, and returns the range covering the matched
// text. It handles both Include directives (full path) and inline data-file
// references such as @pmFromFile (relative/base-name only).
// Falls back to Range{} when no match is found.
func findFileReference(path, source string) parser.Range {
	base := filepath.Base(path)
	lowerBase := strings.ToLower(base)
	lowerPath := strings.ToLower(path)

	lines := strings.Split(source, "\n")
	for i, raw := range lines {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lowerRaw := strings.ToLower(raw)
		// Prefer an exact full-path match (e.g. Include /abs/path/file.conf).
		if col := strings.Index(lowerRaw, lowerPath); col >= 0 {
			return parser.Range{
				Start: parser.Position{Line: i, Character: col},
				End:   parser.Position{Line: i, Character: col + len(path)},
			}
		}
		// Fall back to base-name match (e.g. @pmFromFile php-variables.data).
		if col := strings.Index(lowerRaw, lowerBase); col >= 0 {
			return parser.Range{
				Start: parser.Position{Line: i, Character: col},
				End:   parser.Position{Line: i, Character: col + len(base)},
			}
		}
	}
	return parser.Range{}
}

// cleanStrconvNoise replaces verbose Go strconv error strings with plain English.
// e.g. `strconv.ParseInt: parsing "x": invalid syntax` → `"x" is not a valid integer`
func cleanStrconvNoise(msg string) string {
	if !strings.HasPrefix(msg, "strconv.") {
		return msg
	}
	if _, rest, ok := strings.Cut(msg, `parsing "`); ok {
		if val, _, ok := strings.Cut(rest, `"`); ok {
			return fmt.Sprintf("%q is not a valid integer", val)
		}
	}
	return msg
}

// extractDirectiveFromError parses common Coraza error message patterns and
// returns the lowercase directive name, or empty string if not found.
//
// Handled patterns:
//   - `unknown directive "NAME"`
//   - `invalid directive "NAME"`
//   - `failed to compile the directive "NAME": reason`
//   - `error compiling directive "NAME": reason`
//   - `invalid WAF config from string: ...` (wrapping prefix — stripped automatically)
func extractDirectiveFromError(errMsg string) string {
	lower := strings.ToLower(errMsg)
	markers := []string{
		`unknown directive "`,
		`invalid directive "`,
		`failed to compile the directive "`,
		`error compiling directive "`,
	}
	for _, marker := range markers {
		idx := strings.Index(lower, marker)
		if idx == -1 {
			continue
		}
		rest := errMsg[idx+len(marker):]
		if name, _, ok := strings.Cut(rest, `"`); ok {
			return strings.ToLower(name)
		}
	}
	return ""
}

// stripQuotes removes a single layer of matching surrounding quotes (" or ') from s.
func stripQuotes(s string) string {
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		return s[1 : len(s)-1]
	}
	return s
}

// unknownVariableMessage produces the diagnostic message for an unknown variable
// name, including a hint when the name looks like a common typo.
// "ARGS.yyy" → '.' instead of ':' for key selectors is by far the most common mistake.
func unknownVariableMessage(name string) string {
	if base, rest, ok := strings.Cut(name, "."); ok && base != "" {
		if _, known := knownVariables[strings.ToLower(base)]; known {
			return fmt.Sprintf("unknown variable %q (did you mean %q?)", name, base+":"+strings.ToLower(rest))
		}
	}
	return fmt.Sprintf("unknown variable %q", name)
}

// validateCtlAction validates the key and (when present) value of a ctl action.
// It returns zero or one diagnostic.
func validateCtlAction(action *parser.ActionExpr) []protocol_3_16.Diagnostic {
	key, value, hasValue := strings.Cut(action.Value, "=")

	opt, ok := knowledge.CtlOptionsByKey[strings.ToLower(key)]
	if !ok {
		return []protocol_3_16.Diagnostic{{
			Range:    toProtocolRange(action.Range),
			Severity: severityPtr(protocol_3_16.DiagnosticSeverityWarning),
			Source:   strPtr("coraza-lsp"),
			Code:     &protocol_3_16.IntegerOrString{Value: CodeUnknownCtlOption},
			Message:  fmt.Sprintf("unknown ctl option %q", key),
		}}
	}

	// Options that take no value: nothing more to validate.
	if opt.NoValue {
		return nil
	}

	// Value not typed yet: nothing to validate.
	if !hasValue {
		return nil
	}

	// Free-form value (no enum list): accept anything.
	if len(opt.Values) == 0 {
		return nil
	}

	lower := strings.ToLower(value)
	for _, v := range opt.Values {
		if strings.ToLower(v) == lower {
			return nil
		}
	}

	return []protocol_3_16.Diagnostic{{
		Range:    toProtocolRange(action.Range),
		Severity: severityPtr(protocol_3_16.DiagnosticSeverityWarning),
		Source:   strPtr("coraza-lsp"),
		Code:     &protocol_3_16.IntegerOrString{Value: CodeInvalidCtlValue},
		Message:  fmt.Sprintf("invalid value %q for ctl:%s; valid values: %s", value, opt.Key, strings.Join(opt.Values, ", ")),
	}}
}

// validateUpdateTargetById validates the arguments of a SecRuleUpdateTargetById
// directive:
//
//	SecRuleUpdateTargetById RULE_ID "!VARIABLE_LIST"
//
// Expected argument layout (0-indexed):
//
//	[0] RULE_ID    — word token, must be a positive integer
//	[1] TARGETS    — quoted token, a pipe-separated variable list identical in
//	                 syntax to a SecRule variable argument
//
// Errors are silently suppressed when the quoted argument was unclosed (that
// error is already reported as a parse-error by the parser).
func validateUpdateTargetById(gen *parser.GenericDirectiveNode) []protocol_3_16.Diagnostic {
	var diags []protocol_3_16.Diagnostic

	toks := gen.ArgTokens
	if len(toks) == 0 {
		return nil
	}

	// Validate rule ID (arg 0).
	idTok := toks[0]
	if idTok.Type == parser.TokenWord {
		n, err := strconv.Atoi(idTok.Value)
		if err != nil || n <= 0 {
			diags = append(diags, protocol_3_16.Diagnostic{
				Range: toProtocolRange(parser.Range{
					Start: parser.Position{Line: idTok.Line, Character: idTok.StartChar},
					End:   parser.Position{Line: idTok.Line, Character: idTok.EndChar},
				}),
				Severity: severityPtr(protocol_3_16.DiagnosticSeverityError),
				Source:   strPtr("coraza-lsp"),
				Code:     &protocol_3_16.IntegerOrString{Value: CodeInvalidID},
				Message:  fmt.Sprintf("SecRuleUpdateTargetById: rule id must be a positive integer, got %q", idTok.Value),
			})
		}
	}

	// Validate variable list (arg 1).
	if len(toks) < 2 {
		return diags
	}
	varTok := toks[1]
	// Skip if the string was unclosed — the parse-error is already reported.
	if varTok.Unclosed {
		return diags
	}

	offset := parser.Position{Line: varTok.Line, Character: varTok.StartChar + 1} // +1 for opening "
	vars, parseErrs := parser.ParseVariables(varTok.Value, offset)

	for _, pe := range parseErrs {
		diags = append(diags, protocol_3_16.Diagnostic{
			Range:    toProtocolRange(pe.Range),
			Severity: severityPtr(protocol_3_16.DiagnosticSeverityError),
			Source:   strPtr("coraza-lsp"),
			Code:     &protocol_3_16.IntegerOrString{Value: CodeParseError},
			Message:  pe.Message,
		})
	}

	for _, v := range vars {
		if !knownVariables[strings.ToLower(v.Name)] {
			diags = append(diags, protocol_3_16.Diagnostic{
				Range:    toProtocolRange(v.Range),
				Severity: severityPtr(protocol_3_16.DiagnosticSeverityWarning),
				Source:   strPtr("coraza-lsp"),
				Code:     &protocol_3_16.IntegerOrString{Value: CodeUnknownVariable},
				Message:  unknownVariableMessage(v.Name),
			})
		}
	}

	return diags
}

// macroCapableAction reports whether the named action supports %{…} macro
// expansion in its value. This list mirrors the Coraza/ModSecurity spec.
func macroCapableAction(name string) bool {
	switch name {
	case "setvar", "msg", "logdata", "redirect",
		"initcol", "setsid", "setuid", "setenv", "expirevar":
		return true
	}
	return false
}

// checkMacros scans s for %{…} macro expressions and returns diagnostics for
// any that are syntactically malformed or reference an unknown collection.
// contextRange is the range of the enclosing action/operator token and is used
// for the diagnostic range when a precise sub-range is not available.
func checkMacros(s string, contextRange parser.Range) []protocol_3_16.Diagnostic {
	var diags []protocol_3_16.Diagnostic
	i := 0
	for i < len(s) {
		idx := strings.Index(s[i:], "%{")
		if idx < 0 {
			break
		}
		abs := i + idx
		rest := s[abs+2:] // content after "%{"

		// Find the closing "}".
		end := strings.IndexByte(rest, '}')
		if end < 0 {
			// Unclosed macro — report once and stop scanning.
			diags = append(diags, protocol_3_16.Diagnostic{
				Range:    toProtocolRange(contextRange),
				Severity: severityPtr(protocol_3_16.DiagnosticSeverityError),
				Source:   strPtr("coraza-lsp"),
				Code:     &protocol_3_16.IntegerOrString{Value: CodeInvalidMacro},
				Message:  "unclosed macro expansion (missing closing '}')",
			})
			break
		}

		expr := rest[:end] // e.g. "TX.0", "MATCHED_VAR", "REQUEST_HEADERS.User-Agent"

		if expr == "" {
			diags = append(diags, protocol_3_16.Diagnostic{
				Range:    toProtocolRange(contextRange),
				Severity: severityPtr(protocol_3_16.DiagnosticSeverityError),
				Source:   strPtr("coraza-lsp"),
				Code:     &protocol_3_16.IntegerOrString{Value: CodeInvalidMacro},
				Message:  "empty macro expansion %{}",
			})
		} else {
			// Collection name is everything before the first '.' or ':'.
			collName := expr
			if dot := strings.IndexAny(expr, ".:"); dot >= 0 {
				collName = expr[:dot]
			}
			if !knownVariables[strings.ToLower(collName)] {
				diags = append(diags, protocol_3_16.Diagnostic{
					Range:    toProtocolRange(contextRange),
					Severity: severityPtr(protocol_3_16.DiagnosticSeverityWarning),
					Source:   strPtr("coraza-lsp"),
					Code:     &protocol_3_16.IntegerOrString{Value: CodeInvalidMacro},
					Message:  fmt.Sprintf("unknown macro collection %q in %%{%s}", collName, expr),
				})
			}
		}

		i = abs + 2 + end + 1
	}
	return diags
}

// firstToken returns the first whitespace-delimited token from s.
func firstToken(s string) string {
	for i, r := range s {
		if unicode.IsSpace(r) {
			return s[:i]
		}
	}
	return s
}

// NotifyFunc is the function signature used to push diagnostics to the LSP client.
type NotifyFunc func(uri string, diags []protocol_3_16.Diagnostic)

// Validator schedules and debounces Stage 2 validation per document URI.
// Stage 1 is assumed to have already run synchronously.
//
// Performance: a fresh Coraza WAF is cheap (~5ms) and the 300ms debounce means
// at most ~3 validations/second per document, which is well within budget.
type Validator struct {
	mu       sync.Mutex
	timers   map[string]*time.Timer
	delay    time.Duration
	callback NotifyFunc
}

// NewValidator creates a Validator that calls callback with the combined
// (Stage 1 + Stage 2) diagnostics for a URI after the debounce delay.
func NewValidator(delay time.Duration, callback NotifyFunc) *Validator {
	return &Validator{
		timers:   make(map[string]*time.Timer),
		delay:    delay,
		callback: callback,
	}
}

// Schedule schedules a validation for the given URI+source.
// If a validation is already pending for this URI, it is cancelled and rescheduled.
func (v *Validator) Schedule(uri, source string, stage1 []protocol_3_16.Diagnostic) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if t, ok := v.timers[uri]; ok {
		t.Stop()
	}

	v.timers[uri] = time.AfterFunc(v.delay, func() {
		v.mu.Lock()
		delete(v.timers, uri)
		v.mu.Unlock()

		// Skip Stage 2 when Stage 1 already found parse errors — Coraza would
		// produce confusing messages (e.g. "invalid actions") that are just
		// symptoms of the same underlying syntax problem.
		if hasParseErrors(stage1) {
			v.callback(uri, stage1)
			return
		}

		// Derive the directory from the URI so Coraza can resolve relative paths
		// (e.g. @pmFromFile data files alongside the conf file).
		dir := ""
		if after, ok := strings.CutPrefix(uri, "file://"); ok {
			dir = filepath.Dir(after)
		}

		// Run Stage 2 and merge with Stage 1.
		// Suppress Stage 2 coraza-errors that are already covered by a Stage 1
		// unknown-variable diagnostic on the same line — the LSP warning is more
		// precise and the Coraza repeat is just noise.
		stage2 := ValidateWithCoraza(source, dir)
		stage2 = suppressRedundantCorazaErrors(stage1, stage2)
		all := make([]protocol_3_16.Diagnostic, 0, len(stage1)+len(stage2))
		all = append(all, stage1...)
		all = append(all, stage2...)
		v.callback(uri, all)
	})
}

// Cancel stops any pending validation for the given URI.
func (v *Validator) Cancel(uri string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if t, ok := v.timers[uri]; ok {
		t.Stop()
		delete(v.timers, uri)
	}
}

// CancelAll stops all pending validations.
func (v *Validator) CancelAll() {
	v.mu.Lock()
	defer v.mu.Unlock()
	for uri, t := range v.timers {
		t.Stop()
		delete(v.timers, uri)
	}
}

// suppressRedundantCorazaErrors removes Stage 2 coraza-error diagnostics that
// are already covered by a Stage 1 unknown-variable warning on the same line.
// When the LSP has already identified the offending variable precisely, the
// generic Coraza "unknown variable" repeat is noise that confuses the user.
func suppressRedundantCorazaErrors(stage1, stage2 []protocol_3_16.Diagnostic) []protocol_3_16.Diagnostic {
	// Build the set of lines that Stage 1 flagged with unknown-variable.
	unknownVarLines := make(map[uint32]bool)
	for _, d := range stage1 {
		if d.Code != nil && d.Code.Value == CodeUnknownVariable {
			unknownVarLines[d.Range.Start.Line] = true
		}
	}
	if len(unknownVarLines) == 0 {
		return stage2
	}
	filtered := stage2[:0:0] // avoid modifying the original slice
	for _, d := range stage2 {
		if d.Code != nil && d.Code.Value == CodeCorazaError && unknownVarLines[d.Range.Start.Line] {
			continue // suppressed: Stage 1 already reported this more precisely
		}
		filtered = append(filtered, d)
	}
	return filtered
}

// hasParseErrors reports whether any diagnostic in diags has CodeParseError.
func hasParseErrors(diags []protocol_3_16.Diagnostic) bool {
	for _, d := range diags {
		if d.Code != nil && d.Code.Value == CodeParseError {
			return true
		}
	}
	return false
}

// Helpers

func toProtocolRange(r parser.Range) protocol_3_16.Range {
	return protocol_3_16.Range{
		Start: protocol_3_16.Position{
			Line:      uint32(r.Start.Line),
			Character: uint32(r.Start.Character),
		},
		End: protocol_3_16.Position{
			Line:      uint32(r.End.Line),
			Character: uint32(r.End.Character),
		},
	}
}

func severityPtr(s protocol_3_16.DiagnosticSeverity) *protocol_3_16.DiagnosticSeverity {
	return &s
}

func strPtr(s string) *string {
	return &s
}

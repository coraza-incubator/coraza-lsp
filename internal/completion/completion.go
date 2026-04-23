// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package completion

import (
	"strings"

	protocol_3_16 "github.com/tliron/glsp/protocol_3_16"

	"github.com/coraza-incubator/coraza-lsp/internal/knowledge"
	"github.com/coraza-incubator/coraza-lsp/internal/parser"
)

var (
	kindKeyword  = protocol_3_16.CompletionItemKindKeyword
	kindVariable = protocol_3_16.CompletionItemKindVariable
	kindFunction = protocol_3_16.CompletionItemKindFunction
	kindConstant = protocol_3_16.CompletionItemKindConstant
	kindValue    = protocol_3_16.CompletionItemKindValue
	kindSnippet  = protocol_3_16.InsertTextFormatSnippet
	kindPlain    = protocol_3_16.InsertTextFormatPlainText
)

// CollectTXKeys scans all rules in f for setvar actions that write to the TX
// collection and returns the unique lowercased key names (without the "TX:" prefix).
// Returns nil when f is nil or no TX keys are found.
func CollectTXKeys(f *parser.File) []string {
	if f == nil {
		return nil
	}
	seen := make(map[string]bool)
	var keys []string
	for _, node := range f.Nodes {
		rule, ok := node.(*parser.RuleNode)
		if !ok {
			continue
		}
		for _, action := range rule.Actions {
			if action.LowerName() != "setvar" {
				continue
			}
			val := action.Value
			// Handle delete form: !tx.key
			if strings.HasPrefix(val, "!") {
				val = val[1:]
			}
			if !strings.HasPrefix(strings.ToLower(val), "tx.") {
				continue
			}
			// Extract key: everything after "tx." up to "=" (if present).
			rest := val[3:]
			if eq := strings.IndexByte(rest, '='); eq >= 0 {
				rest = rest[:eq]
			}
			key := strings.ToLower(rest)
			if key != "" && !seen[key] {
				seen[key] = true
				keys = append(keys, key)
			}
		}
	}
	return keys
}

// CollectMarkerIDs scans f for all SecMarker directives and returns their unique IDs.
// Returns nil when f is nil or no markers are found.
func CollectMarkerIDs(f *parser.File) []string {
	if f == nil {
		return nil
	}
	seen := make(map[string]bool)
	var ids []string
	for _, node := range f.Nodes {
		m, ok := node.(*parser.MarkerNode)
		if !ok {
			continue
		}
		if m.MarkerID != "" && !seen[m.MarkerID] {
			seen[m.MarkerID] = true
			ids = append(ids, m.MarkerID)
		}
	}
	return ids
}

// GetCompletions returns LSP completion items for the given context and prefix.
// f is an optional parsed file used to inject file-local completions:
//   - ContextVariableList: TX:KEY suggestions from setvar actions
//   - ContextSkipAfterValue: SecMarker IDs from SecMarker directives
//
// The returned slice is nil when no completions are available.
//
// Performance: all knowledge lookups are O(n) prefix scans over pre-built slices.
func GetCompletions(ctx CompletionContext, prefix string, f ...*parser.File) []protocol_3_16.CompletionItem {
	var file *parser.File
	if len(f) > 0 {
		file = f[0]
	}
	switch ctx {
	case ContextDirectiveName:
		return directiveCompletions(prefix)
	case ContextVariableList:
		return variableCompletions(prefix, CollectTXKeys(file))
	case ContextOperator:
		return operatorCompletions(prefix)
	case ContextActionList:
		return actionCompletions(prefix)
	case ContextTransformation:
		return transformationCompletions(prefix)
	case ContextPhaseValue:
		return phaseValueCompletions(prefix)
	case ContextRuleEngineValue:
		return ruleEngineCompletions(prefix)
	case ContextSeverityValue:
		return severityCompletions(prefix)
	case ContextSkipAfterValue:
		return markerCompletions(prefix, CollectMarkerIDs(file))
	case ContextMacroExpansion:
		return macroCompletions(prefix, CollectTXKeys(file))
	case ContextCtlKey:
		return ctlKeyCompletions(prefix)
	case ContextCtlValue:
		return ctlValueCompletions(prefix)
	default:
		return nil
	}
}

func directiveCompletions(prefix string) []protocol_3_16.CompletionItem {
	items := knowledge.FilterByPrefix(knowledge.Default.Directives, prefix)
	result := make([]protocol_3_16.CompletionItem, 0, len(items))
	for _, item := range items {
		ci := makeItem(item, kindKeyword)

		// Special snippets for the most common directives.
		switch strings.ToLower(item.Name) {
		case "secrule":
			ci.InsertTextFormat = &kindSnippet
			text := "SecRule ${1:VARIABLES} \"@${2:rx} ${3:pattern}\" \\\n" +
				"    \"id:${4:1001},phase:${5:2},${6:deny},msg:'${7:Description}'\""
			ci.InsertText = &text
		case "secaction":
			ci.InsertTextFormat = &kindSnippet
			text := "SecAction \"id:${1:1000},phase:${2:1},${3:pass}\""
			ci.InsertText = &text
		case "secdefaultaction":
			ci.InsertTextFormat = &kindSnippet
			text := "SecDefaultAction \"phase:${1:2},${2:deny},status:${3:403},log,auditlog\""
			ci.InsertText = &text
		}

		result = append(result, ci)
	}
	return result
}

func variableCompletions(prefix string, txKeys []string) []protocol_3_16.CompletionItem {
	items := knowledge.FilterByPrefix(knowledge.Default.Variables, prefix)
	result := make([]protocol_3_16.CompletionItem, 0, len(items))
	for _, item := range items {
		result = append(result, makeItem(item, kindVariable))
	}
	// Inject file-local TX variable completions when the prefix starts with "TX:".
	if len(txKeys) > 0 && strings.HasPrefix(strings.ToUpper(prefix), "TX:") {
		keyPrefix := strings.ToLower(prefix[3:]) // portion after "TX:"
		for _, key := range txKeys {
			if strings.HasPrefix(key, keyPrefix) {
				label := "TX:" + key
				detail := "TX variable (file-local)"
				result = append(result, protocol_3_16.CompletionItem{
					Label:  label,
					Kind:   &kindVariable,
					Detail: &detail,
				})
			}
		}
	}
	return result
}

func operatorCompletions(prefix string) []protocol_3_16.CompletionItem {
	// Strip leading @ and ! from the prefix before matching.
	cleanPrefix := strings.TrimLeft(prefix, "@!")
	items := knowledge.FilterByPrefix(knowledge.Default.Operators, cleanPrefix)
	result := make([]protocol_3_16.CompletionItem, 0, len(items))
	for _, item := range items {
		ci := makeItem(item, kindFunction)
		// Insert text includes the @ prefix.
		text := "@" + item.Name
		ci.InsertText = &text
		result = append(result, ci)
	}
	return result
}

func actionCompletions(prefix string) []protocol_3_16.CompletionItem {
	items := knowledge.FilterByPrefix(knowledge.Default.Actions, prefix)
	result := make([]protocol_3_16.CompletionItem, 0, len(items))
	for _, item := range items {
		ci := makeItem(item, kindKeyword)
		// For actions that take a value, include snippet with colon.
		if item.ActionType == "metadata" || item.ActionType == "data" {
			switch strings.ToLower(item.Name) {
			case "id":
				ci.InsertTextFormat = &kindSnippet
				text := "id:${1:1001}"
				ci.InsertText = &text
			case "phase":
				ci.InsertTextFormat = &kindSnippet
				text := "phase:${1|1,2,3,4,5|}"
				ci.InsertText = &text
			case "msg":
				ci.InsertTextFormat = &kindSnippet
				text := "msg:'${1:Description}'"
				ci.InsertText = &text
			case "tag":
				ci.InsertTextFormat = &kindSnippet
				text := "tag:'${1:category}'"
				ci.InsertText = &text
			case "status":
				ci.InsertTextFormat = &kindSnippet
				text := "status:${1|403,400,429,302|}"
				ci.InsertText = &text
			case "t":
				ci.InsertTextFormat = &kindSnippet
				text := "t:${1:lowercase}"
				ci.InsertText = &text
			case "setvar":
				ci.InsertTextFormat = &kindSnippet
				text := "setvar:${1:TX.var}=${2:value}"
				ci.InsertText = &text
			case "ctl":
				ci.InsertTextFormat = &kindSnippet
				text := "ctl:${1|ruleEngine,requestBodyProcessor,ruleRemoveById,auditEngine|}=${2:value}"
				ci.InsertText = &text
			case "redirect":
				ci.InsertTextFormat = &kindSnippet
				text := "redirect:${1:https://example.com}"
				ci.InsertText = &text
			}
		}
		result = append(result, ci)
	}
	return result
}

func transformationCompletions(prefix string) []protocol_3_16.CompletionItem {
	items := knowledge.FilterByPrefix(knowledge.Default.Transformations, prefix)
	result := make([]protocol_3_16.CompletionItem, 0, len(items))
	for _, item := range items {
		result = append(result, makeItem(item, kindConstant))
	}
	return result
}

func phaseValueCompletions(prefix string) []protocol_3_16.CompletionItem {
	phases := []struct{ label, detail, doc string }{
		{"1", "Request headers", "Phase 1: Evaluated after request headers are received, before the body."},
		{"2", "Request body", "Phase 2: Evaluated after the complete request body is received."},
		{"3", "Response headers", "Phase 3: Evaluated after response headers are sent."},
		{"4", "Response body", "Phase 4: Evaluated after the response body is available."},
		{"5", "Logging", "Phase 5: Evaluated after the response is sent, during logging."},
		{"request", "Alias for phase 1", "Alias for phase:1 — evaluated after request headers are received."},
		{"response", "Alias for phase 4", "Alias for phase:4 — evaluated after response body is available."},
		{"logging", "Alias for phase 5", "Alias for phase:5 — evaluated during logging after the response is sent."},
	}
	lower := strings.ToLower(prefix)
	var result []protocol_3_16.CompletionItem
	for _, p := range phases {
		if !strings.HasPrefix(p.label, lower) {
			continue
		}
		detail := p.detail
		doc := p.doc
		result = append(result, protocol_3_16.CompletionItem{
			Label:  p.label,
			Kind:   &kindValue,
			Detail: &detail,
			Documentation: &protocol_3_16.MarkupContent{
				Kind:  "markdown",
				Value: doc,
			},
		})
	}
	return result
}

func ruleEngineCompletions(prefix string) []protocol_3_16.CompletionItem {
	values := []struct{ label, doc string }{
		{"On", "Enable the WAF engine. Rules are evaluated and enforced."},
		{"Off", "Disable all WAF processing."},
		{"DetectionOnly", "Evaluate rules but never block. Useful during initial deployment."},
	}
	var result []protocol_3_16.CompletionItem
	lower := strings.ToLower(prefix)
	for _, v := range values {
		if !strings.HasPrefix(strings.ToLower(v.label), lower) {
			continue
		}
		doc := v.doc
		result = append(result, protocol_3_16.CompletionItem{
			Label: v.label,
			Kind:  &kindValue,
			Documentation: &protocol_3_16.MarkupContent{
				Kind:  "markdown",
				Value: doc,
			},
		})
	}
	return result
}

func severityCompletions(prefix string) []protocol_3_16.CompletionItem {
	values := []string{"EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG"}
	var result []protocol_3_16.CompletionItem
	lower := strings.ToLower(prefix)
	for _, v := range values {
		if !strings.HasPrefix(strings.ToLower(v), lower) {
			continue
		}
		v := v
		result = append(result, protocol_3_16.CompletionItem{
			Label: v,
			Kind:  &kindValue,
		})
	}
	return result
}

// ctlKeyCompletions returns completion items for the key portion of a ctl action
// (i.e. the user has typed "ctl:" and is completing the option name).
func ctlKeyCompletions(prefix string) []protocol_3_16.CompletionItem {
	var result []protocol_3_16.CompletionItem
	lower := strings.ToLower(prefix)
	for i := range knowledge.CtlOptions {
		opt := &knowledge.CtlOptions[i]
		if !strings.HasPrefix(strings.ToLower(opt.Key), lower) {
			continue
		}
		// For options with no value, insert just the key; otherwise append = ready for value.
		insertText := opt.Key
		if !opt.NoValue {
			insertText = opt.Key + "="
		}
		summary := opt.Summary
		result = append(result, protocol_3_16.CompletionItem{
			Label:      opt.Key,
			Kind:       &kindConstant,
			Detail:     &summary,
			InsertText: &insertText,
		})
	}
	return result
}

// ctlValueCompletions returns completion items for the value portion of a ctl
// action. prefix is the full "KEY=valuePrefix" string from context detection.
func ctlValueCompletions(keyValue string) []protocol_3_16.CompletionItem {
	eqIdx := strings.IndexByte(keyValue, '=')
	if eqIdx < 0 {
		return nil
	}
	key := strings.ToLower(keyValue[:eqIdx])
	valPrefix := strings.ToLower(keyValue[eqIdx+1:])

	opt, ok := knowledge.CtlOptionsByKey[key]
	if !ok || len(opt.Values) == 0 {
		return nil // free-form; no suggestions
	}

	var result []protocol_3_16.CompletionItem
	for _, v := range opt.Values {
		if !strings.HasPrefix(strings.ToLower(v), valPrefix) {
			continue
		}
		v := v
		result = append(result, protocol_3_16.CompletionItem{
			Label: v,
			Kind:  &kindValue,
		})
	}
	return result
}

// macroCompletions returns completion items for the inside of a %{...} macro
// expression. The prefix is the text already typed after %{.
//
// Variable names follow macro notation: plain names like ARGS or REQUEST_HEADERS
// for simple variables, and TX.key for TX collection entries.
func macroCompletions(prefix string, txKeys []string) []protocol_3_16.CompletionItem {
	// Static variables from the knowledge base.
	items := knowledge.FilterByPrefix(knowledge.Default.Variables, prefix)
	result := make([]protocol_3_16.CompletionItem, 0, len(items))
	for _, item := range items {
		result = append(result, makeItem(item, kindVariable))
	}
	// File-local TX keys: suggest "TX.key" when prefix starts with "TX." (macro
	// notation uses a dot, unlike the colon used in SecRule variable lists).
	if len(txKeys) > 0 && strings.HasPrefix(strings.ToUpper(prefix), "TX.") {
		keyPrefix := strings.ToLower(prefix[3:]) // portion after "TX."
		for _, key := range txKeys {
			if strings.HasPrefix(key, keyPrefix) {
				label := "TX." + key
				detail := "TX variable (file-local)"
				result = append(result, protocol_3_16.CompletionItem{
					Label:  label,
					Kind:   &kindVariable,
					Detail: &detail,
				})
			}
		}
	}
	return result
}

// markerCompletions returns completion items for skipAfter values — the IDs of
// SecMarker directives found in the current file.
func markerCompletions(prefix string, markerIDs []string) []protocol_3_16.CompletionItem {
	if len(markerIDs) == 0 {
		return nil
	}
	var result []protocol_3_16.CompletionItem
	for _, id := range markerIDs {
		if !strings.HasPrefix(strings.ToLower(id), strings.ToLower(prefix)) {
			continue
		}
		label := id
		detail := "SecMarker (file-local)"
		result = append(result, protocol_3_16.CompletionItem{
			Label:  label,
			Kind:   &kindConstant,
			Detail: &detail,
		})
	}
	return result
}

// makeItem builds a CompletionItem from a knowledge Item.
func makeItem(item *knowledge.Item, kind protocol_3_16.CompletionItemKind) protocol_3_16.CompletionItem {
	detail := item.Syntax
	if detail == "" {
		detail = item.Summary
	}
	doc := item.Description
	if item.Example != "" {
		doc += "\n\n**Example:**\n```apache\n" + item.Example + "\n```"
	}
	return protocol_3_16.CompletionItem{
		Label:  item.Name,
		Kind:   &kind,
		Detail: &detail,
		Documentation: &protocol_3_16.MarkupContent{
			Kind:  "markdown",
			Value: doc,
		},
		InsertTextFormat: &kindPlain,
	}
}

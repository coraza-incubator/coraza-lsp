// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

// Package knowledge provides a static, compiled-in knowledge base of SecLang
// directives, variables, operators, actions, and transformations.
//
// All lookups are O(1) via pre-built maps. No files are loaded at runtime.
// The Registry is built once at package init time and is safe for concurrent reads.
package knowledge

import "strings"

// Item describes a single SecLang language element with full documentation.
type Item struct {
	// Name is the canonical name (exact casing as used in rules).
	Name string
	// nameLower is the lowercased Name, cached at registry build time so hot-path
	// lookups and prefix filters avoid per-call strings.ToLower allocations.
	nameLower string
	// Aliases are alternative accepted spellings (e.g. "noLog" for "nolog").
	Aliases []string
	// Summary is a single-line description used in completion detail.
	Summary string
	// Description is full markdown documentation shown in hover and completion docs.
	Description string
	// Syntax is a template showing usage (e.g. `SecRule VARIABLES @OPERATOR "ACTIONS"`).
	Syntax string
	// Example is a ready-to-use example rule or directive.
	Example string
	// ActionType classifies action items: "disruptive", "metadata", "flow", "non-disruptive", "data".
	// Empty for non-action items.
	ActionType string
	// Deprecated marks items that are no longer recommended.
	Deprecated bool
}

// Registry holds pre-built lookup maps for all SecLang element types.
// All maps are keyed by lowercase name for case-insensitive lookup.
type Registry struct {
	Directives       []*Item
	DirectivesByName map[string]*Item

	Variables       []*Item
	VariablesByName map[string]*Item

	Operators       []*Item
	OperatorsByName map[string]*Item

	Actions       []*Item
	ActionsByName map[string]*Item

	Transformations       []*Item
	TransformationsByName map[string]*Item
}

// Default is the package-level Registry built at init time.
var Default = buildRegistry()

func buildRegistry() *Registry {
	r := &Registry{
		DirectivesByName:      make(map[string]*Item, len(allDirectives)),
		VariablesByName:       make(map[string]*Item, len(allVariables)),
		OperatorsByName:       make(map[string]*Item, len(allOperators)),
		ActionsByName:         make(map[string]*Item, len(allActions)),
		TransformationsByName: make(map[string]*Item, len(allTransformations)),
	}

	index(&r.Directives, &r.DirectivesByName, allDirectives)
	index(&r.Variables, &r.VariablesByName, allVariables)
	index(&r.Operators, &r.OperatorsByName, allOperators)
	index(&r.Actions, &r.ActionsByName, allActions)
	index(&r.Transformations, &r.TransformationsByName, allTransformations)

	return r
}

// index populates items and byName from src. Each Item's nameLower is cached
// once so downstream lookups and prefix filters need no further strings.ToLower.
func index(items *[]*Item, byName *map[string]*Item, src []Item) {
	for i := range src {
		item := &src[i]
		item.nameLower = strings.ToLower(item.Name)
		*items = append(*items, item)
		(*byName)[item.nameLower] = item
		for _, alias := range item.Aliases {
			(*byName)[strings.ToLower(alias)] = item
		}
	}
}

// Directive looks up a directive by name (case-insensitive). Returns nil if unknown.
func Directive(name string) *Item { return Default.DirectivesByName[strings.ToLower(name)] }

// Variable looks up a variable by name (case-insensitive). Returns nil if unknown.
func Variable(name string) *Item { return Default.VariablesByName[strings.ToLower(name)] }

// Operator looks up an operator by name (case-insensitive). Returns nil if unknown.
func Operator(name string) *Item { return Default.OperatorsByName[strings.ToLower(name)] }

// Action looks up an action by name (case-insensitive). Returns nil if unknown.
func Action(name string) *Item { return Default.ActionsByName[strings.ToLower(name)] }

// Transformation looks up a transformation by name (case-insensitive). Returns nil if unknown.
func Transformation(name string) *Item {
	return Default.TransformationsByName[strings.ToLower(name)]
}

// FilterByPrefix returns all items whose Name starts with prefix (case-insensitive).
// Uses each Item's cached nameLower — no per-item allocation in the hot path.
func FilterByPrefix(items []*Item, prefix string) []*Item {
	lower := strings.ToLower(prefix)
	result := make([]*Item, 0, len(items))
	for _, item := range items {
		if strings.HasPrefix(item.nameLower, lower) {
			result = append(result, item)
		}
	}
	return result
}

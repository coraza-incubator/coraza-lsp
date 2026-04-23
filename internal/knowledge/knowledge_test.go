// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package knowledge

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAllItemsWellFormed verifies that every item in every category
// has the required non-empty fields.
func TestAllItemsWellFormed(t *testing.T) {
	t.Parallel()

	categories := []struct {
		name  string
		items []Item
	}{
		{"directives", allDirectives},
		{"variables", allVariables},
		{"operators", allOperators},
		{"actions", allActions},
		{"transformations", allTransformations},
	}

	for _, cat := range categories {
		t.Run(cat.name, func(t *testing.T) {
			t.Parallel()
			require.NotEmpty(t, cat.items, "category must not be empty")
			for i, item := range cat.items {
				assert.NotEmpty(t, item.Name, "item[%d] must have a Name", i)
				assert.NotEmpty(t, item.Summary, "item[%d] %q must have a Summary", i, item.Name)
				assert.NotEmpty(t, item.Description, "item[%d] %q must have a Description", i, item.Name)
			}
		})
	}
}

// TestRegistryConsistency verifies that the Default registry maps and slices are in sync.
func TestRegistryConsistency(t *testing.T) {
	t.Parallel()
	r := Default

	verifyCategory(t, "directives", r.Directives, r.DirectivesByName)
	verifyCategory(t, "variables", r.Variables, r.VariablesByName)
	verifyCategory(t, "operators", r.Operators, r.OperatorsByName)
	verifyCategory(t, "actions", r.Actions, r.ActionsByName)
	verifyCategory(t, "transformations", r.Transformations, r.TransformationsByName)
}

func verifyCategory(t *testing.T, name string, items []*Item, byName map[string]*Item) {
	t.Helper()
	assert.NotEmpty(t, items, "%s: slice must not be empty", name)
	assert.NotEmpty(t, byName, "%s: map must not be empty", name)

	// Every item in the slice must be reachable by its lowercase name.
	for _, item := range items {
		key := strings.ToLower(item.Name)
		assert.Equal(t, item, byName[key], "%s: item %q not found in map by canonical name", name, item.Name)
		// Aliases must also be present.
		for _, alias := range item.Aliases {
			assert.Equal(t, item, byName[strings.ToLower(alias)],
				"%s: alias %q for item %q not found in map", name, alias, item.Name)
		}
	}

	// Every map entry must point to an item from the slice.
	sliceSet := make(map[*Item]struct{}, len(items))
	for _, item := range items {
		sliceSet[item] = struct{}{}
	}
	for key, item := range byName {
		_, ok := sliceSet[item]
		assert.True(t, ok, "%s: map key %q points to item not in slice", name, key)
	}
}

// TestRegistrySpotChecks verifies key items are present with correct content.
func TestRegistrySpotChecks(t *testing.T) {
	t.Parallel()
	r := Default

	t.Run("SecRule directive", func(t *testing.T) {
		item := r.DirectivesByName["secrule"]
		require.NotNil(t, item)
		assert.Equal(t, "SecRule", item.Name)
		assert.Contains(t, item.Syntax, "VARIABLES")
	})

	t.Run("ARGS variable", func(t *testing.T) {
		item := r.VariablesByName["args"]
		require.NotNil(t, item)
		assert.Equal(t, "ARGS", item.Name)
	})

	t.Run("rx operator", func(t *testing.T) {
		item := r.OperatorsByName["rx"]
		require.NotNil(t, item)
		assert.Contains(t, strings.ToLower(item.Summary), "regular expression")
	})

	t.Run("id action", func(t *testing.T) {
		item := r.ActionsByName["id"]
		require.NotNil(t, item)
		assert.Equal(t, "metadata", item.ActionType)
	})

	t.Run("lowercase transformation", func(t *testing.T) {
		item := r.TransformationsByName["lowercase"]
		require.NotNil(t, item)
		assert.NotEmpty(t, item.Description)
	})

	t.Run("pmFromFile alias pmf", func(t *testing.T) {
		byFull := r.OperatorsByName["pmfromfile"]
		byAlias := r.OperatorsByName["pmf"]
		require.NotNil(t, byFull)
		require.NotNil(t, byAlias)
		assert.Equal(t, byFull, byAlias, "alias must point to same item")
	})

	t.Run("normalizePath alias", func(t *testing.T) {
		byCanon := r.TransformationsByName["normalisepath"]
		byAlias := r.TransformationsByName["normalizepath"]
		require.NotNil(t, byCanon)
		require.NotNil(t, byAlias)
		assert.Equal(t, byCanon, byAlias)
	})
}

// TestNoNamesEmpty verifies no item has an empty Name.
func TestNoNamesEmpty(t *testing.T) {
	t.Parallel()
	r := Default
	for _, item := range r.Directives {
		assert.NotEmpty(t, item.Name)
	}
	for _, item := range r.Variables {
		assert.NotEmpty(t, item.Name)
	}
}

// TestFilterByPrefix verifies prefix filtering is case-insensitive.
func TestFilterByPrefix(t *testing.T) {
	t.Parallel()
	r := Default

	t.Run("lowercase prefix matches uppercase names", func(t *testing.T) {
		results := FilterByPrefix(r.Directives, "secrule")
		require.NotEmpty(t, results)
		found := false
		for _, item := range results {
			if item.Name == "SecRule" {
				found = true
			}
		}
		assert.True(t, found)
	})

	t.Run("empty prefix returns all", func(t *testing.T) {
		results := FilterByPrefix(r.Operators, "")
		assert.Equal(t, len(r.Operators), len(results))
	})

	t.Run("nonexistent prefix returns empty", func(t *testing.T) {
		results := FilterByPrefix(r.Directives, "zzznomatch")
		assert.Empty(t, results)
	})

	t.Run("partial prefix", func(t *testing.T) {
		results := FilterByPrefix(r.Actions, "ph")
		require.NotEmpty(t, results)
		for _, item := range results {
			assert.True(t, strings.HasPrefix(strings.ToLower(item.Name), "ph"),
				"item %q should start with 'ph'", item.Name)
		}
	})
}

// TestActionsHaveActionType verifies all action items have a non-empty ActionType.
func TestActionsHaveActionType(t *testing.T) {
	t.Parallel()
	for _, item := range allActions {
		assert.NotEmpty(t, item.ActionType, "action %q must have ActionType", item.Name)
		validTypes := map[string]bool{
			"disruptive":    true,
			"metadata":      true,
			"flow":          true,
			"non-disruptive": true,
			"data":          true,
		}
		assert.True(t, validTypes[item.ActionType],
			"action %q has invalid ActionType %q", item.Name, item.ActionType)
	}
}

// TestLookupHelpers exercises the case-insensitive Directive/Variable/
// Operator/Action/Transformation helpers — miss, case-insensitive hit, and
// alias hit — across all five categories.
func TestLookupHelpers(t *testing.T) {
	t.Parallel()

	pick := func(items []Item) (canonical, alias string) {
		for _, it := range items {
			if len(it.Aliases) > 0 {
				return it.Name, it.Aliases[0]
			}
		}
		if len(items) > 0 {
			return items[0].Name, ""
		}
		return "", ""
	}

	type lookup struct {
		name   string
		fn     func(string) *Item
		source []Item
	}
	kinds := []lookup{
		{"Directive", Directive, allDirectives},
		{"Variable", Variable, allVariables},
		{"Operator", Operator, allOperators},
		{"Action", Action, allActions},
		{"Transformation", Transformation, allTransformations},
	}

	for _, k := range kinds {
		t.Run(k.name, func(t *testing.T) {
			t.Parallel()
			canonical, alias := pick(k.source)
			require.NotEmpty(t, canonical, "test corpus should have at least one item")

			// Exact casing hits.
			assert.NotNil(t, k.fn(canonical), "exact name should resolve")
			// Case-insensitive hits.
			assert.NotNil(t, k.fn(strings.ToUpper(canonical)), "UPPER name should resolve")
			assert.NotNil(t, k.fn(strings.ToLower(canonical)), "lower name should resolve")
			// Miss.
			assert.Nil(t, k.fn("definitely-not-a-real-"+k.name+"-sSsS"), "garbage name should miss")
			// Empty string is a miss.
			assert.Nil(t, k.fn(""), "empty name should miss")
			// Alias resolves to the same canonical item, if any alias exists.
			if alias != "" {
				viaAlias := k.fn(alias)
				viaCanonical := k.fn(canonical)
				require.NotNil(t, viaAlias)
				assert.Same(t, viaCanonical, viaAlias, "alias and canonical should point at the same Item")
			}
		})
	}
}

// TestItem_nameLowerPopulated asserts every registered Item has its cached
// lowercased name set by the registry builder. This invariant is load-bearing
// for FilterByPrefix performance.
func TestItem_nameLowerPopulated(t *testing.T) {
	t.Parallel()

	check := func(category string, items []*Item) {
		for _, it := range items {
			assert.NotEmpty(t, it.nameLower, "%s Item %q has empty nameLower", category, it.Name)
			assert.Equal(t, strings.ToLower(it.Name), it.nameLower,
				"%s Item %q: nameLower out of sync with Name", category, it.Name)
		}
	}
	check("directives", Default.Directives)
	check("variables", Default.Variables)
	check("operators", Default.Operators)
	check("actions", Default.Actions)
	check("transformations", Default.Transformations)
}

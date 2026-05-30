package config

import "testing"

// Merge must copy the defaults' slices, not alias them — otherwise mutating a
// merged config's slice corrupts the shared defaults.
func TestMerge_CopiesDefaultSlices(t *testing.T) {
	defaults := Config{
		FilePatterns: []string{"**/*.conf"},
		Ignore:       []string{"**/.git/**"},
		IncludePaths: []string{"rules"},
	}
	var c Config
	c.Merge(defaults)

	// Mutate the merged config's slices.
	c.FilePatterns[0] = "MUTATED"
	c.Ignore[0] = "MUTATED"
	c.IncludePaths[0] = "MUTATED"

	if defaults.FilePatterns[0] != "**/*.conf" ||
		defaults.Ignore[0] != "**/.git/**" ||
		defaults.IncludePaths[0] != "rules" {
		t.Fatalf("Merge aliased defaults' slices; defaults were corrupted: %+v", defaults)
	}
}

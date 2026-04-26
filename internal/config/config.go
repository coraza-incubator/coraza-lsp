// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

// Package config defines the project-level configuration for coraza-lsp.
//
// The config lives at `.coraza.json` in the workspace root and lets users
// give the language server information it cannot derive from a single open
// file: the rule-loading entrypoint, search paths for Include resolution,
// whether to index the whole workspace or only open files, which files are
// SecLang, and per-diagnostic severity overrides.
//
// All fields are optional. A missing config is equivalent to `Default()`.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/coraza-incubator/coraza-lsp/internal/vfs"
)

// DefaultFilename is the conventional name searched for at the workspace root.
const DefaultFilename = ".coraza.json"

// Severity is the diagnostic-severity override allowed under `diagnostics`.
type Severity string

const (
	SeverityError       Severity = "error"
	SeverityWarning     Severity = "warning"
	SeverityInformation Severity = "information"
	SeverityHint        Severity = "hint"
	SeverityOff         Severity = "off"
)

func (s Severity) valid() bool {
	switch s {
	case SeverityError, SeverityWarning, SeverityInformation, SeverityHint, SeverityOff:
		return true
	}
	return false
}

// Config is the parsed `.coraza.json` document.
type Config struct {
	// Schema is the optional `$schema` URL; present only for editor tooling.
	Schema string `json:"$schema,omitempty"`

	// Entrypoint is the rule file that bootstraps the whole set (e.g.
	// "crs-setup.conf"). When set, the LSP treats it as the loading root
	// and upgrades cross-file diagnostics to real warnings/errors.
	Entrypoint string `json:"entrypoint,omitempty"`

	// IncludePaths are search roots for resolving `Include` directives,
	// evaluated in order. Relative paths are resolved against the config
	// file's directory.
	IncludePaths []string `json:"includePaths,omitempty"`

	// Global, when true, makes the server index every file matching
	// FilePatterns under the workspace, not only open documents. Enables
	// cross-file features (workspace-wide duplicate-id detection, Include
	// graph) at the cost of O(workspace) indexing on startup.
	Global bool `json:"global,omitempty"`

	// FilePatterns are doublestar globs (relative to the workspace root)
	// that should be treated as SecLang content. Defaults to `["**/*.conf"]`
	// with a "first 20 lines contain a SecLang directive" sniff.
	FilePatterns []string `json:"filePatterns,omitempty"`

	// Ignore are globs to exclude from indexing, in addition to .gitignore.
	Ignore []string `json:"ignore,omitempty"`

	// Diagnostics maps diagnostic codes (e.g. "skipafter-not-found") to a
	// severity override. Use "off" to suppress a diagnostic entirely.
	Diagnostics map[string]Severity `json:"diagnostics,omitempty"`
}

// Default returns a Config populated with the shipped defaults.
func Default() Config {
	return Config{
		FilePatterns: []string{"**/*.conf"},
		Ignore:       []string{"**/.git/**", "**/node_modules/**"},
		Diagnostics:  map[string]Severity{},
	}
}

// Merge fills zero-value fields of c from defaults. Values already set on c
// win. Slices and maps are *replaced* wholesale when non-nil on c — the file
// author gets exactly what they wrote, not an accidental concatenation.
func (c *Config) Merge(defaults Config) {
	if c.Schema == "" {
		c.Schema = defaults.Schema
	}
	if c.Entrypoint == "" {
		c.Entrypoint = defaults.Entrypoint
	}
	if c.IncludePaths == nil {
		c.IncludePaths = defaults.IncludePaths
	}
	if c.FilePatterns == nil {
		c.FilePatterns = defaults.FilePatterns
	}
	if c.Ignore == nil {
		c.Ignore = defaults.Ignore
	}
	if c.Diagnostics == nil {
		c.Diagnostics = map[string]Severity{}
	}
	for k, v := range defaults.Diagnostics {
		if _, set := c.Diagnostics[k]; !set {
			c.Diagnostics[k] = v
		}
	}
	// Global is a bool; defaults.Global == false is the sentinel; explicit
	// `"global": false` is indistinguishable from unset. That's intentional —
	// false is also the default, so both resolve the same way.
	if !c.Global {
		c.Global = defaults.Global
	}
}

// Validate reports structural problems with c. Missing files / directories
// are not fatal (workspace contents can change at runtime), so they return
// nil — only hard schema errors return non-nil. Callers that want warnings
// for missing paths should walk c directly.
func (c *Config) Validate() error {
	var errs []string

	known := knownDiagnosticCodes()
	knownSet := make(map[string]bool, len(known))
	for _, k := range known {
		knownSet[k] = true
	}
	// Validate in sorted key order so error messages are deterministic.
	keys := make([]string, 0, len(c.Diagnostics))
	for k := range c.Diagnostics {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, code := range keys {
		sev := c.Diagnostics[code]
		if len(knownSet) > 0 && !knownSet[code] {
			errs = append(errs, fmt.Sprintf("unknown diagnostic code %q", code))
		}
		if !sev.valid() {
			errs = append(errs, fmt.Sprintf(
				"invalid severity %q for %q (want one of: error, warning, information, hint, off)",
				sev, code))
		}
	}

	if len(errs) == 0 {
		return nil
	}
	return fmt.Errorf("invalid .coraza.json:\n  - %s", strings.Join(errs, "\n  - "))
}

// Load reads and parses the config at path using the OS filesystem. See
// LoadFS for the embedder-friendly variant that takes an explicit FileSystem.
func Load(path string) (*Config, error) {
	return LoadFS(vfs.OSFileSystem(), path)
}

// LoadFS reads and parses the config at path. Returns (nil, nil) if the file
// does not exist — a missing config is not an error. Returns a helpful parse
// error if the file exists but is malformed.
//
// The loader tolerates JSONC-style `"//":` comment properties at any level
// (the convention used by tsconfig.json, VS Code settings.json, etc.), so the
// commented template written by `coraza-lsp init` round-trips cleanly.
func LoadFS(filesys vfs.FileSystem, path string) (*Config, error) {
	data, err := filesys.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	cleaned, err := stripCommentProps(data)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	var c Config
	if err := json.Unmarshal(cleaned, &c); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &c, nil
}

// stripCommentProps removes every `"//"` property from every object in the
// JSON document, at every depth. Keeps the parse strictly JSON after the
// strip — Go's json.Unmarshal handles the cleaned bytes.
func stripCommentProps(data []byte) ([]byte, error) {
	var v any
	// json.Decoder keeps numbers as json.Number so we don't lose precision
	// on round-trip — not strictly needed here, but cheap insurance.
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	v = stripCommentValues(v)
	return json.Marshal(v)
}

func stripCommentValues(v any) any {
	switch t := v.(type) {
	case map[string]any:
		// A JSON object may have duplicate keys across the wire; Go collapses
		// them to the last occurrence during Decode, so we only see one "//".
		// That matches how tsconfig.json handles comments — lossy but safe.
		for k := range t {
			if k == "//" {
				delete(t, k)
				continue
			}
			t[k] = stripCommentValues(t[k])
		}
		return t
	case []any:
		for i := range t {
			t[i] = stripCommentValues(t[i])
		}
		return t
	default:
		return v
	}
}

// Discover walks from start up to the filesystem root looking for a
// DefaultFilename, using the OS filesystem. See DiscoverFS for the
// embedder-friendly variant that takes an explicit FileSystem.
func Discover(start string) string {
	return DiscoverFS(vfs.OSFileSystem(), start)
}

// DiscoverFS walks from start up to the filesystem root looking for a
// DefaultFilename. Returns the absolute path to the first one found, or ""
// if none exists. start is resolved via filepath.Abs first (a no-op for paths
// that are already absolute, including the synthetic roots embedders typically
// pass to MemFS).
func DiscoverFS(filesys vfs.FileSystem, start string) string {
	dir, err := filepath.Abs(start)
	if err != nil {
		dir = start
	}
	for {
		candidate := filepath.Join(dir, DefaultFilename)
		if info, err := filesys.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// --- known-diagnostic-codes registry ----------------------------------------
//
// The analysis package owns the canonical list of diagnostic codes. It
// registers them during its init() via RegisterDiagnosticCodes so this
// package can validate a user's severity-override map without importing
// analysis (which would create a cycle).

var (
	diagCodesMu sync.RWMutex
	diagCodes   []string
)

// RegisterDiagnosticCodes is called by internal/analysis at init time with
// its canonical list. Callers may register multiple times; the union is kept.
func RegisterDiagnosticCodes(codes ...string) {
	diagCodesMu.Lock()
	defer diagCodesMu.Unlock()
	seen := make(map[string]bool, len(diagCodes)+len(codes))
	for _, c := range diagCodes {
		seen[c] = true
	}
	for _, c := range codes {
		if !seen[c] {
			diagCodes = append(diagCodes, c)
			seen[c] = true
		}
	}
}

func knownDiagnosticCodes() []string {
	diagCodesMu.RLock()
	defer diagCodesMu.RUnlock()
	out := make([]string, len(diagCodes))
	copy(out, diagCodes)
	return out
}

// Template is the starter content written by `coraza-lsp init`. It is
// intentionally commented so users can see every option without chasing docs.
const Template = `{
  "$schema": "https://raw.githubusercontent.com/coraza-incubator/coraza-lsp/main/schema/coraza.schema.json",

  "//": "Entry rule file. When set, the LSP treats this as the canonical loading root and can confidently flag cross-file issues (e.g. missing skipAfter targets) as warnings instead of informational hints.",
  "entrypoint": "",

  "//": "Search roots for resolving Include directives. Evaluated in order.",
  "includePaths": [],

  "//": "When true, the server indexes every file matching filePatterns under the workspace, not just what is open. Enables workspace-wide duplicate rule-id detection and cross-file go-to-definition.",
  "global": false,

  "//": "Files to treat as SecLang. Defaults to **/*.conf that contain SecLang directives. Extend this if your rules live in a non-.conf extension.",
  "filePatterns": ["**/*.conf"],

  "//": "Globs to skip while indexing. Add paths that contain non-SecLang config files (e.g. nginx site configs that happen to share the .conf suffix).",
  "ignore": ["**/.git/**", "**/node_modules/**"],

  "//": "Override diagnostic severities per code. Valid values: error, warning, information, hint, off. Codes match the 'code' field in LSP diagnostics.",
  "diagnostics": {}
}
`

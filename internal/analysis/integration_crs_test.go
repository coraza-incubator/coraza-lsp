// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package analysis_test

// CRS integration test: parse every .conf and .conf.example from OWASP Core
// Rule Set and verify that the LSP produces no false-positive Stage 1 diagnostics.
//
// The test is guarded by the "integration" build tag so it is excluded from the
// normal `go test ./...` run. To execute it:
//
//	go test -tags integration ./internal/analysis/...
//	make integration
//
// If /tmp/coreruleset does not exist the test clones it automatically (depth 1).
// In CI the clone happens on first run; subsequent runs reuse the cached directory.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	protocol_3_16 "github.com/tliron/glsp/protocol_3_16"

	"github.com/coraza-incubator/coraza-lsp/internal/analysis"
	"github.com/coraza-incubator/coraza-lsp/internal/parser"
)

const (
	crsRoot    = "/tmp/coreruleset"
	crsRepoURL = "https://github.com/coreruleset/coreruleset"
)

// falsePositiveCodes are the diagnostic codes that must NEVER fire on valid
// CRS source. Cross-file warnings (skipafter-not-found) are excluded — they
// are expected in per-file analysis.
var falsePositiveCodes = map[string]bool{
	analysis.CodeParseError:            true,
	analysis.CodeMissingID:             true,
	analysis.CodeMissingPhase:          true,
	analysis.CodeInvalidID:             true,
	analysis.CodeInvalidPhase:          true,
	analysis.CodeDuplicateID:           true,
	analysis.CodeUnknownVariable:       true,
	analysis.CodeUnknownCtlOption:      true,
	analysis.CodeInvalidCtlValue:       true,
	analysis.CodeInvalidMacro:          true,
	analysis.CodeUnknownTransformation: true,
	analysis.CodeCorazaError:           true,
}

func TestCRS_NoFalsePositives(t *testing.T) {
	ensureCRS(t)

	var confFiles []string
	err := filepath.Walk(crsRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Skip util/ — contains test fixtures with intentionally invalid rules.
		if info.IsDir() && info.Name() == "util" {
			return filepath.SkipDir
		}
		if strings.HasSuffix(path, ".conf") || strings.HasSuffix(path, ".conf.example") {
			confFiles = append(confFiles, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", crsRoot, err)
	}
	if len(confFiles) == 0 {
		t.Fatalf("no .conf or .conf.example files found in %s", crsRoot)
	}

	t.Logf("Testing %d CRS files", len(confFiles))

	var totalRules int
	var failures []string

	for _, path := range confFiles {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("read %s: %v", path, err)
			continue
		}

		f := parser.Parse(path, string(src))
		diags := analysis.Analyze(f)
		diags = append(diags, analysis.ValidateWithCoraza(string(src), filepath.Dir(path))...)

		for _, n := range f.Nodes {
			if _, ok := n.(*parser.RuleNode); ok {
				totalRules++
			}
		}

		rel := strings.TrimPrefix(path, crsRoot+"/")
		for _, d := range diags {
			code := diagCode(d)
			if !falsePositiveCodes[code] {
				continue
			}
			failures = append(failures,
				fmt.Sprintf("%s:%d [%s] %s", rel, d.Range.Start.Line+1, code, d.Message))
		}
	}

	t.Logf("Analyzed %d rules across %d files", totalRules, len(confFiles))

	for _, f := range failures {
		t.Errorf("false-positive: %s", f)
	}
}

// ensureCRS clones the CRS repository to crsRoot if it does not already exist.
func ensureCRS(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(crsRoot); err == nil {
		return // already present
	}
	t.Logf("CRS not found at %s — cloning (depth 1)...", crsRoot)
	cmd := exec.Command("git", "clone", "--depth", "1", crsRepoURL, crsRoot)
	cmd.Stdout = os.Stderr // write clone progress to stderr so it's visible
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("git clone %s %s: %v", crsRepoURL, crsRoot, err)
	}
	t.Logf("CRS cloned to %s", crsRoot)
}

func diagCode(d protocol_3_16.Diagnostic) string {
	if d.Code == nil {
		return ""
	}
	s, _ := d.Code.Value.(string)
	return s
}

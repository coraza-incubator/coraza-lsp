// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"

	protocol "github.com/tliron/glsp/protocol_3_16"

	"github.com/coraza-incubator/coraza-lsp/internal/analysis"
	"github.com/coraza-incubator/coraza-lsp/internal/parser"
)

// augmentCrossFile appends workspace-wide `duplicate-id` diagnostics to the
// single-file diagnostics when `Global` is enabled. Any rule id that appears
// in the currently-analysed file AND in another indexed/open file is flagged
// on the current file, pointing at the other file.
//
// Runs only when:
//   - cfg.Global is true (the user opted into workspace-wide analysis), AND
//   - the current diagnostic code isn't user-suppressed ("off").
func (s *Server) augmentCrossFile(uri string, doc *parser.File, base []protocol.Diagnostic) []protocol.Diagnostic {
	cfg := s.Config()
	if !cfg.Global {
		return base
	}
	// Honour the user's severity override for duplicate-id. `off` → skip.
	opts := s.analysisOptions()
	if opts.SeverityOverrides != nil {
		if opts.SeverityOverrides[string(analysis.CodeDuplicateID)] == "off" {
			return base
		}
	}

	all := s.store.AllASTs()
	// Index of "id → (uri, range)" from every *other* file.
	type hit struct {
		uri string
		rng parser.Range
	}
	byID := make(map[string]hit)
	for otherURI, f := range all {
		if otherURI == uri || f == nil {
			continue
		}
		for _, n := range f.Nodes {
			rule, ok := n.(*parser.RuleNode)
			if !ok {
				continue
			}
			id := rule.FindAction("id")
			if id == nil {
				continue
			}
			if _, set := byID[id.Value]; !set {
				byID[id.Value] = hit{uri: otherURI, rng: id.Range}
			}
		}
	}
	if len(byID) == 0 {
		return base
	}

	severity := protocol.DiagnosticSeverityError
	if opts.SeverityOverrides != nil {
		if sev, ok := opts.SeverityOverrides[string(analysis.CodeDuplicateID)]; ok {
			switch sev {
			case "warning":
				severity = protocol.DiagnosticSeverityWarning
			case "information":
				severity = protocol.DiagnosticSeverityInformation
			case "hint":
				severity = protocol.DiagnosticSeverityHint
			}
		}
	}

	out := base
	for _, n := range doc.Nodes {
		rule, ok := n.(*parser.RuleNode)
		if !ok {
			continue
		}
		id := rule.FindAction("id")
		if id == nil {
			continue
		}
		other, ok := byID[id.Value]
		if !ok {
			continue
		}
		src := "coraza-lsp"
		code := protocol.IntegerOrString{Value: string(analysis.CodeDuplicateID)}
		out = append(out, protocol.Diagnostic{
			Range:    toProtocolRange(id.Range),
			Severity: &severity,
			Source:   &src,
			Code:     &code,
			Message: fmt.Sprintf(
				"duplicate rule id %s (also defined in %s)",
				id.Value, other.uri),
		})
	}
	return out
}

// toProtocolRange mirrors the private helper in internal/analysis — kept
// local here to avoid exporting it just for this one caller.
func toProtocolRange(r parser.Range) protocol.Range {
	return protocol.Range{
		Start: protocol.Position{Line: uint32(r.Start.Line), Character: uint32(r.Start.Character)},
		End:   protocol.Position{Line: uint32(r.End.Line), Character: uint32(r.End.Character)},
	}
}

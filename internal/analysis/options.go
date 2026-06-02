// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package analysis

import (
	protocol_3_16 "github.com/tliron/glsp/protocol_3_16"

	"github.com/coraza-incubator/coraza-lsp/internal/config"
)

// Options carries per-analysis preferences derived from the loaded project
// config. A zero-value Options applies the shipped defaults for every field.
type Options struct {
	// SeverityOverrides maps diagnostic codes to a user-chosen severity (from
	// `.coraza.json`'s `diagnostics` map). A value of config.SeverityOff means
	// "suppress this diagnostic entirely" and is honoured by emit().
	SeverityOverrides map[string]config.Severity

	// EntrypointAware is set by callers (pkg/lsp) when config.Entrypoint is
	// non-empty, signalling that the file is part of a complete rule set.
	//
	// NOTE: this field is not yet consumed by the analyser — the planned
	// cross-file severity promotion (escalating skipafter-not-found / unknown-
	// variable hints to warnings when an entrypoint resolves them) is not
	// implemented, and no resolvability check is performed. It is retained only
	// because pkg/lsp populates it; reading it is a future enhancement. Do not
	// rely on it to change diagnostic severities today.
	EntrypointAware bool

	// ExtraOperators is the set of additional operator names (from
	// `.coraza.json`'s `extraOperators`) that the analyser should treat as
	// known, suppressing unknown-operator diagnostics for plugin-registered
	// operators. Keys are normalised: lowercased with any leading '@' stripped
	// (operator names in the AST carry no leading '@'). A nil map is safe to
	// index and simply means "no extras".
	ExtraOperators map[string]bool

	// ExtraActions is the set of additional action names (from `.coraza.json`'s
	// `extraActions`) that the analyser should treat as known, suppressing
	// unknown-action diagnostics for plugin-registered actions. Keys are
	// lowercased. A nil map is safe to index.
	ExtraActions map[string]bool

	// ExtraTransformations is the set of additional transformation names (from
	// `.coraza.json`'s `extraTransformations`) that the analyser should treat
	// as known, suppressing unknown-transformation diagnostics for plugin-
	// registered transformations. Keys are lowercased. A nil map is safe to
	// index.
	ExtraTransformations map[string]bool
}

// DefaultOptions returns an Options value equivalent to "no user config".
func DefaultOptions() Options {
	return Options{}
}

// severity resolves the final LSP severity to emit for the given diagnostic
// code, honoring any override set on opts. The second return is false when
// the diagnostic has been suppressed ("off") and the caller should skip it.
func (o Options) severity(code string, def protocol_3_16.DiagnosticSeverity) (protocol_3_16.DiagnosticSeverity, bool) {
	if o.SeverityOverrides == nil {
		return def, true
	}
	s, ok := o.SeverityOverrides[code]
	if !ok {
		return def, true
	}
	switch s {
	case config.SeverityError:
		return protocol_3_16.DiagnosticSeverityError, true
	case config.SeverityWarning:
		return protocol_3_16.DiagnosticSeverityWarning, true
	case config.SeverityInformation:
		return protocol_3_16.DiagnosticSeverityInformation, true
	case config.SeverityHint:
		return protocol_3_16.DiagnosticSeverityHint, true
	case config.SeverityOff:
		return 0, false
	}
	return def, true
}

// apply rewrites the severity of each diagnostic according to the override
// map, dropping any marked "off". Called once as a post-processing pass
// rather than inline at each emit site — keeps the emission call sites
// unchanged and makes the behaviour exhaustive (we can't forget a site).
func (o Options) apply(diags []protocol_3_16.Diagnostic) []protocol_3_16.Diagnostic {
	if len(o.SeverityOverrides) == 0 {
		return diags
	}
	// Allocate a fresh slice rather than aliasing the caller's backing array via
	// diags[:0]: when an override drops or rewrites entries we would otherwise
	// corrupt the caller's view of the input slice.
	out := make([]protocol_3_16.Diagnostic, 0, len(diags))
	for _, d := range diags {
		code, ok := codeOf(d)
		if !ok {
			out = append(out, d)
			continue
		}
		defaultSev := protocol_3_16.DiagnosticSeverityError
		if d.Severity != nil {
			defaultSev = *d.Severity
		}
		sev, keep := o.severity(code, defaultSev)
		if !keep {
			continue
		}
		d.Severity = &sev
		out = append(out, d)
	}
	return out
}

func codeOf(d protocol_3_16.Diagnostic) (string, bool) {
	if d.Code == nil {
		return "", false
	}
	// DiagnosticCode is a string alias, so a single `case string:` is enough.
	if s, ok := d.Code.Value.(string); ok {
		return s, true
	}
	return "", false
}

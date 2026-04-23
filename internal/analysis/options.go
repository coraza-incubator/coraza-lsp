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

	// EntrypointAware is true when the analyser should treat the file as part
	// of a complete rule set (config.Entrypoint is set and resolvable).
	// Enables cross-file severities that would otherwise be softened.
	EntrypointAware bool
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
	out := diags[:0]
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

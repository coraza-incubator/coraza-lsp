// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package lsp

import (
	"github.com/coraza-incubator/coraza-lsp/internal/vfs"
)

// FileSystem is the filesystem abstraction the LSP server uses for every
// disk-touching operation: loading .coraza.json, walking the workspace
// during global indexing, sniffing files for SecLang content, and verifying
// the targets of Include directives.
//
// CLI users get OSFileSystem() by default and never need to think about this.
// Embedders that host the LSP inside a larger application — for example a web
// tool that serves rules from a database — pass a sandboxed implementation
// (such as NewMemFS) so the LSP cannot read files outside the embedder's
// intended scope.
type FileSystem = vfs.FileSystem

// OSFileSystem returns a FileSystem backed by the real OS filesystem. This is
// the default; you only need to call this directly if you want to wrap or
// compose it.
func OSFileSystem() FileSystem { return vfs.OSFileSystem() }

// NewMemFS returns an in-memory FileSystem populated from the given map of
// path → contents. Useful for tests and for embedders serving rules from a
// non-filesystem source. See vfs.NewMemFS for the path-resolution rules.
func NewMemFS(files map[string][]byte) FileSystem { return vfs.NewMemFS(files) }

// Option configures a Server. Pass options to New.
type Option func(*serverOptions)

type serverOptions struct {
	fs FileSystem
}

func defaultOptions() *serverOptions {
	return &serverOptions{fs: OSFileSystem()}
}

// WithFileSystem makes the server read all files through the given FileSystem.
// When omitted, the server uses OSFileSystem().
//
// Embedders running the LSP in a multi-tenant web application should pass a
// MemFS (or a custom FileSystem) so the LSP cannot escape the per-session
// document set. Without this, didOpen / Include resolution / workspace
// indexing all read directly from the host's disk.
func WithFileSystem(fs FileSystem) Option {
	return func(o *serverOptions) {
		if fs != nil {
			o.fs = fs
		}
	}
}

// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package lsp

import (
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/coraza-incubator/coraza-lsp/internal/parser"
	"github.com/coraza-incubator/coraza-lsp/internal/vfs"
)

// indexedFile is a parsed rule file that the user did not open in the editor.
// Only populated when config.Global is true. Unlike Document, it holds just
// the AST — the source text isn't needed for the workspace-level features we
// currently support (cross-file duplicate-id, marker index).
type indexedFile struct {
	Path string // absolute filesystem path
	AST  *parser.File
}

// indexWorkspace walks root looking for files that match `filePatterns`, are
// not excluded by `ignore`, and contain a SecLang directive in the first 20
// lines. Parsed ASTs are returned keyed by the file URI used elsewhere in the
// server.
//
// The scan is synchronous. Callers that care about UI responsiveness should
// invoke it from a goroutine (LoadConfig does when Global is true).
func indexWorkspace(filesys vfs.FileSystem, root string, filePatterns, ignore []string) map[string]*indexedFile {
	out := map[string]*indexedFile{}
	if root == "" {
		return out
	}
	_ = filesys.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d == nil {
			return nil
		}
		if d.IsDir() {
			if matchesAny(path, ignore, root) {
				return fs.SkipDir
			}
			return nil
		}
		if !matchesAny(path, filePatterns, root) {
			return nil
		}
		if matchesAny(path, ignore, root) {
			return nil
		}
		if !sniffsAsSecLang(filesys, path) {
			return nil
		}
		data, err := filesys.ReadFile(path)
		if err != nil {
			return nil
		}
		uri := "file://" + filepath.ToSlash(path)
		out[uri] = &indexedFile{
			Path: path,
			AST:  parser.Parse(uri, string(data)),
		}
		return nil
	})
	return out
}

// matchesAny reports whether path matches any of the given globs, relative to
// root. Uses filepath.Match — supports `*` and `?` but not `**`. `**/*.conf`
// is normalised to `*.conf` applied at every depth (the walk visits every
// path so this is equivalent).
func matchesAny(path string, globs []string, root string) bool {
	if len(globs) == 0 {
		return false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	rel = filepath.ToSlash(rel)
	base := filepath.Base(path)
	for _, glob := range globs {
		g := filepath.ToSlash(glob)
		// Strip a leading "**/" so the pattern matches at any depth.
		flat := strings.TrimPrefix(g, "**/")
		if ok, _ := filepath.Match(flat, base); ok {
			return true
		}
		if ok, _ := filepath.Match(g, rel); ok {
			return true
		}
		// "**/deprecated/**" on directory paths.
		if strings.Contains(g, "/**") {
			prefix := strings.TrimSuffix(strings.TrimPrefix(g, "**/"), "/**")
			if prefix != "" && strings.Contains("/"+rel+"/", "/"+prefix+"/") {
				return true
			}
		}
	}
	return false
}

// sniffsAsSecLang reads the first ~4 KB of path and returns true iff it sees
// a SecLang directive at the start of some non-comment line within the first
// 20 lines. Keeps nginx/apache/etc. .conf files out of the index.
func sniffsAsSecLang(filesys vfs.FileSystem, path string) bool {
	f, err := filesys.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 4096)
	n, _ := f.Read(buf)
	text := string(buf[:n])
	lines := strings.SplitN(text, "\n", 21)
	for i := 0; i < len(lines) && i < 20; i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// First token is the directive name.
		head := line
		if sp := strings.IndexAny(head, " \t"); sp >= 0 {
			head = head[:sp]
		}
		switch strings.ToLower(head) {
		case "secrule", "secaction", "secmarker", "secdefaultaction",
			"secruleengine", "secrequestbodyaccess", "secresponsebodyaccess",
			"secauditengine", "secauditlog", "include":
			return true
		}
	}
	return false
}

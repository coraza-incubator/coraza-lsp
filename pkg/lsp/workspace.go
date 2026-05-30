// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package lsp

import (
	"io/fs"
	"log"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/coraza-incubator/coraza-lsp/internal/parser"
	"github.com/coraza-incubator/coraza-lsp/internal/vfs"
)

// maxIndexedFileSize caps how many bytes a single workspace file may have
// before indexWorkspace skips it. Global indexing happens automatically (the
// user never opened the file), so a stray multi-hundred-MB file must not be
// slurped into memory and parsed. Files above this size are skipped with a log
// note.
const maxIndexedFileSize = 4 << 20 // 4 MiB

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
		// Skip pathologically large files: global indexing is automatic, so a
		// stray huge .conf must not be read whole into memory and parsed.
		if info, ierr := d.Info(); ierr == nil && info.Size() > maxIndexedFileSize {
			log.Printf("coraza-lsp: skipping %s from workspace index (%d bytes > %d)", path, info.Size(), maxIndexedFileSize)
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
// root. Globs use doublestar semantics (github.com/bmatcuk/doublestar): `*`
// and `?` within a path segment, `**` to match across path separators, and
// `{a,b}` brace alternation — matching the behaviour documented for
// `filePatterns`/`ignore` in internal/config. Matching is always performed on
// the slash-separated path relative to root so patterns like `**/*.conf` and
// `**/deprecated/**` work regardless of OS.
//
// Patterns are matched against both the relative path and the base name, so a
// bare `*.conf` (no leading `**/`) still matches a nested file as the docs
// imply. Malformed patterns are skipped (they cannot match) rather than
// silently aborting the whole walk.
func matchesAny(path string, globs []string, root string) bool {
	if len(globs) == 0 {
		return false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		rel = path
	}
	rel = filepath.ToSlash(rel)
	base := filepath.ToSlash(filepath.Base(path))
	for _, glob := range globs {
		g := filepath.ToSlash(glob)
		if !doublestar.ValidatePattern(g) {
			// Malformed glob: cannot match anything; ignore it so one bad
			// entry can't short-circuit indexing.
			continue
		}
		if ok, _ := doublestar.Match(g, rel); ok {
			return true
		}
		// A pattern without a `**`/`/` prefix (e.g. "*.conf") is conventionally
		// understood to apply at any depth; match it against the base name too.
		if !strings.Contains(g, "/") {
			if ok, _ := doublestar.Match(g, base); ok {
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

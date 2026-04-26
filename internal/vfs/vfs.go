// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

// Package vfs is the filesystem abstraction used by every coraza-lsp component
// that reads from disk. The CLI server uses OSFileSystem (the default).
// Embedders that host the LSP inside a larger application (e.g. a web tool
// serving rules from a database) pass a sandboxed implementation so the LSP
// cannot read files outside the embedder's intended scope.
package vfs

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// FileSystem is the minimal surface coraza-lsp needs from a filesystem.
// All paths are interpreted by the implementation — OSFileSystem treats them
// as native paths; MemFS treats them as virtual paths in its internal map.
type FileSystem interface {
	Open(name string) (io.ReadCloser, error)
	ReadFile(name string) ([]byte, error)
	Stat(name string) (fs.FileInfo, error)
	WalkDir(root string, fn fs.WalkDirFunc) error
}

// OSFileSystem returns a FileSystem backed by the real OS filesystem. This is
// the default when no WithFileSystem option is passed to lsp.New.
func OSFileSystem() FileSystem { return osFS{} }

type osFS struct{}

func (osFS) Open(name string) (io.ReadCloser, error) { return os.Open(name) }
func (osFS) ReadFile(name string) ([]byte, error)    { return os.ReadFile(name) }
func (osFS) Stat(name string) (fs.FileInfo, error)   { return os.Stat(name) }
func (osFS) WalkDir(root string, fn fs.WalkDirFunc) error {
	return filepath.WalkDir(root, fn)
}

// NewMemFS returns a FileSystem backed by an in-memory map of path → contents.
// Paths are virtual — they need not correspond to anything on disk. Useful for
// tests and for embedders serving rules from a database. The map is copied at
// construction time; later mutations to the caller's map have no effect.
//
// WalkDir treats the map's keys as a flat list of files and synthesises the
// directories implied by their path components. Directories are visited
// before their children, in lexical order.
func NewMemFS(files map[string][]byte) FileSystem {
	cp := make(map[string][]byte, len(files))
	for k, v := range files {
		cp[normalize(k)] = append([]byte(nil), v...)
	}
	return &memFS{files: cp}
}

type memFS struct {
	files map[string][]byte // key: cleaned slash-path, no leading slash
}

// ErrNotExist mirrors os.ErrNotExist for consumers using errors.Is.
var ErrNotExist = fs.ErrNotExist

// normalize converts a host-style path to a slash-separated, cleaned form.
// Leading slashes are preserved so that absolute paths the embedder used as
// map keys round-trip identically through WalkDir / Stat / ReadFile.
func normalize(p string) string {
	p = filepath.ToSlash(p)
	abs := strings.HasPrefix(p, "/")
	cleaned := path.Clean(strings.TrimPrefix(p, "/"))
	if abs {
		return "/" + cleaned
	}
	return cleaned
}

func (m *memFS) Open(name string) (io.ReadCloser, error) {
	data, err := m.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (m *memFS) ReadFile(name string) ([]byte, error) {
	data, ok := m.files[normalize(name)]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: ErrNotExist}
	}
	return append([]byte(nil), data...), nil
}

func (m *memFS) Stat(name string) (fs.FileInfo, error) {
	key := normalize(name)
	if data, ok := m.files[key]; ok {
		return memFileInfo{name: path.Base(key), size: int64(len(data)), dir: false}, nil
	}
	// Treat any prefix of an existing file's path as a directory.
	prefix := key + "/"
	for k := range m.files {
		if strings.HasPrefix(k, prefix) {
			return memFileInfo{name: path.Base(key), dir: true}, nil
		}
	}
	if key == "." || key == "" {
		return memFileInfo{name: ".", dir: true}, nil
	}
	return nil, &fs.PathError{Op: "stat", Path: name, Err: ErrNotExist}
}

// WalkDir visits root and every entry beneath it in lexical order. Both files
// and synthesised directories are visited; the WalkDirFunc receives a DirEntry
// whose IsDir reflects the synthesised directory structure.
func (m *memFS) WalkDir(root string, fn fs.WalkDirFunc) error {
	rootKey := normalize(root)

	// Collect keys under root and synthesised intermediate directories.
	dirs := map[string]struct{}{}
	files := []string{}
	prefix := rootKey + "/"
	if rootKey == "." || rootKey == "" {
		prefix = ""
	}
	for k := range m.files {
		if prefix != "" && !strings.HasPrefix(k, prefix) {
			continue
		}
		files = append(files, k)
		// Synthesise every parent directory back up to (and including) the root.
		dir := path.Dir(k)
		for dir != "." && dir != "/" {
			if prefix != "" && !strings.HasPrefix(dir+"/", prefix) && dir != rootKey {
				break
			}
			dirs[dir] = struct{}{}
			if dir == rootKey {
				break
			}
			dir = path.Dir(dir)
		}
	}
	dirs[rootKey] = struct{}{}

	all := make([]string, 0, len(files)+len(dirs))
	for d := range dirs {
		all = append(all, d)
	}
	all = append(all, files...)
	sort.Strings(all)

	dedup := all[:0]
	var prev string
	for _, p := range all {
		if p == prev {
			continue
		}
		dedup = append(dedup, p)
		prev = p
	}

	// skipPrefix tracks a directory path the caller asked us to skip via
	// fs.SkipDir. Any subsequent entry that lives under it is dropped — the
	// stdlib's filepath.WalkDir does the same.
	skipPrefix := ""

	for _, p := range dedup {
		if skipPrefix != "" && strings.HasPrefix(p, skipPrefix) {
			continue
		}
		skipPrefix = ""
		_, isDir := dirs[p]
		entry := memDirEntry{name: path.Base(p), dir: isDir}
		walkPath := p
		if walkPath == "" {
			walkPath = "."
		}
		if err := fn(walkPath, entry, nil); err != nil {
			if errors.Is(err, fs.SkipAll) {
				return nil
			}
			if errors.Is(err, fs.SkipDir) {
				if isDir {
					skipPrefix = p + "/"
				}
				continue
			}
			return err
		}
	}
	return nil
}

type memFileInfo struct {
	name string
	size int64
	dir  bool
}

func (i memFileInfo) Name() string       { return i.name }
func (i memFileInfo) Size() int64        { return i.size }
func (i memFileInfo) Mode() os.FileMode  { return 0o444 }
func (i memFileInfo) ModTime() time.Time { return time.Time{} }
func (i memFileInfo) IsDir() bool        { return i.dir }
func (i memFileInfo) Sys() any           { return nil }

type memDirEntry struct {
	name string
	dir  bool
}

func (e memDirEntry) Name() string               { return e.name }
func (e memDirEntry) IsDir() bool                { return e.dir }
func (e memDirEntry) Type() fs.FileMode          { return 0 }
func (e memDirEntry) Info() (fs.FileInfo, error) { return memFileInfo{name: e.name, dir: e.dir}, nil }

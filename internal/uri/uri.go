// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

// Package uri converts between LSP `file://` document URIs and native OS paths.
//
// This is the single place that gets the cross-platform mapping right. The naive
// approach (strings.TrimPrefix(uri, "file://") and "file://"+path) breaks on
// Windows, where a URI is file:///C:/dir/x and the OS path is C:\dir\x: the
// concatenation form would emit a malformed file://C:\dir\x and the trim form
// would yield /C:/dir/x. It also ignores percent-encoding (e.g. %20 for spaces).
package uri

import (
	"net/url"
	"path/filepath"
	"strings"
)

// ToPath converts a file:// URI to a native OS filesystem path. A value that is
// not a file:// URI is returned unchanged (treated as already a path).
func ToPath(uri string) string {
	if !strings.HasPrefix(uri, "file://") {
		return uri
	}
	u, err := url.Parse(uri)
	if err != nil {
		return uri
	}
	p := u.Path // already percent-decoded by url.Parse
	// Windows: file:///C:/dir → u.Path is "/C:/dir"; drop the leading slash so
	// VolumeName sees "C:".
	if filepath.VolumeName(strings.TrimPrefix(p, "/")) != "" {
		p = strings.TrimPrefix(p, "/")
	}
	return filepath.FromSlash(p)
}

// ToURI converts a native OS filesystem path to a well-formed file:// URI.
// A value that already looks like a file:// URI is returned unchanged.
func ToURI(path string) string {
	if strings.HasPrefix(path, "file://") {
		return path
	}
	slash := filepath.ToSlash(path)
	// Absolute Windows paths (C:/dir) need an extra leading slash: file:///C:/dir.
	if !strings.HasPrefix(slash, "/") {
		slash = "/" + slash
	}
	u := url.URL{Scheme: "file", Path: slash}
	return u.String()
}

// Dir returns the directory of a file:// URI (or path) as a native OS path.
func Dir(uri string) string {
	return filepath.Dir(ToPath(uri))
}

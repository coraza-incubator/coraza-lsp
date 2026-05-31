// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package vfs_test

import (
	"errors"
	"io"
	"io/fs"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coraza-incubator/coraza-lsp/internal/vfs"
)

func TestOSFileSystem_StatTmp(t *testing.T) {
	t.Parallel()
	osfs := vfs.OSFileSystem()
	info, err := osfs.Stat("/tmp")
	if err != nil {
		t.Skip("system has no /tmp; OSFileSystem still functional via other paths")
	}
	assert.True(t, info.IsDir())
}

func TestMemFS_ReadFile_HitAndMiss(t *testing.T) {
	t.Parallel()
	mem := vfs.NewMemFS(map[string][]byte{
		"/policy/main.conf": []byte("SecRuleEngine On"),
	})

	got, err := mem.ReadFile("/policy/main.conf")
	require.NoError(t, err)
	assert.Equal(t, "SecRuleEngine On", string(got))

	_, err = mem.ReadFile("/nope")
	assert.True(t, errors.Is(err, fs.ErrNotExist))
}

func TestMemFS_Open_Closes(t *testing.T) {
	t.Parallel()
	mem := vfs.NewMemFS(map[string][]byte{
		"/a.conf": []byte("hello"),
	})
	rc, err := mem.Open("/a.conf")
	require.NoError(t, err)
	defer func() { _ = rc.Close() }()

	data, err := io.ReadAll(rc)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(data))
}

func TestMemFS_Stat_DirAndFile(t *testing.T) {
	t.Parallel()
	mem := vfs.NewMemFS(map[string][]byte{
		"/policy/rules/a.conf": []byte("x"),
	})

	info, err := mem.Stat("/policy/rules/a.conf")
	require.NoError(t, err)
	assert.False(t, info.IsDir())
	assert.Equal(t, int64(1), info.Size())

	dir, err := mem.Stat("/policy/rules")
	require.NoError(t, err)
	assert.True(t, dir.IsDir())
}

func TestMemFS_WalkDir_VisitsFilesAndSyntheticDirs(t *testing.T) {
	t.Parallel()
	mem := vfs.NewMemFS(map[string][]byte{
		"/root/a.conf":     []byte("a"),
		"/root/sub/b.conf": []byte("b"),
		"/root/sub/c.conf": []byte("c"),
	})

	var visited []string
	require.NoError(t, mem.WalkDir("/root", func(p string, d fs.DirEntry, err error) error {
		require.NoError(t, err)
		visited = append(visited, p)
		return nil
	}))

	sort.Strings(visited)
	assert.Contains(t, visited, "/root")
	assert.Contains(t, visited, "/root/sub")
	assert.Contains(t, visited, "/root/a.conf")
	assert.Contains(t, visited, "/root/sub/b.conf")
	assert.Contains(t, visited, "/root/sub/c.conf")
}

func TestMemFS_WalkDir_SkipDir(t *testing.T) {
	t.Parallel()
	mem := vfs.NewMemFS(map[string][]byte{
		"/root/keep.conf":          []byte("k"),
		"/root/skip/buried.conf":   []byte("b"),
		"/root/skip/deeper/x.conf": []byte("x"),
	})

	var visited []string
	require.NoError(t, mem.WalkDir("/root", func(p string, d fs.DirEntry, err error) error {
		visited = append(visited, p)
		if d != nil && d.IsDir() && p == "/root/skip" {
			return fs.SkipDir
		}
		return nil
	}))

	for _, p := range visited {
		assert.NotContains(t, p, "buried.conf",
			"SkipDir should have prevented walking into /root/skip")
	}
}

func TestMemFS_DefensiveCopy(t *testing.T) {
	t.Parallel()
	src := map[string][]byte{
		"/a.conf": []byte("original"),
	}
	mem := vfs.NewMemFS(src)

	// Mutating the input map after construction must not change MemFS.
	src["/a.conf"] = []byte("mutated")
	src["/b.conf"] = []byte("new")

	got, err := mem.ReadFile("/a.conf")
	require.NoError(t, err)
	assert.Equal(t, "original", string(got))

	_, err = mem.ReadFile("/b.conf")
	assert.True(t, errors.Is(err, fs.ErrNotExist))
}

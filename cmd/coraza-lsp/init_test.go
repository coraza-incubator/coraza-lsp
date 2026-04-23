// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coraza-incubator/coraza-lsp/internal/config"
)

func TestRunInit_FreshWrite(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	var out bytes.Buffer
	require.NoError(t, runInit([]string{"--path", dir}, &out))

	dest := filepath.Join(dir, config.DefaultFilename)
	data, err := os.ReadFile(dest)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"filePatterns"`)
	assert.Contains(t, out.String(), dest)

	// Round-trip: the file we just wrote must parse cleanly.
	loaded, err := config.Load(dest)
	require.NoError(t, err)
	require.NotNil(t, loaded)
}

func TestRunInit_RefusesOverwrite(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dest := filepath.Join(dir, config.DefaultFilename)
	require.NoError(t, os.WriteFile(dest, []byte(`{"entrypoint": "keep me"}`), 0o644))

	var out bytes.Buffer
	err := runInit([]string{"--path", dir}, &out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")

	// Untouched.
	data, _ := os.ReadFile(dest)
	assert.Contains(t, string(data), "keep me")
}

func TestRunInit_ForceOverwrites(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dest := filepath.Join(dir, config.DefaultFilename)
	require.NoError(t, os.WriteFile(dest, []byte(`{"entrypoint": "overwritten"}`), 0o644))

	var out bytes.Buffer
	require.NoError(t, runInit([]string{"--path", dir, "--force"}, &out))

	data, _ := os.ReadFile(dest)
	assert.NotContains(t, string(data), "overwritten")
	assert.Contains(t, string(data), `"filePatterns"`)
}

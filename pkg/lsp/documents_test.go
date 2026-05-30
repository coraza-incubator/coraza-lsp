// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package lsp

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/coraza-incubator/coraza-lsp/internal/parser"
)

func TestDocumentStore_OpenAndGet(t *testing.T) {
	t.Parallel()
	s := NewDocumentStore()
	doc := s.Open("file:///a.conf", "SecRuleEngine On", 1)
	require.NotNil(t, doc)
	assert.Equal(t, "file:///a.conf", doc.URI)
	assert.Equal(t, int32(1), doc.Version)
	assert.Equal(t, "SecRuleEngine On", doc.Content)
	require.NotNil(t, doc.AST)

	got := s.Get("file:///a.conf")
	require.NotNil(t, got)
	assert.Equal(t, doc.Content, got.Content)
}

func TestDocumentStore_GetMissing(t *testing.T) {
	t.Parallel()
	s := NewDocumentStore()
	assert.Nil(t, s.Get("file:///nonexistent.conf"))
}

func TestDocumentStore_Change(t *testing.T) {
	t.Parallel()
	s := NewDocumentStore()
	s.Open("file:///a.conf", "SecRuleEngine On", 1)
	doc := s.Change("file:///a.conf", "SecRuleEngine Off", 2)
	require.NotNil(t, doc)
	assert.Equal(t, "SecRuleEngine Off", doc.Content)
	assert.Equal(t, int32(2), doc.Version)

	// The stored version should reflect the change.
	got := s.Get("file:///a.conf")
	require.NotNil(t, got)
	assert.Equal(t, "SecRuleEngine Off", got.Content)
}

func TestDocumentStore_Close(t *testing.T) {
	t.Parallel()
	s := NewDocumentStore()
	s.Open("file:///a.conf", "SecRuleEngine On", 1)
	s.Close("file:///a.conf")
	assert.Nil(t, s.Get("file:///a.conf"))
}

func TestDocumentStore_CloseNonExistent(t *testing.T) {
	t.Parallel()
	s := NewDocumentStore()
	// Should not panic.
	s.Close("file:///nonexistent.conf")
}

func TestDocumentStore_All(t *testing.T) {
	t.Parallel()
	s := NewDocumentStore()
	s.Open("file:///a.conf", "SecRuleEngine On", 1)
	s.Open("file:///b.conf", "SecRuleEngine Off", 1)

	all := s.All()
	assert.Len(t, all, 2)
	assert.NotNil(t, all["file:///a.conf"])
	assert.NotNil(t, all["file:///b.conf"])
}

func TestDocumentStore_AllAfterClose(t *testing.T) {
	t.Parallel()
	s := NewDocumentStore()
	s.Open("file:///a.conf", "SecRuleEngine On", 1)
	s.Open("file:///b.conf", "SecRuleEngine Off", 1)
	s.Close("file:///a.conf")

	all := s.All()
	assert.Len(t, all, 1)
	assert.NotNil(t, all["file:///b.conf"])
}

func TestDocumentStore_ASTCached(t *testing.T) {
	t.Parallel()
	s := NewDocumentStore()
	src := `SecRule ARGS "@rx x" "id:1001,phase:2,deny"`
	doc := s.Open("file:///a.conf", src, 1)
	require.NotNil(t, doc.AST)
	rules := doc.AST.AllRules()
	assert.Len(t, rules, 1)
}

func TestDocumentStore_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	s := NewDocumentStore()
	const n = 50
	// Mix every mutating and reading entry point on overlapping URIs so the
	// race detector exercises the read-copy-out contract on AllDocs/All/AllASTs
	// and the cross-file id cache (SetIndex/CrossFileIDs) interleaved with
	// Open/Change/Close.
	const workers = 9
	done := make(chan struct{}, n*workers)
	src := `SecRule ARGS "@rx x" "id:%d,phase:2,deny"`

	for i := 0; i < n; i++ {
		i := i
		go func() { s.Open("file:///a.conf", "SecRuleEngine On", int32(i)); done <- struct{}{} }()
		go func() {
			s.Change("file:///b.conf", "SecRule ARGS \"@rx y\" \"id:42,phase:2,deny\"", int32(i))
			done <- struct{}{}
		}()
		go func() { s.Close("file:///a.conf"); done <- struct{}{} }()
		go func() { s.Get("file:///a.conf"); done <- struct{}{} }()
		go func() { _ = s.AllDocs(); done <- struct{}{} }()
		go func() { _ = s.All(); done <- struct{}{} }()
		go func() { _ = s.AllASTs(); done <- struct{}{} }()
		go func() { _ = s.CrossFileIDs(); done <- struct{}{} }()
		go func() {
			f := parser.Parse("file:///idx.conf", fmt.Sprintf(src, 42))
			s.SetIndex(map[string]*indexedFile{
				"file:///idx.conf": {Path: "/idx.conf", AST: f},
				"file:///b.conf":   {Path: "/b.conf", AST: f},
			})
			done <- struct{}{}
		}()
	}
	for i := 0; i < n*workers; i++ {
		<-done
	}
}

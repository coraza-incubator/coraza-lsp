// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

// Package server implements the LSP server handler and document store.
package server

import (
	"sync"

	"github.com/coraza-incubator/coraza-lsp/internal/parser"
)

// Document holds the current state of an open text document.
type Document struct {
	URI     string
	Version int32
	Content string
	AST     *parser.File
}

// DocumentStore is a thread-safe store for open LSP documents.
// It uses full document synchronisation (TextDocumentSyncKindFull):
// every change event replaces the entire content.
type DocumentStore struct {
	mu   sync.RWMutex
	docs map[string]*Document
}

// NewDocumentStore returns an empty DocumentStore.
func NewDocumentStore() *DocumentStore {
	return &DocumentStore{docs: make(map[string]*Document)}
}

// Open adds or replaces a document.
func (s *DocumentStore) Open(uri, content string, version int32) *Document {
	doc := &Document{
		URI:     uri,
		Version: version,
		Content: content,
		AST:     parser.Parse(uri, content),
	}
	s.mu.Lock()
	s.docs[uri] = doc
	s.mu.Unlock()
	return doc
}

// Change replaces the content of an existing document and re-parses its AST.
// If the document is not yet open, it is created.
func (s *DocumentStore) Change(uri, content string, version int32) *Document {
	return s.Open(uri, content, version)
}

// Close removes a document from the store.
func (s *DocumentStore) Close(uri string) {
	s.mu.Lock()
	delete(s.docs, uri)
	s.mu.Unlock()
}

// Get returns the document for the given URI, or nil if not open.
func (s *DocumentStore) Get(uri string) *Document {
	s.mu.RLock()
	doc := s.docs[uri]
	s.mu.RUnlock()
	return doc
}

// All returns a snapshot of all open documents as a map URI→*parser.File.
// The returned map is a new copy and safe to iterate without holding the lock.
func (s *DocumentStore) All() map[string]*parser.File {
	s.mu.RLock()
	out := make(map[string]*parser.File, len(s.docs))
	for uri, doc := range s.docs {
		out[uri] = doc.AST
	}
	s.mu.RUnlock()
	return out
}

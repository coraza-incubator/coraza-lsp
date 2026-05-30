// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

// Package server implements the LSP server handler and document store.
package lsp

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
	// Lines is Content split on "\n", computed once at Open time so per-request
	// features (completion) don't re-split the whole document on every call.
	Lines []string
}

// DocumentStore is a thread-safe store for open LSP documents plus, when
// `config.Global` is true, indexed (closed) rule files from the workspace.
// Both are kept so cross-file features (workspace-wide duplicate-id, marker
// resolution across files) can see the complete set without the user having
// to open every file.
type DocumentStore struct {
	mu      sync.RWMutex
	docs    map[string]*Document
	indexed map[string]*indexedFile // populated by SetIndex when Global is true

	// ruleIDs caches each file's rule-id → Range contribution, computed once
	// when the file's AST changes (Open/Change/SetIndex) rather than rescanned
	// on every cross-file diagnostic run. Keyed by URI; open docs override
	// indexed files with the same URI (handled at merge time below).
	ruleIDs    map[string]map[string]parser.Range
	xfGen      uint64                      // bumped whenever ruleIDs changes
	xfCacheGen uint64                      // generation xfCache was built at
	xfCache    map[string]crossFileIDEntry // merged id → up-to-two locations
}

// crossFileIDEntry records, for one rule id, where it is defined across the
// whole workspace: the count of distinct files plus up to two (uri, range)
// samples so augmentCrossFile can report an "other" file even when the current
// file is one of the definers.
type crossFileIDEntry struct {
	count int
	uri1  string
	rng1  parser.Range
	uri2  string
	rng2  parser.Range
}

// NewDocumentStore returns an empty DocumentStore.
func NewDocumentStore() *DocumentStore {
	return &DocumentStore{
		docs:    make(map[string]*Document),
		indexed: make(map[string]*indexedFile),
		ruleIDs: make(map[string]map[string]parser.Range),
	}
}

// ruleIDsFromAST extracts the rule-id → id-action Range map from a parsed file.
// First definition of a given id within the file wins (mirrors the previous
// augmentCrossFile behaviour).
func ruleIDsFromAST(f *parser.File) map[string]parser.Range {
	if f == nil {
		return nil
	}
	var ids map[string]parser.Range
	for _, n := range f.Nodes {
		rule, ok := n.(*parser.RuleNode)
		if !ok {
			continue
		}
		id := rule.FindAction("id")
		if id == nil {
			continue
		}
		if ids == nil {
			ids = make(map[string]parser.Range)
		}
		if _, set := ids[id.Value]; !set {
			ids[id.Value] = id.Range
		}
	}
	return ids
}

// setRuleIDs records a file's id contribution and invalidates the merged
// cache. Caller must hold mu.
func (s *DocumentStore) setRuleIDs(uri string, f *parser.File) {
	ids := ruleIDsFromAST(f)
	if ids == nil {
		delete(s.ruleIDs, uri)
	} else {
		s.ruleIDs[uri] = ids
	}
	s.xfGen++
}

// CrossFileIDs returns, for each rule id known across the workspace, where it
// is defined (count + sample locations). The merged map is cached and only
// rebuilt when a file's id set changes, so the common case (repeated diagnostic
// runs between edits) is O(1) plus a copy. Open documents shadow indexed files
// with the same URI because Open/SetIndex feed the same ruleIDs map keyed by
// URI.
func (s *DocumentStore) CrossFileIDs() map[string]crossFileIDEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.xfCache == nil || s.xfCacheGen != s.xfGen {
		merged := make(map[string]crossFileIDEntry)
		for uri, ids := range s.ruleIDs {
			for id, rng := range ids {
				e := merged[id]
				e.count++
				switch e.count {
				case 1:
					e.uri1, e.rng1 = uri, rng
				case 2:
					e.uri2, e.rng2 = uri, rng
				}
				merged[id] = e
			}
		}
		s.xfCache = merged
		s.xfCacheGen = s.xfGen
	}
	// Return a copy so callers can read it without holding the lock.
	out := make(map[string]crossFileIDEntry, len(s.xfCache))
	for id, e := range s.xfCache {
		out[id] = e
	}
	return out
}

// SetIndex replaces the indexed (closed-file) set wholesale. Called by the
// workspace scanner after LoadConfig / after a config reload.
func (s *DocumentStore) SetIndex(idx map[string]*indexedFile) {
	s.mu.Lock()
	// Drop id contributions from the previous indexed-only set, keeping those
	// from currently-open docs (which are re-added below if also indexed).
	for uri := range s.indexed {
		if _, open := s.docs[uri]; !open {
			delete(s.ruleIDs, uri)
		}
	}
	if idx == nil {
		s.indexed = make(map[string]*indexedFile)
	} else {
		s.indexed = idx
	}
	for uri, f := range s.indexed {
		// Open docs win over the on-disk snapshot for the same URI.
		if _, open := s.docs[uri]; open {
			continue
		}
		s.setRuleIDs(uri, f.AST)
	}
	s.xfGen++ // ensure the cache rebuilds even if no per-file set changed
	s.mu.Unlock()
}

// AllASTs returns every known AST — open documents override any indexed file
// with the same URI so edits win over the on-disk snapshot.
func (s *DocumentStore) AllASTs() map[string]*parser.File {
	s.mu.RLock()
	out := make(map[string]*parser.File, len(s.docs)+len(s.indexed))
	for uri, f := range s.indexed {
		out[uri] = f.AST
	}
	for uri, doc := range s.docs {
		out[uri] = doc.AST
	}
	s.mu.RUnlock()
	return out
}

// Open adds or replaces a document.
func (s *DocumentStore) Open(uri, content string, version int32) *Document {
	doc := &Document{
		URI:     uri,
		Version: version,
		Content: content,
		AST:     parser.Parse(uri, content),
		Lines:   splitLines(content),
	}
	s.mu.Lock()
	s.docs[uri] = doc
	s.setRuleIDs(uri, doc.AST)
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
	// If the file is still in the indexed (on-disk) set, fall back to that
	// snapshot's id contribution; otherwise drop it entirely.
	if f, ok := s.indexed[uri]; ok {
		s.setRuleIDs(uri, f.AST)
	} else {
		s.setRuleIDs(uri, nil)
	}
	s.mu.Unlock()
}

// Get returns the document for the given URI, or nil if not open.
func (s *DocumentStore) Get(uri string) *Document {
	s.mu.RLock()
	doc := s.docs[uri]
	s.mu.RUnlock()
	return doc
}

// AllDocs returns a snapshot of all open documents keyed by URI. The map is a
// new copy, safe to iterate without holding the lock; the *Document values
// are shared pointers to the live store state — callers must treat them as
// read-only.
func (s *DocumentStore) AllDocs() map[string]*Document {
	s.mu.RLock()
	out := make(map[string]*Document, len(s.docs))
	for uri, doc := range s.docs {
		out[uri] = doc
	}
	s.mu.RUnlock()
	return out
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

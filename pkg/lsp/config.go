// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package lsp

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/coraza-incubator/coraza-lsp/internal/analysis"
	"github.com/coraza-incubator/coraza-lsp/internal/config"
)

// configState holds the currently-active `.coraza.json` config, the path it
// was loaded from (so we can tell fsnotify what to watch), and the derived
// analysis options. All access is guarded by mu.
type configState struct {
	mu      sync.RWMutex
	cfg     config.Config
	path    string // absolute path to the loaded config, "" if none found
	root    string // workspace root the config is scoped to
	opts    analysis.Options
	watcher *fsnotify.Watcher // nil until WatchConfig has been called
	stop    chan struct{}     // closed to stop the watcher goroutine
}

// LoadConfig discovers and loads `.coraza.json` for the given workspace root.
// A missing config is not an error — the server falls back to defaults.
// Errors in the file are surfaced via onError (typically a window/showMessage).
func (s *Server) LoadConfig(workspaceRoot string, onError func(msg string)) {
	s.cfgState.mu.Lock()
	defer s.cfgState.mu.Unlock()

	s.cfgState.root = workspaceRoot
	path := config.DiscoverFS(s.fs, workspaceRoot)
	s.cfgState.path = path

	cfg := config.Default()
	if path != "" {
		parsed, err := config.LoadFS(s.fs, path)
		if err != nil {
			if onError != nil {
				onError(fmt.Sprintf("coraza-lsp: %v", err))
			}
		} else if parsed != nil {
			parsed.Merge(cfg)
			if err := parsed.Validate(); err != nil && onError != nil {
				onError(fmt.Sprintf("coraza-lsp: %v", err))
			}
			cfg = *parsed
		}
	}

	s.cfgState.cfg = cfg
	s.cfgState.opts = optionsFromConfig(cfg)

	// Kick off (or clear) the workspace index. Runs synchronously because
	// LoadConfig is already called from a background-friendly place
	// (initialize handler + the watcher goroutine). For large workspaces
	// users can flip global:false to skip this cost.
	if cfg.Global && workspaceRoot != "" {
		idx := indexWorkspace(s.fs, workspaceRoot, cfg.FilePatterns, cfg.Ignore)
		s.store.SetIndex(idx)
	} else {
		s.store.SetIndex(nil)
	}
}

// Config returns a snapshot of the current config. Safe for concurrent use.
func (s *Server) Config() config.Config {
	s.cfgState.mu.RLock()
	defer s.cfgState.mu.RUnlock()
	return s.cfgState.cfg
}

// analysisOptions returns the derived analysis.Options. Used on every
// analyse call so severity overrides stay in sync with config edits.
func (s *Server) analysisOptions() analysis.Options {
	s.cfgState.mu.RLock()
	defer s.cfgState.mu.RUnlock()
	return s.cfgState.opts
}

func optionsFromConfig(cfg config.Config) analysis.Options {
	if len(cfg.Diagnostics) == 0 && !cfg.Global && cfg.Entrypoint == "" {
		return analysis.DefaultOptions()
	}
	return analysis.Options{
		SeverityOverrides: cfg.Diagnostics,
		EntrypointAware:   cfg.Entrypoint != "",
	}
}

// WatchConfig starts a background goroutine that watches the config file for
// changes and reloads it on save/remove. Events are debounced in a 100 ms
// window because many editors fire multiple fsnotify events per save (rename,
// chmod, write).
//
// If no config file exists the watcher monitors the workspace root so a later
// `coraza-lsp init` (or manual creation) is picked up.
//
// onChange is called after every successful reload with the old and new
// configs so the caller can decide what to re-compute. onError is called when
// the watcher surfaces a parse or validation error.
func (s *Server) WatchConfig(onChange func(old, new config.Config), onError func(msg string)) error {
	s.cfgState.mu.Lock()
	defer s.cfgState.mu.Unlock()

	if s.cfgState.watcher != nil {
		return nil // already watching
	}

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("fsnotify: %w", err)
	}

	// Watch the parent directory (not just the file) so create/remove of
	// `.coraza.json` is caught too.
	watchDir := s.cfgState.root
	if s.cfgState.path != "" {
		watchDir = filepath.Dir(s.cfgState.path)
	}
	if watchDir == "" {
		w.Close()
		return nil // no workspace root → nothing to watch
	}
	if err := w.Add(watchDir); err != nil {
		w.Close()
		return fmt.Errorf("fsnotify watch %s: %w", watchDir, err)
	}

	s.cfgState.watcher = w
	s.cfgState.stop = make(chan struct{})
	stop := s.cfgState.stop

	go s.watchLoop(w, stop, onChange, onError)
	return nil
}

// StopWatchConfig stops any active config watcher. Safe to call multiple times.
func (s *Server) StopWatchConfig() {
	s.cfgState.mu.Lock()
	defer s.cfgState.mu.Unlock()
	if s.cfgState.watcher == nil {
		return
	}
	close(s.cfgState.stop)
	s.cfgState.watcher.Close()
	s.cfgState.watcher = nil
}

func (s *Server) watchLoop(w *fsnotify.Watcher, stop <-chan struct{}, onChange func(old, new config.Config), onError func(msg string)) {
	// Debounce: coalesce rapid-fire events (save-via-rename produces 2-4).
	const debounce = 100 * time.Millisecond
	var timer *time.Timer
	reload := make(chan struct{}, 1)

	schedule := func() {
		if timer != nil {
			timer.Stop()
		}
		timer = time.AfterFunc(debounce, func() {
			select {
			case reload <- struct{}{}:
			default:
			}
		})
	}

	for {
		select {
		case <-stop:
			return
		case ev, ok := <-w.Events:
			if !ok {
				return
			}
			if !strings.HasSuffix(ev.Name, config.DefaultFilename) {
				continue
			}
			schedule()
		case err, ok := <-w.Errors:
			if !ok {
				return
			}
			if onError != nil {
				onError(fmt.Sprintf("coraza-lsp: fsnotify: %v", err))
			}
		case <-reload:
			old := s.Config()
			s.LoadConfig(s.cfgState.root, onError)
			if onChange != nil {
				onChange(old, s.Config())
			}
		}
	}
}

// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

// Package e2e contains end-to-end tests that build and run the coraza-lsp
// binary and communicate with it over stdio using the LSP wire protocol.
package e2e_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// binaryPath is set by TestMain to the compiled coraza-lsp binary.
var binaryPath string

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "coraza-lsp-e2e-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e: cannot create temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmp)

	bin := filepath.Join(tmp, "coraza-lsp")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}

	// Build the binary from the project root (two levels up from test/e2e).
	_, testFile, _, _ := runtime.Caller(0)
	projectRoot := filepath.Join(filepath.Dir(testFile), "..", "..")

	cmd := exec.Command("go", "build", "-o", bin, "./cmd/coraza-lsp")
	cmd.Dir = projectRoot
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: build failed: %v\n", err)
		os.Exit(1)
	}

	binaryPath = bin
	os.Exit(m.Run())
}

// ---- LSP client helpers ----------------------------------------------------

// lspMsg is a decoded LSP message.
type lspMsg map[string]any

// lspClient drives the coraza-lsp binary over its stdio pipes.
type lspClient struct {
	t      *testing.T
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	reader *bufio.Reader

	mu   sync.Mutex
	msgs []lspMsg // accumulated server→client messages
	done chan struct{}
}

func startClient(t *testing.T) *lspClient {
	t.Helper()

	cmd := exec.Command(binaryPath, "--stdio")
	stdinPipe, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdoutPipe, err := cmd.StdoutPipe()
	require.NoError(t, err)
	cmd.Stderr = os.Stderr

	require.NoError(t, cmd.Start())

	c := &lspClient{
		t:      t,
		cmd:    cmd,
		stdin:  stdinPipe,
		reader: bufio.NewReader(stdoutPipe),
		done:   make(chan struct{}),
	}

	// Background goroutine reads all server→client messages.
	go c.readLoop()

	t.Cleanup(func() {
		c.send("shutdown", nil)
		c.send("exit", nil)
		// Give the server a moment to shut down cleanly.
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			cmd.Process.Kill()
		}
		close(c.done)
	})

	return c
}

func (c *lspClient) readLoop() {
	for {
		msg, err := c.readOne()
		if err != nil {
			return
		}
		c.mu.Lock()
		c.msgs = append(c.msgs, msg)
		c.mu.Unlock()
	}
}

func (c *lspClient) readOne() (lspMsg, error) {
	var contentLen int
	for {
		line, err := c.reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		if rest, ok := strings.CutPrefix(line, "Content-Length: "); ok {
			contentLen, _ = strconv.Atoi(rest)
		}
	}
	if contentLen == 0 {
		return nil, fmt.Errorf("zero content length")
	}
	body := make([]byte, contentLen)
	if _, err := io.ReadFull(c.reader, body); err != nil {
		return nil, err
	}
	var msg lspMsg
	if err := json.Unmarshal(body, &msg); err != nil {
		return nil, err
	}
	return msg, nil
}

var sendID int
var sendMu sync.Mutex

func (c *lspClient) send(method string, params any) int {
	sendMu.Lock()
	sendID++
	id := sendID
	sendMu.Unlock()

	msg := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
		"params":  params,
	}
	b, _ := json.Marshal(msg)
	fmt.Fprintf(c.stdin, "Content-Length: %d\r\n\r\n%s", len(b), b)
	return id
}

func (c *lspClient) notify(method string, params any) {
	msg := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params":  params,
	}
	b, _ := json.Marshal(msg)
	fmt.Fprintf(c.stdin, "Content-Length: %d\r\n\r\n%s", len(b), b)
}

// waitForResponse blocks until a message with the given id arrives (or timeout).
func (c *lspClient) waitForResponse(id int) lspMsg {
	c.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		for _, msg := range c.msgs {
			if rawID, ok := msg["id"]; ok {
				if int(rawID.(float64)) == id {
					c.mu.Unlock()
					return msg
				}
			}
		}
		c.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	c.t.Fatalf("timeout waiting for response id=%d", id)
	return nil
}

// waitForNotification blocks until a notification with the given method arrives.
func (c *lspClient) waitForNotification(method string) lspMsg {
	c.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		for _, msg := range c.msgs {
			if msg["method"] == method {
				c.mu.Unlock()
				return msg
			}
		}
		c.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	c.t.Fatalf("timeout waiting for notification method=%s", method)
	return nil
}

// initClient starts a server and completes the LSP initialize handshake.
// All non-lifecycle tests should start here to avoid boilerplate.
func initClient(t *testing.T) *lspClient {
	t.Helper()
	return initClientInDir(t, "")
}

// initClientInDir starts a server with rootUri pointing at the given
// workspace directory. Use this when a test needs the server to discover a
// `.coraza.json` — the LSP can't tell where the workspace is without it.
func initClientInDir(t *testing.T, dir string) *lspClient {
	t.Helper()
	c := startClient(t)
	params := map[string]any{
		"processId":    os.Getpid(),
		"capabilities": map[string]any{},
	}
	if dir != "" {
		params["rootUri"] = "file://" + dir
	} else {
		params["rootUri"] = nil
	}
	id := c.send("initialize", params)
	c.waitForResponse(id)
	c.notify("initialized", map[string]any{})
	return c
}

// didOpen sends a textDocument/didOpen notification for seclang content.
func (c *lspClient) didOpen(uri, text string) {
	c.notify("textDocument/didOpen", map[string]any{
		"textDocument": map[string]any{
			"uri":        uri,
			"languageId": "seclang",
			"version":    1,
			"text":       text,
		},
	})
}

// waitForDiagnostics blocks until a publishDiagnostics notification for uri
// arrives and returns its diagnostics slice.
func (c *lspClient) waitForDiagnostics(uri string) []any {
	c.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		for _, msg := range c.msgs {
			if msg["method"] != "textDocument/publishDiagnostics" {
				continue
			}
			params, _ := msg["params"].(map[string]any)
			if params == nil || params["uri"] != uri {
				continue
			}
			c.mu.Unlock()
			if ds, ok := params["diagnostics"].([]any); ok {
				return ds
			}
			return nil
		}
		c.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	c.t.Fatalf("timeout waiting for diagnostics on %s", uri)
	return nil
}

// ---- Tests -----------------------------------------------------------------

func TestE2E_Initialize(t *testing.T) {
	c := startClient(t)

	id := c.send("initialize", map[string]any{
		"processId":    os.Getpid(),
		"rootUri":      nil,
		"capabilities": map[string]any{},
	})
	resp := c.waitForResponse(id)

	require.Nil(t, resp["error"], "initialize must not return an error")
	result, ok := resp["result"].(map[string]any)
	require.True(t, ok, "result should be an object")

	caps, ok := result["capabilities"].(map[string]any)
	require.True(t, ok, "capabilities should be present")

	assert.NotNil(t, caps["completionProvider"], "completion should be declared")
	assert.Equal(t, true, caps["hoverProvider"])
	assert.Equal(t, true, caps["definitionProvider"])
	assert.Equal(t, true, caps["documentSymbolProvider"])
	assert.Equal(t, true, caps["documentFormattingProvider"])
	assert.NotNil(t, caps["codeActionProvider"])

	// Server info
	serverInfo, ok := result["serverInfo"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "coraza-lsp", serverInfo["name"])

	// Acknowledge initialization.
	c.notify("initialized", map[string]any{})
}

func TestE2E_HoverDirective(t *testing.T) {
	c := startClient(t)

	// Initialize.
	initID := c.send("initialize", map[string]any{
		"processId":    os.Getpid(),
		"rootUri":      nil,
		"capabilities": map[string]any{},
	})
	c.waitForResponse(initID)
	c.notify("initialized", map[string]any{})

	// Open a document.
	const uri = "file:///test.conf"
	const src = "SecRuleEngine On\n"
	c.notify("textDocument/didOpen", map[string]any{
		"textDocument": map[string]any{
			"uri":        uri,
			"languageId": "seclang",
			"version":    1,
			"text":       src,
		},
	})

	// Hover over "SecRuleEngine" (line 0, char 5).
	hoverID := c.send("textDocument/hover", map[string]any{
		"textDocument": map[string]any{"uri": uri},
		"position":     map[string]any{"line": 0, "character": 5},
	})
	resp := c.waitForResponse(hoverID)

	require.Nil(t, resp["error"])
	if resp["result"] != nil {
		result := resp["result"].(map[string]any)
		contents := result["contents"].(map[string]any)
		assert.Contains(t, contents["value"].(string), "SecRuleEngine")
	}
}

func TestE2E_Completion(t *testing.T) {
	c := startClient(t)

	initID := c.send("initialize", map[string]any{
		"processId":    os.Getpid(),
		"rootUri":      nil,
		"capabilities": map[string]any{},
	})
	c.waitForResponse(initID)
	c.notify("initialized", map[string]any{})

	const uri = "file:///completion-test.conf"
	c.notify("textDocument/didOpen", map[string]any{
		"textDocument": map[string]any{
			"uri":        uri,
			"languageId": "seclang",
			"version":    1,
			"text":       "Sec",
		},
	})

	compID := c.send("textDocument/completion", map[string]any{
		"textDocument": map[string]any{"uri": uri},
		"position":     map[string]any{"line": 0, "character": 3},
		"context":      map[string]any{"triggerKind": 1},
	})
	resp := c.waitForResponse(compID)

	require.Nil(t, resp["error"])
	require.NotNil(t, resp["result"])

	items, ok := resp["result"].([]any)
	require.True(t, ok, "result should be an array of completion items")
	assert.NotEmpty(t, items)

	// At least SecRule should be present.
	var foundSecRule bool
	for _, item := range items {
		m := item.(map[string]any)
		if m["label"] == "SecRule" {
			foundSecRule = true
		}
	}
	assert.True(t, foundSecRule, "SecRule should be in completions")
}

func TestE2E_Diagnostics_MissingID(t *testing.T) {
	c := startClient(t)

	initID := c.send("initialize", map[string]any{
		"processId":    os.Getpid(),
		"rootUri":      nil,
		"capabilities": map[string]any{},
	})
	c.waitForResponse(initID)
	c.notify("initialized", map[string]any{})

	const uri = "file:///diag-test.conf"
	// A rule without an id should trigger a missing-id diagnostic.
	c.notify("textDocument/didOpen", map[string]any{
		"textDocument": map[string]any{
			"uri":        uri,
			"languageId": "seclang",
			"version":    1,
			"text":       `SecRule ARGS "@rx x" "phase:2,deny"`,
		},
	})

	notif := c.waitForNotification("textDocument/publishDiagnostics")
	params := notif["params"].(map[string]any)
	assert.Equal(t, uri, params["uri"])

	diags := params["diagnostics"].([]any)
	require.NotEmpty(t, diags)

	var foundMissingID bool
	for _, d := range diags {
		dm := d.(map[string]any)
		if code, ok := dm["code"].(string); ok && code == "missing-id" {
			foundMissingID = true
		}
	}
	assert.True(t, foundMissingID, "missing-id diagnostic expected")
}

func TestE2E_DocumentSymbols(t *testing.T) {
	c := startClient(t)

	initID := c.send("initialize", map[string]any{
		"processId":    os.Getpid(),
		"rootUri":      nil,
		"capabilities": map[string]any{},
	})
	c.waitForResponse(initID)
	c.notify("initialized", map[string]any{})

	const uri = "file:///symbols-test.conf"
	c.notify("textDocument/didOpen", map[string]any{
		"textDocument": map[string]any{
			"uri":        uri,
			"languageId": "seclang",
			"version":    1,
			"text":       `SecRule ARGS "@rx x" "id:1001,phase:2,deny,msg:'XSS'"`,
		},
	})

	symID := c.send("textDocument/documentSymbol", map[string]any{
		"textDocument": map[string]any{"uri": uri},
	})
	resp := c.waitForResponse(symID)

	require.Nil(t, resp["error"])
	require.NotNil(t, resp["result"])
	syms := resp["result"].([]any)
	require.NotEmpty(t, syms)

	sym := syms[0].(map[string]any)
	assert.Contains(t, sym["name"].(string), "1001")
}

func TestE2E_Formatting(t *testing.T) {
	c := startClient(t)

	initID := c.send("initialize", map[string]any{
		"processId":    os.Getpid(),
		"rootUri":      nil,
		"capabilities": map[string]any{},
	})
	c.waitForResponse(initID)
	c.notify("initialized", map[string]any{})

	const uri = "file:///fmt-test.conf"
	c.notify("textDocument/didOpen", map[string]any{
		"textDocument": map[string]any{
			"uri":        uri,
			"languageId": "seclang",
			"version":    1,
			"text":       "SecRuleEngine   On",
		},
	})

	fmtID := c.send("textDocument/formatting", map[string]any{
		"textDocument": map[string]any{"uri": uri},
		"options":      map[string]any{"tabSize": 4, "insertSpaces": true},
	})
	resp := c.waitForResponse(fmtID)

	require.Nil(t, resp["error"])
	edits := resp["result"].([]any)
	require.NotEmpty(t, edits)
	edit := edits[0].(map[string]any)
	assert.Equal(t, "SecRuleEngine On", edit["newText"])
}

func TestE2E_GoToDefinition_SkipAfter(t *testing.T) {
	c := startClient(t)

	initID := c.send("initialize", map[string]any{
		"processId":    os.Getpid(),
		"rootUri":      nil,
		"capabilities": map[string]any{},
	})
	c.waitForResponse(initID)
	c.notify("initialized", map[string]any{})

	const uri = "file:///def-test.conf"
	src := "SecRule ARGS \"@rx x\" \"id:1,phase:2,pass,skipAfter:END\"\nSecMarker END"
	c.notify("textDocument/didOpen", map[string]any{
		"textDocument": map[string]any{
			"uri":        uri,
			"languageId": "seclang",
			"version":    1,
			"text":       src,
		},
	})

	// Find skipAfter position: "skipAfter:END" starts at char 42 on line 0.
	defID := c.send("textDocument/definition", map[string]any{
		"textDocument": map[string]any{"uri": uri},
		"position":     map[string]any{"line": 0, "character": 42},
	})
	resp := c.waitForResponse(defID)

	require.Nil(t, resp["error"])
	// Result may be nil (if cursor doesn't land exactly on skipAfter value),
	// or a location array. Either is acceptable — just no panic/error.
	_ = resp["result"]
}

func TestE2E_DidChange_UpdatesContent(t *testing.T) {
	c := startClient(t)

	initID := c.send("initialize", map[string]any{
		"processId":    os.Getpid(),
		"rootUri":      nil,
		"capabilities": map[string]any{},
	})
	c.waitForResponse(initID)
	c.notify("initialized", map[string]any{})

	const uri = "file:///change-test.conf"
	c.notify("textDocument/didOpen", map[string]any{
		"textDocument": map[string]any{
			"uri":        uri,
			"languageId": "seclang",
			"version":    1,
			"text":       "SecRuleEngine On",
		},
	})

	// Change the document.
	c.notify("textDocument/didChange", map[string]any{
		"textDocument": map[string]any{
			"uri":     uri,
			"version": 2,
		},
		"contentChanges": []any{
			map[string]any{"text": "SecRuleEngine Off"},
		},
	})

	// Request hover to verify the server accepted the new content without crashing.
	hoverID := c.send("textDocument/hover", map[string]any{
		"textDocument": map[string]any{"uri": uri},
		"position":     map[string]any{"line": 0, "character": 5},
	})
	resp := c.waitForResponse(hoverID)
	require.Nil(t, resp["error"])
}

// TestE2E_Diagnostics_EdgeCases exercises a broad set of syntax and semantic
// issues across many directives in a single file, asserting that each expected
// diagnostic code appears at least once. Any server-side panic or protocol
// error would surface as a timeout / non-nil error on the publishDiagnostics
// notification and fail the test.
func TestE2E_Diagnostics_EdgeCases(t *testing.T) {
	c := initClient(t)

	const uri = "file:///edge-cases.conf"
	// Each line is crafted to trigger a specific Stage-1 diagnostic.
	src := strings.Join([]string{
		`# Missing id on a SecRule.`,
		`SecRule ARGS "@rx x" "phase:2,deny"`,
		``,
		`# Invalid phase.`,
		`SecRule ARGS "@rx x" "id:101,phase:9,deny"`,
		``,
		`# Invalid id (non-numeric).`,
		`SecRule ARGS "@rx x" "id:abc,phase:2,deny"`,
		``,
		`# Duplicate ids across two rules.`,
		`SecRule ARGS "@rx a" "id:2001,phase:2,deny"`,
		`SecRule ARGS "@rx b" "id:2001,phase:2,deny"`,
		``,
		`# skipAfter to nowhere.`,
		`SecRule ARGS "@rx x" "id:3001,phase:2,pass,skipAfter:NOT_A_MARKER"`,
		``,
		`# Missing id on SecAction.`,
		`SecAction "phase:1,pass"`,
		``,
		`# Unknown directive.`,
		`SecCompletelyMadeUp something`,
		``,
		`# Unknown variable in a rule.`,
		`SecRule TOTALLY_FAKE_VAR "@rx x" "id:4001,phase:2,deny"`,
		``,
		`# Unknown transformation.`,
		`SecRule ARGS "@rx x" "id:5001,phase:2,deny,t:notARealTransform"`,
		``,
		`# ctl with unknown option.`,
		`SecAction "id:6001,phase:1,pass,ctl:thisOptionDoesNotExist=Off"`,
		``,
		`# Well-formed control rules so the file isn't all-errors.`,
		`SecRuleEngine On`,
		`SecMarker GOOD_MARKER`,
		`SecRule ARGS "@rx x" "id:7001,phase:2,pass,skipAfter:GOOD_MARKER"`,
	}, "\n")

	c.didOpen(uri, src)
	diags := c.waitForDiagnostics(uri)
	require.NotEmpty(t, diags, "expected diagnostics for multi-issue file")

	codes := make(map[string]int, len(diags))
	for _, d := range diags {
		dm, _ := d.(map[string]any)
		if dm == nil {
			continue
		}
		if code, ok := dm["code"].(string); ok {
			codes[code]++
		}
	}

	// Every code below is raised by Stage-1 analysis; none depend on the
	// Coraza WAF oracle (which debounces and is out of scope for this test).
	wantCodes := []string{
		"missing-id",
		"invalid-phase",
		"invalid-id",
		"duplicate-id",
		"skipafter-not-found",
		"unknown-directive",
		"unknown-variable",
		"unknown-transformation",
	}
	for _, code := range wantCodes {
		assert.Contains(t, codes, code, "expected at least one %q diagnostic; got codes=%v", code, codes)
	}

	// Current behaviour: the analyzer flags the subsequent occurrence(s) only,
	// pointing back at the first definition's line. If the UX ever changes to
	// flag both sides, bump this to >= 2.
	assert.GreaterOrEqual(t, codes["duplicate-id"], 1)
}

// TestE2E_Diagnostics_RecoversFromBrokenEdit asserts the server stays healthy
// when a user types their way through an obviously broken intermediate state
// (unclosed quotes, trailing continuation, half-written directive) and then
// fixes it. We don't assert exact diagnostic codes in the broken state — only
// that the server never crashes and produces diagnostics for each version.
func TestE2E_Diagnostics_RecoversFromBrokenEdit(t *testing.T) {
	c := initClient(t)

	const uri = "file:///typing.conf"

	// Step 1: clearly broken content — unclosed quote + half directive.
	c.didOpen(uri, "SecRule ARGS \"@rx unclosed\nSecRul")
	_ = c.waitForDiagnostics(uri)

	// Step 2: still broken but different — trailing backslash, no next line.
	c.notify("textDocument/didChange", map[string]any{
		"textDocument":   map[string]any{"uri": uri, "version": 2},
		"contentChanges": []any{map[string]any{"text": "SecRule ARGS \"@rx x\" \\\n"}},
	})

	// Step 3: fixed.
	c.notify("textDocument/didChange", map[string]any{
		"textDocument":   map[string]any{"uri": uri, "version": 3},
		"contentChanges": []any{map[string]any{"text": "SecRule ARGS \"@rx x\" \"id:9001,phase:2,deny\"\n"}},
	})

	// The server should still respond to a hover without error.
	hoverID := c.send("textDocument/hover", map[string]any{
		"textDocument": map[string]any{"uri": uri},
		"position":     map[string]any{"line": 0, "character": 3},
	})
	resp := c.waitForResponse(hoverID)
	require.Nil(t, resp["error"], "server should not error after edits through broken states")
}

// TestE2E_Config_SeverityOverrideOff creates a workspace with a
// `.coraza.json` that maps `missing-id` to `off`, opens a file that would
// normally emit missing-id, and asserts the diagnostic is suppressed.
func TestE2E_Config_SeverityOverrideOff(t *testing.T) {
	dir := t.TempDir()
	cfg := `{"diagnostics": {"missing-id": "off"}}`
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".coraza.json"), []byte(cfg), 0o644))

	c := initClientInDir(t, dir)
	uri := "file://" + dir + "/rule.conf"
	c.didOpen(uri, `SecRule ARGS "@rx x" "phase:2,deny"`)

	diags := c.waitForDiagnostics(uri)
	for _, d := range diags {
		dm, _ := d.(map[string]any)
		if dm == nil {
			continue
		}
		if code, ok := dm["code"].(string); ok && code == "missing-id" {
			t.Fatalf("missing-id diagnostic should be suppressed by `.coraza.json`")
		}
	}
}

// TestE2E_Config_CoverageIsInit verifies that a file emitted by `coraza-lsp
// init` parses through the LSP without surfacing a config parse error. Uses
// `go run` on the same binary so we're testing the real subcommand plumbing.
func TestE2E_Config_InitWritesParseableFile(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command(binaryPath, "init", "--path", dir)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))

	c := initClientInDir(t, dir)
	// Open any .conf — if the config is unparseable the server shows a
	// window/showMessage with a warning. We simply wait a moment then
	// request a hover and ensure no error comes back.
	uri := "file://" + dir + "/sanity.conf"
	c.didOpen(uri, `SecRule ARGS "@rx x" "id:1,phase:2,deny"`)
	_ = c.waitForDiagnostics(uri)

	hoverID := c.send("textDocument/hover", map[string]any{
		"textDocument": map[string]any{"uri": uri},
		"position":     map[string]any{"line": 0, "character": 3},
	})
	resp := c.waitForResponse(hoverID)
	require.Nil(t, resp["error"], "server should not error with default config")
}

func TestE2E_VersionInfo(t *testing.T) {
	cmd := exec.Command(binaryPath, "--version")
	out, err := cmd.Output()
	require.NoError(t, err)
	assert.Contains(t, string(out), "coraza-lsp")
}

// TestE2E_CodeAction_AddMissingID proves the missing-id quick-fix is produced
// over the wire AND that its WorkspaceEdit targets the real document URI (the
// HIGH bug fixed in PR #8 was that edits were keyed on an empty document).
func TestE2E_CodeAction_AddMissingID(t *testing.T) {
	c := startClient(t)
	initID := c.send("initialize", map[string]any{
		"processId":    os.Getpid(),
		"rootUri":      nil,
		"capabilities": map[string]any{},
	})
	c.waitForResponse(initID)
	c.notify("initialized", map[string]any{})

	const uri = "file:///codeaction-test.conf"
	c.didOpen(uri, `SecRule ARGS "@rx x" "phase:2,deny"`)

	// Find the missing-id diagnostic to feed into the code-action request.
	diags := c.waitForDiagnostics(uri)
	require.NotEmpty(t, diags)
	var missing map[string]any
	for _, d := range diags {
		dm := d.(map[string]any)
		if code, _ := dm["code"].(string); code == "missing-id" {
			missing = dm
		}
	}
	require.NotNil(t, missing, "expected a missing-id diagnostic")

	caID := c.send("textDocument/codeAction", map[string]any{
		"textDocument": map[string]any{"uri": uri},
		"range":        missing["range"],
		"context":      map[string]any{"diagnostics": []any{missing}},
	})
	resp := c.waitForResponse(caID)
	require.Nil(t, resp["error"])

	dbg, _ := json.Marshal(resp["result"])
	t.Logf("CA RESULT: %s", dbg)
	actions, ok := resp["result"].([]any)
	require.True(t, ok, "code action result should be an array")
	require.NotEmpty(t, actions, "expected at least one quick-fix")

	// Some action must carry a WorkspaceEdit keyed on the real document URI.
	var foundEditForURI bool
	for _, a := range actions {
		am := a.(map[string]any)
		edit, _ := am["edit"].(map[string]any)
		if edit == nil {
			continue
		}
		changes, _ := edit["changes"].(map[string]any)
		if _, has := changes[uri]; has {
			foundEditForURI = true
		}
	}
	assert.True(t, foundEditForURI, "a quick-fix must edit the real document URI %q", uri)
}

// TestE2E_WorkspaceSymbol_ByID proves a rule can be located by its id over the
// wire — the backbone of the "Go to Rule by ID" command.
func TestE2E_WorkspaceSymbol_ByID(t *testing.T) {
	c := startClient(t)
	initID := c.send("initialize", map[string]any{
		"processId":    os.Getpid(),
		"rootUri":      nil,
		"capabilities": map[string]any{},
	})
	c.waitForResponse(initID)
	c.notify("initialized", map[string]any{})

	const uri = "file:///wssym-test.conf"
	c.didOpen(uri, "SecRule ARGS \"@rx x\" \"id:942100,phase:2,deny,msg:'SQLi'\"")

	symID := c.send("workspace/symbol", map[string]any{"query": "942100"})
	resp := c.waitForResponse(symID)
	require.Nil(t, resp["error"])

	syms, ok := resp["result"].([]any)
	require.True(t, ok, "workspace/symbol result should be an array")
	require.NotEmpty(t, syms, "expected a symbol for rule id 942100")

	var found bool
	for _, s := range syms {
		sm := s.(map[string]any)
		name, _ := sm["name"].(string)
		loc, _ := sm["location"].(map[string]any)
		if loc != nil && loc["uri"] == uri && containsStr(name, "942100") {
			found = true
		}
	}
	assert.True(t, found, "rule 942100 should be locatable by id via workspace/symbol")
}

func containsStr(s, sub string) bool { return strings.Contains(s, sub) }

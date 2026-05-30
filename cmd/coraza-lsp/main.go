// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

// Package main is the entry point for the Coraza SecLang Language Server.
// It supports stdio (default), TCP, and WebSocket transports.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/tliron/commonlog"
	_ "github.com/tliron/commonlog/simple"

	lspserver "github.com/coraza-incubator/coraza-lsp/pkg/lsp"
)

// Build-time variables injected via -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	// Subcommand dispatch. Subcommands are detected before flag.Parse so the
	// top-level flag set can stay LSP-server-oriented (--stdio, --tcp, …).
	if len(os.Args) >= 2 && os.Args[1] == "init" {
		if err := runInit(os.Args[2:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "coraza-lsp init:", err)
			os.Exit(2)
		}
		return
	}

	var (
		useStdio    = flag.Bool("stdio", false, "Use stdio transport (default when no other transport is specified)")
		tcpAddr     = flag.String("tcp", "", "Listen on TCP address (e.g. :7998)")
		wsAddr      = flag.String("ws", "", "Listen on WebSocket address (e.g. :7999)")
		verbose     = flag.Bool("v", false, "Enable verbose logging")
		showVersion = flag.Bool("version", false, "Print version information and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("coraza-lsp %s (%s, %s)\n", version, commit, date)
		os.Exit(0)
	}

	logLevel := 1
	if *verbose {
		logLevel = 2
	}
	commonlog.Configure(logLevel, nil)

	srv := lspserver.New(version)

	var err error
	switch {
	case *tcpAddr != "":
		err = srv.RunTCP(loopbackAddr(*tcpAddr))
	case *wsAddr != "":
		err = srv.RunWebSocket(loopbackAddr(*wsAddr))
	default: // --stdio is the default (also when --stdio flag is explicitly set)
		_ = useStdio
		err = srv.RunStdio()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "coraza-lsp: fatal: %v\n", err)
		os.Exit(1)
	}
}

// loopbackAddr defaults a bare port / wildcard bind to loopback. The TCP and
// WebSocket transports are dev-only and have no/limited per-message size
// guards (see pkg/lsp), so binding them to all interfaces would expose the LSP
// — including its on-disk file-read behaviour — to the local network. If the
// user provides an explicit host we honour it; only a missing or wildcard host
// (e.g. ":7998" or "0.0.0.0:7998") is rewritten to 127.0.0.1.
func loopbackAddr(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr // leave malformed input for the listener to reject
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

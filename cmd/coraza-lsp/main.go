// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

// Package main is the entry point for the Coraza SecLang Language Server.
// It supports stdio (default), TCP, and WebSocket transports.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/tliron/commonlog"
	_ "github.com/tliron/commonlog/simple"

	lspserver "github.com/coraza-incubator/coraza-lsp/internal/server"
)

// Build-time variables injected via -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
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
		err = srv.RunTCP(*tcpAddr)
	case *wsAddr != "":
		err = srv.RunWebSocket(*wsAddr)
	default: // --stdio is the default (also when --stdio flag is explicitly set)
		_ = useStdio
		err = srv.RunStdio()
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "coraza-lsp: fatal: %v\n", err)
		os.Exit(1)
	}
}

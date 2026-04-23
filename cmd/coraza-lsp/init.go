// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/coraza-incubator/coraza-lsp/internal/config"
)

// runInit writes a starter .coraza.json into the directory given by --path
// (default "."). Returns an error when the file already exists and --force
// is not passed. Progress messages go to stdout.
func runInit(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(io.Discard) // suppress the default usage dump; we print our own.
	path := fs.String("path", ".", "directory in which to create .coraza.json")
	force := fs.Bool("force", false, "overwrite an existing .coraza.json")
	if err := fs.Parse(args); err != nil {
		return err
	}

	abs, err := filepath.Abs(*path)
	if err != nil {
		return fmt.Errorf("resolving %s: %w", *path, err)
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", abs, err)
	}

	dest := filepath.Join(abs, config.DefaultFilename)
	if _, err := os.Stat(dest); err == nil && !*force {
		return fmt.Errorf("%s already exists; pass --force to overwrite", dest)
	}

	if err := os.WriteFile(dest, []byte(config.Template), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", dest, err)
	}

	fmt.Fprintf(stdout, "wrote %s\n", dest)
	return nil
}

// Copyright 2026 OWASP Coraza
// SPDX-License-Identifier: Apache-2.0
//
// CLI: tokenize a single SecLang file and print every token with its scopes.
// Usage: node tokenize.mjs <file> [--json]
import { readFile } from "node:fs/promises";
import { tokenizeText } from "./lib/grammar.mjs";

const args = process.argv.slice(2);
const json = args.includes("--json");
const file = args.find((a) => !a.startsWith("--"));
if (!file) {
  console.error("usage: node tokenize.mjs <file> [--json]");
  process.exit(2);
}

const text = await readFile(file, "utf8");
const lines = await tokenizeText(text);

if (json) {
  console.log(JSON.stringify(lines, null, 2));
} else {
  lines.forEach((toks, i) => {
    for (const t of toks) {
      if (t.text.trim() === "") continue;
      const scope = t.scopes.slice(1).join(" ") || "(none — fallthrough)";
      console.log(
        `${String(i + 1).padStart(4)}:${String(t.startIndex).padStart(3)}  ${JSON.stringify(t.text).padEnd(28)}  ${scope}`,
      );
    }
  });
}

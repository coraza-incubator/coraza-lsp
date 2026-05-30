// Copyright 2026 OWASP Coraza
// Author: Juan Pablo Tosso <pablo@owasp.org>
// SPDX-License-Identifier: Apache-2.0
//
// Loads the shipped SecLang TextMate grammar and tokenizes text with the exact
// engine VS Code uses (vscode-textmate driving an Oniguruma WASM regex backend).
// Returns, for every line, the list of {startIndex, endIndex, text, scopes}.

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { createRequire } from "node:module";
import onigModule from "vscode-oniguruma";
import vsctmModule from "vscode-textmate";

// Both deps ship as CommonJS; under ESM their APIs hang off the default export.
const oniguruma = onigModule.default ?? onigModule;
const vsctm = vsctmModule.default ?? vsctmModule;

const __dirname = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

// Path to the grammar shipped in the VS Code extension — single source of truth.
export const GRAMMAR_PATH = resolve(
  __dirname,
  "../../../editors/vscode/syntaxes/seclang.tmLanguage.json",
);
export const SCOPE_NAME = "source.seclang";

let _registryPromise = null;

async function makeRegistry() {
  const wasmPath = require.resolve("vscode-oniguruma/release/onig.wasm");
  const wasmBin = await readFile(wasmPath);
  await oniguruma.loadWASM(wasmBin.buffer);

  const onigLib = Promise.resolve({
    createOnigScanner: (patterns) => new oniguruma.OnigScanner(patterns),
    createOnigString: (s) => new oniguruma.OnigString(s),
  });

  const grammarRaw = await readFile(GRAMMAR_PATH, "utf8");
  const grammarJson = vsctm.parseRawGrammar(grammarRaw, GRAMMAR_PATH);

  return new vsctm.Registry({
    onigLib,
    loadGrammar: async (scopeName) =>
      scopeName === SCOPE_NAME ? grammarJson : null,
  });
}

export async function loadGrammar() {
  if (!_registryPromise) _registryPromise = makeRegistry();
  const registry = await _registryPromise;
  const grammar = await registry.loadGrammar(SCOPE_NAME);
  if (!grammar) throw new Error(`grammar ${SCOPE_NAME} failed to load`);
  return grammar;
}

// tokenizeText returns an array of lines; each line is an array of token
// objects {startIndex, endIndex, text, scopes}. Carries grammar state across
// lines so begin/end (continuation) rules behave exactly as in the editor.
export async function tokenizeText(text) {
  const grammar = await loadGrammar();
  const lines = text.split("\n");
  let ruleStack = vsctm.INITIAL;
  const out = [];
  for (const line of lines) {
    const r = grammar.tokenizeLine(line, ruleStack);
    out.push(
      r.tokens.map((t) => ({
        startIndex: t.startIndex,
        endIndex: t.endIndex,
        text: line.slice(t.startIndex, t.endIndex),
        scopes: t.scopes,
      })),
    );
    ruleStack = r.ruleStack;
  }
  return out;
}

// Copyright 2026 OWASP Coraza
// SPDX-License-Identifier: Apache-2.0
//
// Audits SecLang highlighting over a corpus of rule files. Tokenizes each file
// with the shipped grammar and reports "highlighting holes": non-whitespace
// tokens that received no scope beyond the root `source.seclang` (so they would
// render as plain unstyled text in an editor).
//
// Usage:
//   node audit.mjs                       # audit ./fixtures
//   node audit.mjs --corpus /tmp/coreruleset/rules
//   node audit.mjs --corpus DIR --max 50 # fail if > 50 distinct holes
//   node audit.mjs --corpus DIR --show 40
import { readFile, readdir, stat } from "node:fs/promises";
import { join, extname } from "node:path";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { tokenizeText } from "./lib/grammar.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));

function arg(name, def) {
  const i = process.argv.indexOf(name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : def;
}
const corpus = resolve(arg("--corpus", join(__dirname, "fixtures")));
const maxHoles = parseInt(arg("--max", "0"), 10);
const show = parseInt(arg("--show", "30"), 10);

// CRS `.data` files are plain pattern lists consumed by @pmFromFile/@ipMatchFromFile,
// not SecLang source — they are deliberately excluded.
const SECLANG_EXT = new Set([".conf", ".seclang"]);

async function walk(dir, acc = []) {
  for (const name of await readdir(dir)) {
    const p = join(dir, name);
    const s = await stat(p);
    if (s.isDirectory()) await walk(p, acc);
    else if (SECLANG_EXT.has(extname(name))) acc.push(p);
  }
  return acc;
}

// A token is a "hole" if its trimmed text is non-empty and its only scope is
// the root. Pure punctuation that the grammar intentionally leaves unscoped
// (quotes handled by the parent) is filtered out to reduce noise.
const IGNORE = new Set(['"', "'", "\\"]);
function isHole(t) {
  const txt = t.text.trim();
  if (txt === "" || IGNORE.has(txt)) return false;
  return t.scopes.length <= 1;
}

const files = (await stat(corpus)).isDirectory()
  ? await walk(corpus)
  : [corpus];

const holeBuckets = new Map(); // normalized text -> {count, examples:[]}
let totalTokens = 0,
  totalHoles = 0,
  totalLines = 0;

for (const f of files) {
  let text;
  try {
    text = await readFile(f, "utf8");
  } catch {
    continue;
  }
  const lines = await tokenizeText(text);
  totalLines += lines.length;
  lines.forEach((toks, i) => {
    for (const t of toks) {
      if (t.text.trim() !== "") totalTokens++;
      if (isHole(t)) {
        totalHoles++;
        const key = t.text.trim();
        if (!holeBuckets.has(key)) holeBuckets.set(key, { count: 0, examples: [] });
        const b = holeBuckets.get(key);
        b.count++;
        if (b.examples.length < 3)
          b.examples.push(`${f.replace(corpus, ".")}:${i + 1}:${t.startIndex}`);
      }
    }
  });
}

const sorted = [...holeBuckets.entries()].sort((a, b) => b[1].count - a[1].count);

console.log(`corpus:        ${corpus}`);
console.log(`files:         ${files.length}`);
console.log(`lines:         ${totalLines}`);
console.log(`tokens:        ${totalTokens}`);
console.log(`holes (total): ${totalHoles}`);
console.log(`holes (distinct text): ${sorted.length}`);
console.log("");
console.log(`Top ${Math.min(show, sorted.length)} highlighting holes (text → count, examples):`);
for (const [text, b] of sorted.slice(0, show)) {
  console.log(`  ${String(b.count).padStart(5)}  ${JSON.stringify(text).padEnd(36)} ${b.examples.join("  ")}`);
}

if (maxHoles > 0 && sorted.length > maxHoles) {
  console.error(`\nFAIL: ${sorted.length} distinct holes > --max ${maxHoles}`);
  process.exit(1);
}

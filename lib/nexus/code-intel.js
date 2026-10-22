"use strict";
// ================= code-intel: "find references" (reverse of go-to-definition) =================
// find_symbol answers "where is X defined?". This answers the other half an LSP gives you —
// "where is X USED?": every caller / reference of a function, class, variable or type across the
// repo, grouped by file with line numbers and a classification (definition vs import vs usage).
// Any model driving Nexus — even a small local one with no language server — gets impact-analysis
// it would not otherwise have before changing or deleting a symbol.
//
// Pure and dependency-free: files come in as [{path, content}], a plain object comes out, so it is
// deterministic and unit-tested in test/run.js. The IO (walking the tree, reading files) lives in
// the caller (deviceTool) — this module never touches the filesystem or network.

// A source identifier: letters, digits, underscore, $; cannot start with a digit. We only look up
// whole identifiers (never arbitrary regex) so matches are precise and the input is safe to splice
// into a RegExp after escaping.
const IDENT_RE = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

// Classify how the symbol appears on a line it is already known to occur on (best-effort, language
// agnostic): "def" a declaration, "import" an import/include/require line, otherwise "usage".
function classifyLine(line, sym) {
  const t = String(line);
  const trimmed = t.trim();
  if (/^(import\b|from\b|#include\b|using\b|use\b|require\b|package\b|export\s+\{)/.test(trimmed) || /\b(require|import)\s*\(/.test(trimmed)) return "import";
  const e = sym.replace(/[$]/g, "\\$&"); // $ is the only regex-special char an identifier can contain
  const defPatterns = [
    "function\\s*\\*?\\s+" + e + "\\b",                 // function foo / function* foo
    "class\\s+" + e + "\\b",                            // class Foo
    "def\\s+" + e + "\\b",                              // python / ruby def foo
    "(?:interface|type|enum|struct|trait|module|fn|func|impl)\\s+" + e + "\\b", // ts/go/rust/etc.
    "(?:const|let|var|static|public|private|protected|final)\\s+(?:\\w+\\s+)?" + e + "\\s*[=:]", // typed/untyped decl
    e + "\\s*(?::=|=)\\s*(?:async\\s*)?(?:function\\b|\\([^)]*\\)\\s*=>|\\()", // name = function / name = (…) =>
    e + "\\s*\\([^)]*\\)\\s*\\{",                       // method shorthand:  name(args) {
  ];
  for (const p of defPatterns) if (new RegExp("(^|[^.\\w$])" + p).test(t)) return "def";
  return "usage";
}

// Find every usage of `symbol` across `files` ([{path, content}]). Returns a grouped, ranked,
// size-capped report. opts: { context (lines around each hit, default 0), maxHits, maxPerFile }.
function findReferences(files, symbol, opts) {
  opts = opts || {};
  const sym = String(symbol == null ? "" : symbol).trim();
  if (!sym) return { error: "find_references needs a symbol name" };
  if (!IDENT_RE.test(sym)) return { symbol: sym, error: "find_references matches whole-word identifiers only (letters/digits/_/$, not starting with a digit) — use search{pattern} for free-form text or regex" };
  const maxHits = opts.maxHits || 300;
  const maxPerFile = opts.maxPerFile || 60;
  const ctx = Math.max(0, Math.min(5, Number(opts.context) || 0));
  const esc = sym.replace(/[$]/g, "\\$&");
  // whole-word match that also respects $ and leading/trailing identifier chars, so `foo` does not
  // match `foobar`, `_foo`, `foo2` or `a.foo` is still a usage (dot before is allowed).
  const re = new RegExp("(^|[^A-Za-z0-9_$])" + esc + "(?![A-Za-z0-9_$])");
  const byFile = [];
  let total = 0, defs = 0, imports = 0, truncated = false;
  for (const f of files || []) {
    if (!f || typeof f.content !== "string") continue;
    const lines = f.content.split("\n");
    const hits = [];
    for (let i = 0; i < lines.length; i++) {
      if (!re.test(lines[i])) continue;
      const kind = classifyLine(lines[i], sym);
      if (kind === "def") defs++; else if (kind === "import") imports++;
      const hit = { line: i + 1, kind, text: lines[i].replace(/\t/g, "  ").trim().slice(0, 200) };
      if (ctx > 0) {
        hit.before = lines.slice(Math.max(0, i - ctx), i).map((l) => l.replace(/\t/g, "  ").slice(0, 200));
        hit.after = lines.slice(i + 1, i + 1 + ctx).map((l) => l.replace(/\t/g, "  ").slice(0, 200));
      }
      hits.push(hit);
      total++;
      if (hits.length >= maxPerFile) { truncated = true; break; }
      if (total >= maxHits) { truncated = true; break; }
    }
    if (hits.length) byFile.push({ path: f.path, count: hits.length, hits });
    if (total >= maxHits) { truncated = true; break; }
  }
  // most-referenced files first, then alphabetical for a stable, deterministic order
  byFile.sort((a, b) => b.count - a.count || String(a.path).localeCompare(String(b.path)));
  const out = { symbol: sym, files: byFile.length, total, definitions: defs, imports, usages: total - defs - imports, truncated, references: byFile };
  if (!total) out.note = "no usages found — the symbol may be unused, spelled differently, or defined outside the scanned tree";
  return out;
}

module.exports = { findReferences, classifyLine, IDENT_RE };

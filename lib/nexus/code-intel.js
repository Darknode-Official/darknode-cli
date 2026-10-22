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

// ---------------- import / dependency graph (module_graph) ----------------
// "What imports this file, and what does it import?" — whole-file impact analysis, the level above
// find_references. Pure and best-effort: JS/TS relative specifiers are resolved to real repo files
// precisely; Python/Go are parsed and resolved where simple, otherwise listed as external. Never
// executes or requires anything — it only reads the import/require/from lines as text.

function dirName(p) { const i = String(p).lastIndexOf("/"); return i < 0 ? "" : p.slice(0, i); }
function normPath(p) {
  const parts = [];
  for (const seg of String(p).split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") { if (parts.length && parts[parts.length - 1] !== "..") parts.pop(); else parts.push(".."); }
    else parts.push(seg);
  }
  return parts.join("/");
}
function joinRel(dir, rel) { return normPath((dir ? dir + "/" : "") + rel); }
function extOf(p) { const m = /\.([a-z0-9]+)$/i.exec(String(p)); return m ? m[1].toLowerCase() : ""; }

const JS_EXTS = ["", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", "/index.js", "/index.ts", "/index.jsx", "/index.tsx", "/index.mjs"];

// Pull raw import specifiers out of one file's source (language-aware), as written.
function parseImports(filePath, content) {
  const ext = extOf(filePath);
  const specs = [];
  let m;
  if (/^(js|jsx|ts|tsx|mjs|cjs|vue|svelte)$/.test(ext)) {
    const reFrom = /(?:^|[\n;])\s*(?:import|export)\b[^;\n]*?\bfrom\s*["']([^"']+)["']/g;
    const reBare = /(?:^|[\n;])\s*import\s*["']([^"']+)["']/g;
    const reReq = /\brequire\s*\(\s*["']([^"']+)["']\s*\)/g;
    const reDyn = /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g;
    while ((m = reFrom.exec(content))) specs.push(m[1]);
    while ((m = reBare.exec(content))) specs.push(m[1]);
    while ((m = reReq.exec(content))) specs.push(m[1]);
    while ((m = reDyn.exec(content))) specs.push(m[1]);
  } else if (ext === "py") {
    const reFrom = /(?:^|\n)[ \t]*from[ \t]+([.\w]+)[ \t]+import\b/g;
    const reImp = /(?:^|\n)[ \t]*import[ \t]+([.\w]+(?:[ \t]*,[ \t]*[.\w]+)*)/g;
    while ((m = reFrom.exec(content))) specs.push(m[1]);
    while ((m = reImp.exec(content))) for (const p of m[1].split(",")) specs.push(p.trim());
  } else if (ext === "go") {
    const reSingle = /(?:^|\n)[ \t]*import[ \t]+(?:[.\w]+[ \t]+)?"([^"]+)"/g;
    const reBlock = /(?:^|\n)[ \t]*import[ \t]*\(([\s\S]*?)\)/g;
    while ((m = reSingle.exec(content))) specs.push(m[1]);
    while ((m = reBlock.exec(content))) { let mm; const r2 = /"([^"]+)"/g; while ((mm = r2.exec(m[1]))) specs.push(mm[1]); }
  }
  // de-dup, keep order
  const seen = new Set(); const out = [];
  for (const s of specs) if (s && !seen.has(s)) { seen.add(s); out.push(s); }
  return out;
}

// Resolve one specifier from `importer` to a repo file in `fileSet` (a Set of repo-relative paths),
// or return null when it is external (a package / stdlib) or can't be resolved.
function resolveSpec(spec, importer, fileSet) {
  const ext = extOf(importer);
  if (/^(js|jsx|ts|tsx|mjs|cjs|vue|svelte)$/.test(ext)) {
    if (spec[0] !== "." && spec[0] !== "/") return null;            // bare = external package
    const base = joinRel(dirName(importer), spec);
    for (const suf of JS_EXTS) { const cand = normPath(base + suf); if (fileSet.has(cand)) return cand; }
    return null;
  }
  if (ext === "py") {
    let modPath = spec, up = 0;
    while (modPath[0] === ".") { up++; modPath = modPath.slice(1); }
    const mod = modPath.replace(/\./g, "/");
    const bases = [];
    if (up > 0) { let d = dirName(importer); for (let i = 1; i < up; i++) d = dirName(d); bases.push(d ? d + "/" + mod : mod); }
    else bases.push(mod);                                           // absolute: resolve from repo root (best-effort)
    for (const b of bases) for (const suf of [".py", "/__init__.py"]) { const cand = normPath(b + suf); if (fileSet.has(cand)) return cand; }
    return null;
  }
  return null;                                                      // other languages: specifier listed, not resolved
}

// Build the whole import graph once: { imports: {file:[{spec,resolved,external}]}, importedBy: {file:[importers]} }.
function buildImportGraph(files) {
  const fileSet = new Set();
  for (const f of files || []) if (f && f.path) fileSet.add(normPath(f.path));
  const imports = {}, importedBy = {};
  for (const f of files || []) {
    if (!f || typeof f.content !== "string") continue;
    const self = normPath(f.path);
    const specs = parseImports(self, f.content);
    const edges = [];
    for (const spec of specs) {
      const resolved = resolveSpec(spec, self, fileSet);
      edges.push({ spec, resolved: resolved || null, external: !resolved && spec[0] !== "." && spec[0] !== "/" });
      if (resolved) { (importedBy[resolved] = importedBy[resolved] || []).push(self); }
    }
    imports[self] = edges;
  }
  return { imports, importedBy, fileSet };
}

// The module_graph tool: with a target path, its imports + importedBy; without one, a project summary.
function moduleGraph(files, target, opts) {
  opts = opts || {};
  const g = buildImportGraph(files);
  if (target) {
    const t = normPath(target);
    if (!g.fileSet.has(t)) return { error: "file not in the scanned tree: " + target + " — pass a repo-relative source path, or omit path for a project summary" };
    const edges = g.imports[t] || [];
    const internal = edges.filter((e) => e.resolved).map((e) => e.resolved);
    const external = edges.filter((e) => e.external).map((e) => e.spec);
    const unresolved = edges.filter((e) => !e.resolved && !e.external).map((e) => e.spec);
    const importedBy = (g.importedBy[t] || []).slice().sort();
    return { file: t, importsInternal: internal, importsExternal: external, importsUnresolved: unresolved, importedBy, fanOut: internal.length, fanIn: importedBy.length };
  }
  // project summary
  const cap = opts.top || 15;
  const fanIn = Object.keys(g.importedBy).map((p) => ({ path: p, importedBy: g.importedBy[p].length }));
  fanIn.sort((a, b) => b.importedBy - a.importedBy || a.path.localeCompare(b.path));
  let edgeCount = 0; for (const p of Object.keys(g.imports)) edgeCount += g.imports[p].filter((e) => e.resolved).length;
  const entryPoints = Array.from(g.fileSet).filter((p) => !g.importedBy[p]).sort().slice(0, cap);
  return {
    files: g.fileSet.size,
    internalEdges: edgeCount,
    mostImported: fanIn.slice(0, cap),
    entryPoints: { note: "source files nothing else imports (likely entry points, scripts, or dead code)", files: entryPoints, total: Array.from(g.fileSet).filter((p) => !g.importedBy[p]).length },
  };
}

module.exports = { findReferences, classifyLine, IDENT_RE, parseImports, resolveSpec, buildImportGraph, moduleGraph };

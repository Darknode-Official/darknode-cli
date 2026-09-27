"use strict";
// ================= repo-map: fast, dependency-free codebase orientation =================
// Top coding agents (Claude Code, Codex, Devin) open a task already oriented: they know the
// shape of the tree and the important symbols. Nexus previously only had keyword-overlap
// retrieval (and only for the local engine). This module builds a compact, RANKED map of a
// repository — a pruned file tree plus a per-file symbol outline (functions / classes /
// exports) extracted by language-aware regexes — cheap enough to inject into the system
// prompt every session, for EVERY engine.
//
// Pure and testable: `buildRepoMap` takes an array of { path, content } (or { path, size }),
// never touches the filesystem itself, and returns a deterministic structure. `renderRepoMap`
// turns it into a token-budgeted string. The caller (darknode.js) does the fs walk.

// Directories that never carry signal for a coding task.
const IGNORE_DIRS = new Set([
  "node_modules", ".git", ".hg", ".svn", "dist", "build", "out", "target", "vendor",
  ".next", ".nuxt", ".cache", "coverage", "__pycache__", ".venv", "venv", "env",
  ".idea", ".vscode", ".gradle", ".terraform", "bin", "obj", ".pytest_cache",
  ".mypy_cache", ".tox", "bower_components", ".parcel-cache", ".turbo", ".svelte-kit",
]);

// Files that are noise (locks, minified bundles, maps, binaries by extension).
const IGNORE_FILE_RE = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|Cargo\.lock|poetry\.lock|Gemfile\.lock|go\.sum)$|\.(min\.js|min\.css|map|lock)$/i;
const BINARY_EXT_RE = /\.(png|jpe?g|gif|bmp|ico|webp|svg|pdf|zip|gz|tar|tgz|bz2|xz|7z|rar|exe|dll|so|dylib|o|a|class|jar|war|wasm|bin|dat|db|sqlite3?|woff2?|ttf|otf|eot|mp[34]|mov|avi|mkv|wav|flac|ogg|psd|ai|sketch)$/i;

// Language detection by extension → symbol-extraction rules.
const EXT_LANG = {
  js: "js", mjs: "js", cjs: "js", jsx: "js", ts: "ts", tsx: "ts",
  py: "py", pyi: "py", rb: "rb", go: "go", rs: "rs", java: "java",
  c: "c", h: "c", cc: "cpp", cpp: "cpp", cxx: "cpp", hpp: "cpp",
  cs: "cs", php: "php", swift: "swift", kt: "kt", scala: "scala",
  sh: "sh", bash: "sh", lua: "lua", ex: "ex", exs: "ex", dart: "dart",
  vue: "js", svelte: "js",
};

function extOf(p) { const m = /\.([a-z0-9]+)$/i.exec(p); return m ? m[1].toLowerCase() : ""; }
function baseOf(p) { const s = String(p).replace(/\/+$/, ""); const i = s.lastIndexOf("/"); return i < 0 ? s : s.slice(i + 1); }

// Is this a path we should even consider for the map?
function isSourceFile(p) {
  if (IGNORE_FILE_RE.test(p) || BINARY_EXT_RE.test(p)) return false;
  for (const seg of String(p).split("/")) if (IGNORE_DIRS.has(seg)) return false;
  return true;
}

// Per-language symbol matchers. Each returns [{ kind, name, line }]. Regexes are intentionally
// forgiving: a repo map is a hint, not a compiler, so a few misses/false-positives are fine as
// long as the output is stable and the common declarations are caught.
const SYMBOL_RULES = {
  js: [
    [/^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)/, "fn"],
    [/^\s*(?:export\s+)?(?:abstract\s+)?class\s+([A-Za-z_$][\w$]*)/, "class"],
    [/^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>/, "fn"],
    [/^\s*([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{/, "method"],
    [/^\s*module\.exports\s*=/, "exports"],
  ],
  py: [
    [/^\s*(?:async\s+)?def\s+([A-Za-z_][\w]*)/, "fn"],
    [/^\s*class\s+([A-Za-z_][\w]*)/, "class"],
  ],
  rb: [
    [/^\s*def\s+([A-Za-z_][\w?!]*)/, "fn"],
    [/^\s*(?:class|module)\s+([A-Za-z_][\w:]*)/, "class"],
  ],
  go: [
    [/^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][\w]*)/, "fn"],
    [/^\s*type\s+([A-Za-z_][\w]*)\s+(?:struct|interface)/, "type"],
  ],
  rs: [
    [/^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z_][\w]*)/, "fn"],
    [/^\s*(?:pub\s+)?(?:struct|enum|trait)\s+([A-Za-z_][\w]*)/, "type"],
    [/^\s*impl(?:\s*<[^>]*>)?\s+([A-Za-z_][\w:]*)/, "impl"],
  ],
  java: [
    [/^\s*(?:public|private|protected)?\s*(?:static\s+)?(?:final\s+)?(?:abstract\s+)?(?:class|interface|enum)\s+([A-Za-z_][\w]*)/, "class"],
    [/^\s*(?:public|private|protected)\s+(?:static\s+)?[\w<>\[\]]+\s+([A-Za-z_][\w]*)\s*\(/, "method"],
  ],
  c: [[/^[A-Za-z_][\w\s\*]*\s+([A-Za-z_][\w]*)\s*\([^;]*\)\s*\{/, "fn"]],
  php: [
    [/^\s*(?:public|private|protected|static|abstract|final|\s)*function\s+([A-Za-z_][\w]*)/, "fn"],
    [/^\s*(?:abstract\s+|final\s+)?class\s+([A-Za-z_][\w]*)/, "class"],
  ],
  sh: [[/^\s*(?:function\s+)?([A-Za-z_][\w-]*)\s*\(\s*\)\s*\{/, "fn"]],
};
SYMBOL_RULES.ts = SYMBOL_RULES.js.concat([
  [/^\s*(?:export\s+)?(?:declare\s+)?interface\s+([A-Za-z_$][\w$]*)/, "type"],
  [/^\s*(?:export\s+)?type\s+([A-Za-z_$][\w$]*)\s*=/, "type"],
  [/^\s*(?:export\s+)?enum\s+([A-Za-z_$][\w$]*)/, "type"],
]);
SYMBOL_RULES.cpp = SYMBOL_RULES.c.concat([[/^\s*(?:class|struct)\s+([A-Za-z_][\w]*)/, "class"]]);

// Language keywords that the forgiving "method" / call-shaped regexes would otherwise capture as
// bogus symbols (`if (...) {`, `for (...) {`, `catch (e) {`, `switch (x) {`, …).
const KEYWORDS = new Set([
  "if", "for", "while", "switch", "catch", "return", "do", "else", "with", "function", "class",
  "try", "finally", "case", "default", "typeof", "instanceof", "new", "delete", "void", "in",
  "of", "await", "yield", "throw", "super", "this", "constructor", "get", "set", "static",
  "def", "elif", "except", "lambda", "and", "or", "not", "func", "fn", "let", "const", "var",
  "foreach", "unless", "when", "match", "select", "go", "defer", "using", "namespace",
]);

// Extract symbols from one file's content. Skips comment-only / string-heavy lines cheaply and
// dedups by name (keeping the first sighting) so a class + its methods don't dominate.
function extractSymbols(pathOrExt, content, opts) {
  const lang = EXT_LANG[extOf(pathOrExt)] || EXT_LANG[pathOrExt] || null;
  const rules = lang && SYMBOL_RULES[lang];
  if (!rules || typeof content !== "string") return [];
  const cap = (opts && opts.max) || 40;
  const out = [], seen = new Set();
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > 400) continue; // minified / data line
    for (const [re, kind] of rules) {
      const m = re.exec(line);
      if (m && m[1] && !KEYWORDS.has(m[1]) && !seen.has(kind + " " + m[1])) {
        seen.add(kind + " " + m[1]);
        out.push({ kind, name: m[1], line: i + 1 });
        break;
      }
    }
    if (out.length >= cap) break;
  }
  return out;
}

// Score a file for how likely it matters to a coding task: entry points and files with many
// symbols rank high; tests, config and generated-ish paths rank low. Higher = more important.
function scoreFile(f) {
  const p = f.path, b = baseOf(p).toLowerCase();
  let s = 0;
  const nSym = f.symbols ? f.symbols.length : 0;
  s += Math.min(nSym, 30); // symbol density is the main signal
  if (/^(index|main|app|server|cli|mod|lib)\.[a-z]+$/.test(b)) s += 12; // entry points
  if (/(^|\/)(src|lib|app|pkg|internal)\//.test(p)) s += 4; // canonical source dirs
  const depth = p.split("/").length; s -= Math.max(0, depth - 2); // shallow files matter more
  if (/(^|\/)(test|tests|spec|__tests__|e2e|fixtures?)(\/|$)/i.test(p) || /\.(test|spec)\.[a-z]+$/i.test(b)) s -= 6;
  if (/(^|\/)(docs?|examples?|samples?|demos?)(\/|$)/i.test(p)) s -= 4;
  if (/\.(json|ya?ml|toml|ini|cfg|conf|lock|md|txt|xml|env)$/i.test(b)) s -= 3; // config/docs
  if (/(readme|license|changelog|contributing)/i.test(b)) s -= 2;
  return s;
}

// Build the map from an array of { path, content?, size? }. Files without content still appear
// in the tree (and can be scored/sized) but contribute no symbols.
function buildRepoMap(files, opts) {
  opts = opts || {};
  const symMax = opts.symbolsPerFile || 40;
  const kept = [];
  for (const f of files || []) {
    if (!f || typeof f.path !== "string" || !f.path) continue;
    if (!isSourceFile(f.path)) continue;
    const symbols = typeof f.content === "string" ? extractSymbols(f.path, f.content, { max: symMax }) : [];
    const size = typeof f.size === "number" ? f.size : (typeof f.content === "string" ? f.content.length : 0);
    const rec = { path: f.path.replace(/^\.\//, ""), size, symbols, lang: EXT_LANG[extOf(f.path)] || null };
    rec.score = scoreFile(rec);
    kept.push(rec);
  }
  kept.sort((a, b) => b.score - a.score || a.path.localeCompare(b.path));
  const langs = {};
  for (const f of kept) if (f.lang) langs[f.lang] = (langs[f.lang] || 0) + 1;
  return {
    fileCount: kept.length,
    symbolCount: kept.reduce((n, f) => n + f.symbols.length, 0),
    languages: langs,
    files: kept,
  };
}

// Render a token-budgeted text view. `maxFiles` files are shown with up to `maxSymbols` symbols
// each; the rest are summarized as a count. Deterministic, compact, prompt-ready.
function renderRepoMap(map, opts) {
  opts = opts || {};
  const maxFiles = opts.maxFiles || 40;
  const maxSym = opts.maxSymbols || 12;
  if (!map || !map.files || !map.files.length) return "(empty repository map)";
  const langLine = Object.entries(map.languages).sort((a, b) => b[1] - a[1]).map(([l, n]) => l + " x" + n).join(", ");
  const lines = [];
  lines.push("Repository map: " + map.fileCount + " source files, " + map.symbolCount + " symbols" + (langLine ? " (" + langLine + ")" : "") + ".");
  const shown = map.files.slice(0, maxFiles);
  for (const f of shown) {
    const syms = f.symbols.slice(0, maxSym).map((s) => s.name + (s.kind === "class" || s.kind === "type" ? "*" : "")).join(", ");
    const more = f.symbols.length > maxSym ? " +" + (f.symbols.length - maxSym) : "";
    lines.push("  " + f.path + (syms ? "  — " + syms + more : ""));
  }
  if (map.files.length > maxFiles) lines.push("  … and " + (map.files.length - maxFiles) + " more files.");
  return lines.join("\n");
}

// Find where a symbol is defined across a built map. Ranks exact-name definitions first, then
// case-insensitive, then substring — so "where is fooBar defined" lands on the definition, not a
// mention. Returns [{ path, name, kind, line }]. This is agentic "go to definition" without an LSP.
function findSymbol(map, name, opts) {
  opts = opts || {};
  const q = String(name || "").trim();
  if (!q || !map || !map.files) return [];
  const ql = q.toLowerCase();
  const hits = [];
  for (const f of map.files) {
    for (const s of f.symbols || []) {
      const nl = s.name.toLowerCase();
      let rank = null;
      if (s.name === q) rank = 0;
      else if (nl === ql) rank = 1;
      else if (opts.fuzzy !== false && nl.includes(ql) && ql.length >= 3) rank = 2;
      if (rank !== null) hits.push({ path: f.path, name: s.name, kind: s.kind, line: s.line, rank });
    }
  }
  hits.sort((a, b) => a.rank - b.rank || a.path.localeCompare(b.path) || a.line - b.line);
  return hits.slice(0, opts.limit || 25).map(({ rank, ...rest }) => rest); // eslint-disable-line no-unused-vars
}

module.exports = { buildRepoMap, renderRepoMap, extractSymbols, findSymbol, isSourceFile, scoreFile, IGNORE_DIRS, EXT_LANG };

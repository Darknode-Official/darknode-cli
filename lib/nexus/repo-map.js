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
const EXT_LANG = Object.assign(Object.create(null), { // null prototype: "x.constructor" must not resolve to Object
  js: "js", mjs: "js", cjs: "js", jsx: "js", ts: "ts", tsx: "ts",
  py: "py", pyi: "py", rb: "rb", go: "go", rs: "rs", java: "java",
  c: "c", h: "c", cc: "cpp", cpp: "cpp", cxx: "cpp", hpp: "cpp",
  cs: "cs", php: "php", swift: "swift", kt: "kt", scala: "scala",
  sh: "sh", bash: "sh", lua: "lua", ex: "ex", exs: "ex", dart: "dart",
  vue: "js", svelte: "js",
});

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
    [/^\s*(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+([A-Za-z_$][\w$]*)/, "class"], // export default class X (React components) was missed
    [/^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b|(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>)/, "fn"],
    // methods, with modifiers (async/static/get/set/*, #private, TS access) and a TS return type
    [/^\s*(?:(?:static|async|get|set|public|private|protected|readonly|override|abstract)\s+)*\*?\s*#?([A-Za-z_$][\w$]*)\s*(?:<[^>]*>)?\s*\([^)]*\)\s*(?::\s*[^={;$]+)?\{/, "method", true], // no $: "Salt (hex): ${x}" in a template is not a method
    [/^\s*module\.exports\s*=/, "exports"],
  ],
  py: [
    [/^\s*(?:async\s+)?def\s+([A-Za-z_][\w]*)/, "fn"],
    [/^\s*class\s+([A-Za-z_][\w]*)/, "class"],
  ],
  rb: [
    [/^\s*def\s+(?:self\.)?([A-Za-z_][\w?!]*=?)/, "fn"], // def self.call was named "self"; def name=(v) is the setter "name="
    [/^\s*(?:class|module)\s+([A-Za-z_][\w:]*)/, "class"],
  ],
  go: [
    [/^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][\w]*)/, "fn"],
    [/^\s*type\s+([A-Za-z_][\w]*)\s+(?:struct|interface)/, "type"],
  ],
  rs: [
    [/^\s*(?:pub(?:\([^)]*\))?\s+)?(?:(?:const|async|unsafe|extern(?:\s+"[^"]*")?)\s+)*fn\s+([A-Za-z_][\w]*)/, "fn"], // pub(crate) async fn
    [/^\s*(?:pub(?:\([^)]*\))?\s+)?(?:unsafe\s+)?(?:struct|enum|trait)\s+([A-Za-z_][\w]*)/, "type"],
    [/^\s*impl(?:\s*<[^>]*>)?\s+([A-Za-z_][\w:]*)/, "impl"],
  ],
  java: [
    [/^\s*(?:public|private|protected)?\s*(?:static\s+)?(?:final\s+)?(?:abstract\s+)?(?:class|interface|enum)\s+([A-Za-z_][\w]*)/, "class"],
    [/^\s*(?:public|private|protected)\s+(?:static\s+)?[\w<>\[\]]+\s+([A-Za-z_][\w]*)\s*\(/, "method", true],
  ],
  c: [[/^[A-Za-z_][\w\s\*]*\s+([A-Za-z_][\w]*)\s*\([^;]*\)\s*\{/, "fn", true]],
  php: [
    [/^\s*(?:public|private|protected|static|abstract|final|\s)*function\s+([A-Za-z_][\w]*)/, "fn"],
    [/^\s*(?:abstract\s+|final\s+)?class\s+([A-Za-z_][\w]*)/, "class"],
  ],
  sh: [[/^\s*(?:function\s+)?([A-Za-z_][\w-]*)\s*\(\s*\)\s*\{/, "fn", true]],
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
  "of", "await", "yield", "throw", "super", "this", "constructor", "static",
  "def", "elif", "except", "lambda", "and", "or", "not", "func", "fn", "let", "const", "var",
  "foreach", "unless", "when", "match", "select", "go", "defer", "using", "namespace",
]);

// Extract symbols from one file's content. Skips comment-only / string-heavy lines cheaply and
// dedups by name (keeping the first sighting) so a class + its methods don't dominate;
// opts.all keeps every definition (read_symbol needs the second `save`).
function extractSymbols(pathOrExt, content, opts) {
  const lang = EXT_LANG[extOf(pathOrExt)] || EXT_LANG[pathOrExt] || null;
  const rules = lang && SYMBOL_RULES[lang];
  if (!rules || typeof content !== "string") return [];
  const cap = (opts && opts.max) || 40;
  const out = [], seen = new Set(), all = !!(opts && opts.all);
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.length > 400) continue; // minified / data line
    for (const [re, kind, loose] of rules) { // loose = call-shaped: `if (x) {` must not read as a method
      const m = re.exec(line);
      if (m && m[1] && !(loose && KEYWORDS.has(m[1])) && (all || !seen.has(kind + " " + m[1]))) {
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
    if (opts.refs && rec.lang && typeof f.content === "string") rec.refs = extractRefs(f.content);
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

// ---------------- ranked, task-relative map (personalized PageRank over a symbol graph) ----------------
// The flat score above says which files look important in general. For a task, what matters is
// which definitions the code in play actually depends on. Files are nodes; file A links to file B
// once per identifier A uses that B defines. PageRank over that graph ranks what the rest of the
// code leans on, and restarting the walk at the files and names of the task (files read or edited
// this session, identifiers and paths named in the user's message) makes the ranking about the
// task rather than about popularity. Clean-room from the published idea; no parser, no deps.

// Every identifier-shaped word in a file with its count (3+ chars, keywords dropped). Strings and
// comments are included on purpose: a name mentioned in a comment is still a weak dependency.
function extractRefs(content) {
  const refs = new Map();
  if (typeof content !== "string") return refs;
  const re = /[A-Za-z_$][\w$]{2,}/g;
  for (const line of content.split("\n")) {
    if (line.length > 400) continue; // minified / data line
    let m; re.lastIndex = 0;
    while ((m = re.exec(line))) { const w = m[0]; if (!KEYWORDS.has(w)) refs.set(w, (refs.get(w) || 0) + 1); }
  }
  return refs;
}

// Names and paths the user's message points at. idents are code-shaped words (camelCase,
// snake_case, $ or digits, or anything in backticks or quotes); words are plain English words
// of 5+ letters, a much weaker hint ("the stale write guard" is not naming a function guard).
const CODE_SHAPED = /[a-z][A-Z]|[A-Z][a-z]+[A-Z]|_|\$|[A-Za-z]\d/;
function mentionsOf(text) {
  const idents = new Set(), words = new Set(), paths = new Set();
  const s = String(text || "");
  // prefixes bounded: unbounded `[\w./-]+\.` rescanned a long dot-less run from every start (quadratic: 40 KB paste = seconds)
  for (const m of s.matchAll(/[\w./-]{1,256}\.[A-Za-z0-9]{1,5}\b|[\w-]{1,256}\/[\w./-]+/g)) paths.add(m[0].replace(/^\.\//, ""));
  for (const m of s.matchAll(/[`'"]([A-Za-z_$][\w$.]*)[`'"]/g)) for (const w of m[1].split(".")) if (w.length >= 2) idents.add(w);
  for (const m of s.matchAll(/[A-Za-z_$][\w$]{2,}/g)) {
    const w = m[0];
    if (KEYWORDS.has(w)) continue;
    if (CODE_SHAPED.test(w)) idents.add(w); else if (w.length >= 5) words.add(w.toLowerCase());
  }
  return { idents, words, paths };
}

// Words that are usually a built-in method, a property or a throwaway local, whoever defines them.
const GENERIC = new Set(["get", "set", "has", "add", "map", "run", "list", "keys", "values", "entries", "push", "join", "split",
  "slice", "trim", "test", "start", "stop", "write", "read", "line", "lines", "tail", "head", "out", "opt", "opts", "all",
  "call", "apply", "bind", "then", "resolve", "reject", "close", "open", "send", "emit", "init", "data", "name", "type",
  "value", "result", "error", "err", "next", "done", "load", "save", "parse", "format", "render", "update", "create",
  "delete", "remove", "clear", "reset", "find", "filter", "reduce", "sort", "size", "length", "count", "index", "item",
  "items", "node", "text", "path", "file", "files", "main", "home", "same", "pick", "known", "running", "toString"]);

// Personalized PageRank. nodes: count; edges: [{ from, to, w }]; restart: array of weights (any
// scale, normalized here; all zeros = uniform). Dangling nodes return their mass to the restart
// vector. Deterministic power iteration; a few thousand nodes converge in milliseconds.
function pageRank(n, edges, restart, opts) {
  opts = opts || {};
  const d = opts.damping == null ? 0.85 : opts.damping, iters = opts.iterations || 60, tol = opts.tolerance || 1e-9;
  if (!n) return [];
  let rs = restart && restart.reduce((a, b) => a + b, 0) > 0 ? restart.slice() : new Array(n).fill(1);
  const rsum = rs.reduce((a, b) => a + b, 0); rs = rs.map((x) => x / rsum);
  const out = new Array(n).fill(0);
  for (const e of edges) out[e.from] += e.w;
  let r = rs.slice();
  for (let it = 0; it < iters; it++) {
    const next = new Array(n).fill(0);
    let dangling = 0;
    for (let i = 0; i < n; i++) if (!out[i]) dangling += r[i];
    for (const e of edges) next[e.to] += d * r[e.from] * (e.w / out[e.from]);
    let delta = 0;
    for (let i = 0; i < n; i++) { next[i] += (1 - d + d * dangling) * rs[i]; delta += Math.abs(next[i] - r[i]); }
    r = next;
    if (delta < tol) break;
  }
  return r;
}

// Rank (file, definition) pairs for a task. `map` must come from buildRepoMap(files, { refs: true }).
// opts.focus: paths in play (read/edited); opts.query: the user's message. Returns
// { files: [{ path, rank }], defs: [{ path, name, kind, line, rank }] }, both best-first.
function rankRepoMap(map, opts) {
  opts = opts || {};
  const files = (map && map.files) || [];
  const idx = new Map(files.map((f, i) => [f.path, i]));
  const definers = new Map(); // name -> [file index]
  files.forEach((f, i) => { for (const s of f.symbols || []) { const a = definers.get(s.name) || []; if (!a.includes(i)) a.push(i); definers.set(s.name, a); } });
  const { idents, words, paths } = mentionsOf(opts.query);
  const focus = new Set();
  for (const p of opts.focus || []) { const k = String(p).replace(/^\.\//, ""); if (idx.has(k)) focus.add(idx.get(k)); }
  for (const p of paths) for (const [fp, i] of idx) if (fp === p || fp.endsWith("/" + p)) focus.add(i);
  // Edge weight for "file A uses name X that file B defines". Names defined in many files
  // (get, init, data, run) say little about which one is meant, so they are scaled down, as are
  // _private names; a name the user mentioned counts ten times; repeated use grows only as sqrt.
  const nameWeight = (name) => {
    const k = (definers.get(name) || []).length;
    let w = 1;
    if (idents.has(name)) w *= 10;
    else if (words.has(name.toLowerCase())) w *= 3;
    // A long camelCase / snake_case name almost always means one specific thing; a plain
    // lowercase word (get, list, trim, first) is mostly a built-in method or a local.
    if (name.length >= 8 && /[a-z][A-Z]|_[a-z]/.test(name)) w *= 10;
    else if (GENERIC.has(name) || /^[a-z]{1,4}$/.test(name)) w *= 0.02;
    else if (/^[a-z]+$/.test(name)) w *= 0.1;
    if (/^_/.test(name)) w *= 0.1;
    if (k > 5) w *= 0.1;
    else if (k > 1) w *= 1 / k;
    return w;
  };
  const edgeMap = new Map(), contrib = []; // contrib: [from, to, name, w] for distributing rank to definitions
  files.forEach((f, a) => {
    if (!f.refs) return;
    for (const [name, count] of f.refs) {
      const defs = definers.get(name);
      if (!defs) continue;
      const w = nameWeight(name) * Math.sqrt(count);
      for (const b of defs) {
        if (b === a) continue;
        const key = a + ">" + b;
        edgeMap.set(key, (edgeMap.get(key) || 0) + w);
        contrib.push([a, b, name, w]);
      }
    }
  });
  const edges = [...edgeMap].map(([k, w]) => { const [from, to] = k.split(">").map(Number); return { from, to, w }; });
  const restart = files.map((f, i) => {
    let r = 0;
    if (focus.has(i)) r += 1;
    for (const s of f.symbols || []) if (idents.has(s.name)) { r += 1; break; }
    return r;
  });
  const rank = pageRank(files.length, edges, restart);
  // A definition's score is the rank that flows into it along its edges. Definitions nobody
  // references get a small share of their own file's rank so a focused file's outline still
  // shows; a definition the user named is lifted above the rest.
  const outW = new Array(files.length).fill(0);
  for (const e of edges) outW[e.from] += e.w;
  const defScore = new Map(); // "i\0name" -> score
  for (const [a, b, name, w] of contrib) { const k = b + "\0" + name; defScore.set(k, (defScore.get(k) || 0) + rank[a] * w / outW[a]); }
  const defs = [];
  files.forEach((f, i) => {
    for (const s of f.symbols || []) {
      let sc = defScore.get(i + "\0" + s.name) || rank[i] * 0.01;
      const named = idents.has(s.name);
      if (named) sc += rank[i] + 1;
      defs.push({ path: f.path, name: s.name, kind: s.kind, line: s.line, rank: sc, named });
    }
  });
  defs.sort((x, y) => y.rank - x.rank || x.path.localeCompare(y.path) || x.line - y.line);
  const rankedFiles = files.map((f, i) => ({ path: f.path, rank: rank[i] + (focus.has(i) ? 1 : 0) }))
    .sort((x, y) => y.rank - x.rank || x.path.localeCompare(y.path));
  return { files: rankedFiles, defs };
}

// Rough token estimate used for budgeting (about 4 characters per token for code).
const estTokens = (s) => Math.ceil(String(s).length / 4);

// Render the top-ranked definitions grouped by file, as many as fit in opts.tokens (default
// 1024). Binary-searches the number of definitions, so the output never exceeds the budget.
// Signatures only: file path, then "name:line" per definition, files in rank order.
// Definitions scoring under opts.minShare (default 2%) of the best one the user did not name are
// dropped even when they would fit: past that point the list is noise that costs tokens.
function renderRanked(map, ranked, opts) {
  opts = opts || {};
  const budget = opts.tokens || 1024;
  const all = (ranked && ranked.defs) || [];
  const best = (all.find((d) => !d.named) || { rank: 0 }).rank;
  const floor = best * (opts.minShare == null ? 0.02 : opts.minShare);
  const defs = all.filter((d) => d.named || d.rank >= floor);
  // Files appear in the order of their best-ranked definition.
  const fileOrder = new Map();
  for (const d of defs) if (!fileOrder.has(d.path)) fileOrder.set(d.path, fileOrder.size);
  const head = "Repository map (ranked for this task): " + ((map && map.fileCount) || 0) + " source files; most relevant definitions first.";
  const build = (k) => {
    const byFile = new Map();
    for (const d of defs.slice(0, k)) { if (!byFile.has(d.path)) byFile.set(d.path, []); byFile.get(d.path).push(d); }
    const order = [...byFile.keys()].sort((a, b) => (fileOrder.get(a) ?? 1e9) - (fileOrder.get(b) ?? 1e9) || a.localeCompare(b));
    const lines = [head];
    for (const p of order) lines.push("  " + p + "  — " + byFile.get(p).sort((x, y) => x.line - y.line).map((d) => d.name + (d.kind === "class" || d.kind === "type" ? "*" : "") + ":" + d.line).join(", "));
    if (k < all.length) lines.push("  … " + (all.length - k) + " lower-ranked definitions not shown.");
    return lines.join("\n");
  };
  if (estTokens(head) > budget) return "";
  let lo = 0, hi = defs.length;
  while (lo < hi) { const mid = Math.ceil((lo + hi) / 2); if (estTokens(build(mid)) <= budget) lo = mid; else hi = mid - 1; }
  const text = build(lo);
  return estTokens(text) <= budget ? text : head;
}

module.exports = { buildRepoMap, renderRepoMap, extractSymbols, findSymbol, isSourceFile, scoreFile, IGNORE_DIRS, EXT_LANG, extractRefs, mentionsOf, pageRank, rankRepoMap, renderRanked, estTokens };

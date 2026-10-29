"use strict";
// Dependency hygiene for JS/TS projects. Cross-references package.json against the
// import/require statements actually in the source to surface:
//   • declared-but-unused deps  (candidates for removal / smaller install)
//   • imported-but-undeclared    (missing from package.json — a supply-chain risk)
// The parsers (packageName, parseImports, auditDeps) are pure + unit-tested;
// scanImports walks the tree.
const fs = require("fs"), path = require("path");

const BUILTINS = new Set(("assert async_hooks buffer child_process cluster console constants crypto " +
  "dgram diagnostics_channel dns domain events fs http http2 https inspector module net os path " +
  "perf_hooks process punycode querystring readline repl stream string_decoder timers tls " +
  "trace_events tty url util v8 vm wasi worker_threads zlib").split(" "));
const CODE = /\.(js|jsx|ts|tsx|mjs|cjs|mts|cts|vue|svelte|astro)$/i; // .vue/.svelte/.astro: the imports are in their script blocks
const SKIP = /(^|\/)(\.git|node_modules|\.nexus|dist|build|\.cache|\.next|target|__pycache__|vendor)(\/|$)/;

// Anything under node: is a built-in, including the prefix-only modules (node:test, node:sqlite,
// node:sea) that the bare-name list cannot hold: "test" alone is an ordinary npm package.
function isBuiltin(spec) { const s = String(spec || ""); return s.startsWith("node:") || BUILTINS.has(s.split("/")[0]); }

// packageName("lodash/fp") -> "lodash"; "@babel/core/lib" -> "@babel/core".
// Returns null for relative paths (./ ../ /) and Node built-ins.
function packageName(spec) {
  if (!spec || /^[./]/.test(spec) || /^~\//.test(spec)) return null; // ~/x is a path alias (Nuxt, Vite, tsconfig paths), not a package named ~
  if (isBuiltin(spec)) return null;
  const s = spec.replace(/^node:/, "");
  const n = s[0] === "@" ? s.split("/").slice(0, 2).join("/") : s.split("/")[0];
  // only a valid npm name: drops "#internal" subpath imports, "dart:io"/"https://..." schemes and stray text
  return /^(?:@[a-z0-9~][\w.~-]*\/)?[a-z0-9~][\w.~-]*$/i.test(n) ? n : null;
}

// Comments blanked to spaces (newlines kept, so line-start patterns still hold): a
// commented-out require("x") is not a dependency, and --strict failed CI over it.
// Strings are skipped whole so "http://..." is not taken for a comment.
function stripComments(text) {
  let out = "", i = 0; const n = text.length;
  while (i < n) {
    const c = text[i], d = text[i + 1];
    if (c === "/" && d === "/") { const e = text.indexOf("\n", i); const end = e < 0 ? n : e; out += " ".repeat(end - i); i = end; continue; }
    if (c === "/" && d === "*") { const e = text.indexOf("*/", i + 2); const end = e < 0 ? n : e + 2; out += text.slice(i, end).replace(/[^\n]/g, " "); i = end; continue; }
    if (c === "\"" || c === "'" || c === "`") { let j = i + 1; while (j < n && text[j] !== c && !(c !== "`" && text[j] === "\n")) j += text[j] === "\\" ? 2 : 1; out += text.slice(i, j + 1); i = j + 1; continue; }
    out += c; i++;
  }
  return out;
}

// parseImports(text) -> raw specifiers from require()/import/export-from/import().
function parseImports(text) {
  const out = []; text = stripComments(String(text == null ? "" : text));
  // A specifier is one quoted token with no whitespace; static import/export must start a
  // statement - otherwise `name === "import"` or a sentence in a string captured
  // everything up to the next quote as a "package".
  const patterns = [
    /\brequire\(\s*["'`]([^"'`\s]+)["'`]\s*\)/g,
    /(?:^|[;}])[ \t]*(?:import|export)\b[^;"'`]*?\bfrom\s*["']([^"'\s]+)["']/gm,
    /(?:^|[;}])[ \t]*import\s*["']([^"'\s]+)["']/gm,
    /\bimport\(\s*["'`]([^"'`\s]+)["'`]\s*\)/g,
  ];
  for (const re of patterns) { let m; while ((m = re.exec(text))) out.push(m[1]); }
  return out;
}

// auditDeps({ pkg, specifiers }) -> { declared, used, unused, missing }
function auditDeps(opts) {
  opts = opts || {}; const pkg = opts.pkg || {};
  const declared = new Set([].concat(
    Object.keys(pkg.dependencies || {}), Object.keys(pkg.devDependencies || {}),
    Object.keys(pkg.optionalDependencies || {}), Object.keys(pkg.peerDependencies || {})));
  const used = new Set();
  for (const spec of (opts.specifiers || [])) { const n = packageName(spec); if (n && n !== pkg.name) used.add(n); } // a self-import is not a dependency
  // @types/* are loaded by TypeScript automatically (typeRoots), never imported: not "unused"
  const unused = [...declared].filter((d) => !used.has(d) && !d.startsWith("@types/")).sort();
  const missing = [...used].filter((u) => !declared.has(u)).sort();
  return { declared: [...declared].sort(), used: [...used].sort(), unused, missing };
}

// scanImports(cwd, opts) -> deduped specifier array from all JS/TS source files.
function scanImports(cwd, opts) {
  opts = opts || {};
  const maxFiles = opts.maxFiles || 8000, maxBytes = opts.maxBytes || 1000000;
  const set = new Set(); let files = 0;
  const walk = (d) => {
    if (files >= maxFiles) return;
    let ents; try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch (_) { return; }
    if (d !== cwd && ents.some((e) => e.name === "package.json" && e.isFile())) return; // a nested package (functions/, packages/x) has its own deps
    for (const e of ents) {
      if (files >= maxFiles) return;
      const fp = path.join(d, e.name);
      if (SKIP.test(e.name)) continue;
      if (e.isDirectory()) walk(fp);
      else if (CODE.test(e.name)) { try { if (fs.statSync(fp).size > maxBytes) continue; files++; for (const s of parseImports(fs.readFileSync(fp, "utf8"))) set.add(s); } catch (_) {} }
    }
  };
  walk(cwd);
  return [...set];
}

module.exports = { BUILTINS, isBuiltin, packageName, parseImports, auditDeps, scanImports };

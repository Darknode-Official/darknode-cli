"use strict";
// code_search — find the part of the codebase a question is about ("where do we retry failed
// uploads") when the exact string to grep for is unknown. Ranks ~60-line chunks with BM25
// (lib/nexus/bm25.js) over the index the TUI's /index command keeps in .nexus/index.json, building
// it on first use. Each hit comes back as path:start-end plus the lines inside it that mention the
// query's words, read fresh from disk, so the agent reads or edits exactly that range next.
// A hit file changed since the index was built triggers one rebuild, so ranges never go stale.

const fs = require("fs");
const path = require("path");
const bm25 = require("./bm25");

const SKIP = /(^|\/)(\.git|node_modules|\.nexus|dist|build|\.cache|\.next|target|__pycache__)(\/|$)/;
const CODE = /\.(js|jsx|ts|tsx|mjs|cjs|py|rb|go|rs|java|c|h|cpp|cc|cs|php|swift|kt|sh|css|scss|html|json|md|yml|yaml|toml)$/i;
const GEN = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|Cargo\.lock)$|\.(min\.js|min\.css|map)$/;
const MAX_FILE = 2000000, MAX_BYTES = 64 * 1024 * 1024, MAX_FILES = 4000;

const indexPath = (cwd) => path.join(cwd, ".nexus", "index.json");

// Source files under cwd as [{ path, content }] (relative paths), skipping vendored, built and
// generated files; capped so a huge tree can't stall the agent.
function collectFiles(cwd) {
  const list = []; let bytes = 0;
  const walk = (d) => {
    let ents; try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch (_) { return; }
    for (const e of ents) {
      if (list.length >= MAX_FILES) return;
      if (SKIP.test(e.name)) continue;
      const fp = path.join(d, e.name);
      if (e.isDirectory()) walk(fp);
      else if (e.isFile() && CODE.test(e.name) && !GEN.test(e.name)) {
        try { if (fs.statSync(fp).size > MAX_FILE || bytes > MAX_BYTES) continue; const txt = fs.readFileSync(fp, "utf8"); bytes += txt.length; list.push({ path: path.relative(cwd, fp).split(path.sep).join("/"), content: txt }); } catch (_) {}
      }
    }
  };
  walk(cwd);
  return list;
}

// The stored index if it is from this BM25 version, else null.
function loadIndex(cwd) {
  try { const raw = JSON.parse(fs.readFileSync(indexPath(cwd), "utf8").replace(/^﻿/, "")); if (raw && raw.version === bm25.VERSION && raw.docs) return raw; } catch (_) {}
  return null;
}

// Index cwd and store it in .nexus/index.json (best effort: a read-only tree still gets an index in memory).
function buildAndSave(cwd) {
  const list = collectFiles(cwd);
  const index = Object.assign(bm25.buildIndex(list), { files: list.length, ts: Date.now() });
  try { fs.mkdirSync(path.join(cwd, ".nexus"), { recursive: true }); fs.writeFileSync(indexPath(cwd), JSON.stringify(index)); } catch (_) {}
  return index;
}

// Lines inside [start, end] that contain a query word, numbered, at most `max`.
function matchingLines(text, start, end, terms, max) {
  const lines = String(text).split("\n").slice(start - 1, end);
  const out = [];
  for (let i = 0; i < lines.length && out.length < max; i++) {
    const toks = bm25.tokenize(lines[i]);
    if (toks.some((t) => terms.has(t))) out.push((start + i) + ": " + lines[i].trim().slice(0, 160));
  }
  return out;
}

// a: { query, k?, path? }. Never throws; returns { error } on bad input.
function codeSearchTool(a, cwd, deps) {
  a = a || {};
  const query = String(a.query || a.q || a.question || "").trim();
  if (!query) return { error: "code_search needs {query} — describe what the code does, e.g. {query:\"where failed uploads are retried\"}" };
  const k = Math.max(1, Math.min(20, Number(a.k || a.limit) || 6));
  const under = a.path ? String(a.path).replace(/^\.\//, "").replace(/\/+$/, "") : "";
  const root = path.resolve(cwd);
  let index = loadIndex(cwd), built = false;
  if (!index) { index = buildAndSave(cwd); built = true; }
  const run = () => bm25.search(index, query, { k: under ? k + 30 : k }).filter((h) => !under || h.path === under || h.path.startsWith(under + "/")).slice(0, k);
  let hits = run();
  // a hit file edited (or deleted) after the index was built: its line ranges may be off, rebuild once
  if (!built && hits.some((h) => { try { return fs.statSync(path.join(root, h.path)).mtimeMs > (index.ts || 0); } catch (_) { return true; } })) {
    index = buildAndSave(cwd); built = true; hits = run();
  }
  const terms = new Set(bm25.tokenize(query));
  const results = [];
  for (const h of hits) {
    const fp = path.resolve(root, h.path);
    if (fp !== root && !fp.startsWith(root + path.sep)) continue; // an index entry pointing outside the project
    let text = ""; try { text = fs.readFileSync(fp, "utf8"); } catch (_) { continue; }
    results.push({ path: h.path, lines: h.start + "-" + h.end, score: Math.round(h.score * 100) / 100, matches: matchingLines(text, h.start, h.end, terms, 6) });
  }
  const out = { query, results, indexed_files: index.files || 0 };
  if (built) out.note = "index built now (" + (index.files || 0) + " files); later searches reuse .nexus/index.json";
  if (!results.length) out.hint = "no chunk matched those words — try other words for the same idea, or grep for an exact string";
  return out;
}

module.exports = { codeSearchTool, collectFiles, loadIndex, buildAndSave, matchingLines };

"use strict";
// search — the agent's grep. Results are grouped under each file name (the
// path is written once, not on every line), long lines are cut to a window
// AROUND the match (so a hit at column 900 of a minified line is still
// visible), binary files are skipped, and optional context lines show the code
// around each hit — usually saving the follow-up read_file entirely.
// Generated files (lockfiles, *.min.js, source maps) are skipped when walking
// a folder unless asked for; the result says how many were skipped.

const fs = require("fs");
const path = require("path");

const SKIP_DIR = /^(\.git|node_modules|dist|build|out|coverage|\.nexus|\.cache|\.next|__pycache__|\.venv|venv|target)$/;
const GENERATED = /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock|poetry\.lock|composer\.lock|Gemfile\.lock|go\.sum)$|\.(min\.js|min\.css|map)$/;
const MAX_FILE = 1024 * 1024;
const WIN = 200; // chars shown per line

const { globToRe } = require("./glob"); // shared glob (lib/nexus/glob.js)

// Cut a long line to a window around the first match.
function clipLine(line, re) {
  const t = line.replace(/\t/g, "  ");
  if (t.length <= WIN) return t.trimEnd();
  re.lastIndex = 0;
  const m = re.exec(t);
  const at = m ? m.index : 0;
  const start = Math.max(0, Math.min(at - 60, t.length - WIN));
  return (start > 0 ? "…" : "") + t.slice(start, start + WIN).trim() + (start + WIN < t.length ? "…" : "");
}

// A glob written from the project root (src/**/*.c) still matches when the search
// starts in a subfolder (path:"src"), where the walk-relative path is a/x.c.
function cwdRel(cwd, dir, name) { return path.relative(cwd, path.join(dir, name)).split(path.sep).join("/"); }

// grep / ripgrep syntax that JS regex reads differently: POSIX classes ([[:space:]] was a class
// of ":aceps[" then a literal "]", so it silently matched the wrong text) and inline flags
// ((?i)foo, (?i:foo) were rejected and searched as plain text; Node 20 has no scoped flags, so a
// (?i:...) group makes the whole search case-insensitive - more hits, never fewer).
const POSIX = { alpha: "A-Za-z", digit: "0-9", alnum: "A-Za-z0-9", upper: "A-Z", lower: "a-z", space: "\\s", blank: " \\t", word: "\\w", xdigit: "0-9A-Fa-f", punct: "!-\\/:-@\\[-`{-~", cntrl: "\\x00-\\x1f\\x7f", print: "\\x20-\\x7e", graph: "\\x21-\\x7e" };
function grepToJs(pat, flags) {
  let s = String(pat);
  const lead = /^\(\?([imsx]+)\)/.exec(s);
  if (lead) { s = s.slice(lead[0].length); for (const f of lead[1]) if ((f === "i" || f === "s" || f === "m") && !flags.includes(f)) flags += f; }
  s = s.replace(/(?<!\\)\(\?([ims]+)(?=:)/g, (m, fl) => { if (fl.includes("i") && !flags.includes("i")) flags += "i"; return "(?"; });
  s = s.replace(/(?<!\\)\[:([a-z]+):\]/g, (m, n) => Object.prototype.hasOwnProperty.call(POSIX, n) ? POSIX[n] : m);
  return { src: s, flags };
}

function searchTool(a, cwd, rp) {
  const pat = a.pattern || a.query || a.q;
  if (!pat) return { error: "search needs a pattern" };
  const flags = a.case_sensitive || a.caseSensitive ? "" : "i";
  let re, badRe;
  if (a.literal) re = new RegExp(String(pat).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), flags);
  else { try { const g = grepToJs(pat, flags); re = new RegExp(g.src, g.flags); } catch (e) { badRe = e.message.replace(/^Invalid regular expression: /, ""); re = new RegExp(String(pat).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), flags); } }
  const ctx = Math.max(0, Math.min(5, a.context | 0));
  const max = Math.max(1, Math.min(500, a.max_results || a.max || 100));
  const globs = [].concat(a.glob || a.include || []).filter(Boolean).map(globToRe);
  let root;
  try { root = rp(a.path || "."); } catch (e) { return { error: e.message }; }
  let st; try { st = fs.statSync(root); } catch (_) { return { error: "no such path: " + (a.path || ".") }; }
  const single = st.isFile();
  const blocks = [];
  let hits = 0, files = 0, skippedGen = 0, truncated = false;

  const scan = (fp) => {
    const rel = path.relative(cwd, fp) || path.basename(fp);
    let txt;
    try { if (fs.statSync(fp).size > MAX_FILE) return; txt = fs.readFileSync(fp, "utf8"); } catch (_) { return; }
    if (txt.indexOf("\u0000") >= 0) return; // binary
    const lines = txt.replace(/^\uFEFF/, "").split(/\r?\n/); // a BOM is not text: ^using on line 1 missed it. CRLF files: a trailing \r made "foo;$" never match
    if (lines.length > 1 && lines[lines.length - 1] === "") lines.pop(); // trailing newline is not a line
    const hitIdx = [];
    for (let i = 0; i < lines.length; i++) { re.lastIndex = 0; if (re.test(lines[i])) { hitIdx.push(i); if (hits + hitIdx.length >= max) break; } }
    if (!hitIdx.length) return;
    files++; hits += hitIdx.length;
    const out = [rel];
    let last = -1;
    for (const i of hitIdx) {
      const from = Math.max(0, i - ctx, last + 1), to = Math.min(lines.length - 1, i + ctx);
      if (ctx && last >= 0 && from > last + 1) out.push("  --");
      for (let k = from; k <= to; k++) { if (k <= last) continue; out.push("  " + (k + 1) + (k === i || hitIdx.includes(k) ? ": " : "- ") + clipLine(lines[k], re)); last = k; }
    }
    blocks.push(out.join("\n"));
    if (hits >= max) truncated = true;
  };

  const walk = (dir, relDir) => {
    if (truncated) return;
    let ents; try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return; }
    ents.sort((x, y) => x.name.localeCompare(y.name));
    for (const e of ents) {
      if (truncated) return;
      const r = relDir ? relDir + "/" + e.name : e.name;
      if (e.isDirectory()) { if (!SKIP_DIR.test(e.name)) walk(path.join(dir, e.name), r); continue; }
      if (!e.isFile()) continue;
      if (globs.length && !globs.some((g) => g.test(r) || g.test(e.name) || g.test(cwdRel(cwd, dir, e.name)))) continue;
      if (!a.include_generated && GENERATED.test(r)) { skippedGen++; continue; }
      scan(path.join(dir, e.name));
    }
  };
  if (single) scan(root); else walk(root, "");

  const res = { summary: hits ? "Found " + hits + " match" + (hits === 1 ? "" : "es") + " in " + files + " file" + (files === 1 ? "" : "s") : "No matches found" };
  // lines are searched one at a time, so a pattern spanning lines can never match: say so, not just "no matches"
  if (!hits && /\\n|\n|\\r|\r/.test(String(pat))) res.summary += " (the search runs line by line, so a pattern with a line break cannot match; search one line, with context:N to see the lines around it)";
  if (badRe) res.summary += " (not a valid regex - " + badRe + " - so it was searched as plain text)"; // in the summary so batch shows it too
  if (hits) res.results = blocks.join("\n");
  if (truncated) res.truncated = "stopped at " + max + " matches — narrow the pattern, path or glob (or raise max_results)";
  if (skippedGen) res.skipped_generated = skippedGen + " lockfile/minified/source-map file" + (skippedGen === 1 ? "" : "s") + " not searched (include_generated:true to search them)";
  return res;
}

// find — files by glob (**/*.ts, src/**/*.{js,jsx}) or, with no glob characters,
// by a substring of the file name. sort:"recent" lists most recently modified
// first (what was just being worked on).
function findTool(a, cwd, rp) {
  const q = String(a.glob || a.pattern || a.name || "").trim();
  const isGlob = /[*?{[]/.test(q);
  const re = isGlob ? globToRe(q.replace(/^\.\//, "")) : null;
  const sub = q.toLowerCase();
  const max = Math.max(1, Math.min(1000, a.max_results || a.max || 300));
  let root; try { root = rp(a.path || "."); } catch (e) { return { error: e.message }; }
  const found = []; let more = false;
  const walk = (dir, relDir) => {
    let ents; try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return; }
    for (const e of ents) {
      const r = relDir ? relDir + "/" + e.name : e.name;
      if (e.isDirectory()) { if (!SKIP_DIR.test(e.name)) walk(path.join(dir, e.name), r); continue; }
      if (!e.isFile()) continue;
      const ok = !q || (re ? (re.test(r) || re.test(cwdRel(cwd, dir, e.name)) || (!q.includes("/") && re.test(e.name))) : e.name.toLowerCase().includes(sub));
      if (!ok) continue;
      if (found.length >= 20000) { more = true; return; }
      found.push(path.join(dir, e.name));
    }
  };
  walk(root, "");
  let list = found.map((fp) => ({ fp, rel: path.relative(cwd, fp) }));
  if (a.sort === "recent") { for (const x of list) { try { x.m = fs.statSync(x.fp).mtimeMs; } catch (_) { x.m = 0; } } list.sort((x, y) => y.m - x.m); }
  else list.sort((x, y) => x.rel.localeCompare(y.rel));
  const total = list.length;
  const res = { count: total, files: list.slice(0, max).map((x) => x.rel) };
  if (total > max || more) res.truncated = "showing " + Math.min(max, total) + " of " + (more ? "20000+" : total) + " — narrow the glob or path";
  if (!total) res.note = "no files match " + (q || "(any)") + (isGlob ? "" : " (substring of the file name; use a glob like **/*.ts for paths)");
  return res;
}

module.exports = { searchTool, findTool, clipLine, globToRe, GENERATED, grepToJs };

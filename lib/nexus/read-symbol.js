"use strict";
// read_symbol — read ONE function / class / method by name instead of the whole
// file. On a big file this is the difference between a few hundred tokens and
// tens of thousands. The definition line comes from repo-map's symbol
// extractor; the end is found by bracket matching (C-like languages, skipping
// strings and comments) or by indentation (Python, YAML-ish). Lines come back
// numbered, so an edit can target them directly.

const fs = require("fs");
const path = require("path");

const MAX_LINES = 600;

// End line (0-based, inclusive) of a brace-delimited block starting at line s.
function braceEnd(lines, s, js, rust) {
  let depth = 0, opened = false, inBlock = false;
  for (let i = s; i < lines.length && i < s + 5000; i++) {
    const l = lines[i];
    let q = null;
    for (let k = 0; k < l.length; k++) {
      const c = l[k], n = l[k + 1];
      if (inBlock) { if (c === "*" && n === "/") { inBlock = false; k++; } continue; }
      if (q) { if (c === "\\") k++; else if (c === q) q = null; continue; }
      if (c === "/" && n === "/") break;
      if (c === "#" && /^\s*#/.test(l) && !opened) break; // preprocessor / shell-ish comment before the body
      if (c === "/" && n === "*") { inBlock = true; k++; continue; }
      // Rust: ' is a char literal only when it closes like one ('x', '\n', '\u{1F600}'); otherwise a lifetime ('a)
      if (rust && c === "'") { const m = l.slice(k).match(/^'(?:\\(?:u\{[0-9a-fA-F]+\}|x[0-9a-fA-F]{2}|.)|[^\\'])'/); if (m) k += m[0].length - 1; continue; }
      if (c === '"' || c === "'" || c === "`") { q = c; continue; }
      // JS/TS regex literal: a "/" where an expression starts (after ( , = : [ ! & | ? { } ; or `return`)
      if (js && c === "/" && /(?:^|[(,=:[!&|?{};]|\breturn)\s*$/.test(l.slice(0, k))) {
        let cls = false, j = k + 1;
        for (; j < l.length; j++) { const d = l[j]; if (d === "\\") { j++; continue; } if (cls) { if (d === "]") cls = false; } else if (d === "[") cls = true; else if (d === "/") break; }
        if (j < l.length) { k = j; continue; }
      }
      if (c === "{") { depth++; opened = true; }
      else if (c === "}") { depth--; if (opened && depth <= 0) return i; }
    }
    if (q !== "`") q = null; // ordinary strings don't span lines
    // a declaration with no body ends at its `;` (`type X = Y;`, `const a = 1;`, or an arrow/type
    // continued onto the next line) — not at the next function's closing brace
    if (!opened && /;\s*$/.test(l)) return i;
    if (!opened && i > s + 8) return s; // no body found near the definition
  }
  return opened ? Math.min(lines.length - 1, s + 5000) : s;
}

// End line of an indentation block (Python): everything indented deeper than the def line.
function indentEnd(lines, s) {
  const ind = (l) => l.match(/^\s*/)[0].length;
  const base = ind(lines[s]);
  // the header runs until its brackets close (a multi-line signature); if it
  // doesn't then end with ':' it is a one-liner (`def x(self): return 1`)
  let h = s, d = 0;
  for (; h < lines.length && h < s + 20; h++) {
    for (const c of lines[h]) { if ("([{".includes(c)) d++; else if (")]}".includes(c)) d--; }
    if (d <= 0) break;
  }
  if (h >= lines.length || !/:\s*(#.*)?$/.test(lines[h])) return Math.min(h, lines.length - 1);
  // a comment line (commented-out code at column 0) and the inside of a triple-quoted string
  // (SQL / text flush left) don't close the block - both cut a function off after one line
  const triple = (l, open) => { for (const m of l.matchAll(/"""|'''/g)) open = !open ? m[0] : m[0] === open ? null : open; return open; };
  let end = h, str = null;
  for (let i = h + 1; i < lines.length; i++) {
    const l = lines[i];
    if (str) { end = i; str = triple(l, str); continue; }
    if (!l.trim() || (/^\s*#/.test(l) && ind(l) <= base)) continue;
    if (ind(l) <= base) break;
    end = i; str = triple(l, null);
  }
  return end;
}

function blockEnd(lines, s, file) {
  const ext = path.extname(file).toLowerCase();
  if ([".py", ".pyi", ".yaml", ".yml", ".nim", ".coffee"].includes(ext)) return indentEnd(lines, s);
  if ([".rb", ".lua", ".ex", ".exs"].includes(ext)) { // `end`-terminated: match the def's indentation
    const base = lines[s].match(/^\s*/)[0].length;
    // one-line defs (def a; 1; end / def a = 1 / function a() return 1 end / def a, do: 1) close on their own line
    if (/\bend\s*(#.*|--.*)?$/.test(lines[s]) || /^\s*def\s+[\w.?!]+\s*(\([^)]*\))?\s*=(?![=~>])/.test(lines[s]) || /,\s*do:/.test(lines[s])) return s;
    for (let i = s + 1; i < lines.length; i++) if (/^\s*end\b/.test(lines[i]) && lines[i].match(/^\s*/)[0].length === base) return i;
    return s;
  }
  return braceEnd(lines, s, /^\.(m?[jt]sx?|cjs|cts|mts)$/.test(ext), ext === ".rs");
}

// Pull in doc comments / decorators directly above the definition.
function leadStart(lines, s) {
  let i = s;
  while (i > 0) {
    const p = lines[i - 1].trim();
    if (/^(\/\/|\/?\*|#(?!!)|@|"""|\*\/)/.test(p) && i > s - 40) i--;
    else break;
  }
  return i;
}

function readSymbolTool(a, cwd, rp, deps) {
  const file = a.path || a.file;
  const name = String(a.name || a.symbol || "").trim();
  if (!file || !name) return { error: "read_symbol needs {path, name} — e.g. {path:\"src/app.js\", name:\"handleLogin\"}; use outline to list a file's symbols" };
  let fp, txt;
  try { fp = rp(file); txt = fs.readFileSync(fp, "utf8"); } catch (e) { return { error: e.message }; }
  const extract = (deps && deps.extractSymbols) || require("./repo-map").extractSymbols;
  const syms = extract(path.basename(fp), txt, { max: 2000, all: true }) || [];
  const short = name.includes(".") ? name.split(".").pop() : name;
  let hits = syms.filter((s) => s.name === name || s.name === short);
  if (!hits.length) hits = syms.filter((s) => s.name.toLowerCase() === short.toLowerCase());
  if (hits.length > 1 && name.includes(".")) { // Owner.member: prefer the definition inside Owner
    const owner = name.split(".").slice(-2, -1)[0], ls = txt.split("\n");
    const inside = hits.filter((h) => syms.some((o) => o.name === owner && o.line < h.line && blockEnd(ls, o.line - 1, file) >= h.line - 1));
    if (inside.length) hits = inside;
  }
  if (!hits.length) {
    const near = syms.filter((s) => s.name.toLowerCase().includes(short.toLowerCase())).slice(0, 8).map((s) => s.name);
    return { error: "no symbol \"" + name + "\" in " + path.relative(cwd, fp) + (near.length ? " — similar: " + near.join(", ") : " — use outline to list its symbols") };
  }
  const lines = txt.split("\n");
  const idx = Math.max(0, Math.min(hits.length - 1, (a.index | 0)));
  const h = hits[idx];
  const s0 = Math.max(0, (h.line | 0) - 1);
  const start = a.with_comments === false ? s0 : leadStart(lines, s0);
  let end = blockEnd(lines, s0, fp);
  let note;
  if (end - start + 1 > MAX_LINES) { end = start + MAX_LINES - 1; note = "symbol is longer than " + MAX_LINES + " lines — showing the first " + MAX_LINES + "; read_file with offset " + (end + 2) + " continues"; }
  const w = String(end + 1).length;
  const content = lines.slice(start, end + 1).map((l, i) => String(start + i + 1).padStart(w) + "  " + l).join("\n");
  const out = { file: path.relative(cwd, fp), symbol: h.name, kind: h.kind, lines: (start + 1) + "-" + (end + 1), of: lines.length, content };
  if (hits.length > 1) out.otherDefinitions = hits.filter((_, i) => i !== idx).map((x) => ({ line: x.line, kind: x.kind })).slice(0, 10).map((x, i) => "index " + (i < idx ? i : i + 1) + ": line " + x.line + " (" + x.kind + ")").join(", ") + " — pass index:N to read another";
  if (note) out.note = note;
  return out;
}

module.exports = { readSymbolTool, braceEnd, indentEnd, blockEnd };

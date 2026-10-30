"use strict";
// Answer renderer for the Nexus TUI: turns model markdown into terminal lines.
// Pure (no I/O, no terminal state) so it can be unit-tested from strings.
//
//   renderMd(text, width, C) -> string[]   one entry per screen row, already coloured
//
// C supplies the painters, so colour stays the caller's decision (NO_COLOR, themes):
//   { inline(line), gray, dim, mag, green, yellow, cyan, red, bold, italic, underline }
// `inline` paints one prose row (headings, bold, inline code, bullets).
//
// Handles: fenced code (language-aware highlighting, gutter, label), ```diff,
// pipe tables (aligned; stacked records when too wide), block quotes, rules and
// [text](url) links. Streaming-safe: an unclosed fence or a table whose separator
// row hasn't arrived yet renders as code / plain text until the rest streams in.
const { ansiWrap, strWidth, sanitizeTerm } = require("./tui-format");
const { trimUrl } = require("./links");

const id = (s) => s;
const stripSgr = (s) => String(s).replace(/\x1b\[[0-9;]*m/g, "");

// ---- syntax highlighting ----------------------------------------------------
const kw = (s) => new Set(s.split(" "));
const JS = kw("break case catch class const continue debugger default delete do else export extends finally for from function if import in instanceof let new of return static super switch this throw try typeof var void while with yield async await true false null undefined interface type enum implements private protected public readonly abstract declare namespace as satisfies keyof");
const LANGS = {
  js: { kw: JS, line: "//", block: true },
  py: { kw: kw("and as assert async await break class continue def del elif else except finally for from global if import in is lambda nonlocal not or pass raise return try while with yield True False None self match case"), line: "#", triple: true },
  sh: { kw: kw("if then else elif fi for while until do done case esac in function return local export readonly declare unset shift exit set source echo cd sudo"), line: "#", vars: true },
  go: { kw: kw("break case chan const continue default defer else fallthrough for func go goto if import interface map package range return select struct switch type var true false nil iota"), line: "//", block: true },
  rust: { kw: kw("as async await break const continue crate dyn else enum extern false fn for if impl in let loop match mod move mut pub ref return self Self static struct super trait true type unsafe use where while Some None Ok Err"), line: "//", block: true },
  c: { kw: kw("auto break case char const continue default do double else enum extern float for goto if inline int long register return short signed sizeof static struct switch typedef union unsigned void volatile while bool true false nullptr class public private protected virtual override template typename namespace using new delete this throw try catch include define ifdef ifndef endif"), line: "//", block: true },
  java: { kw: kw("abstract boolean break byte case catch char class const continue default do double else enum extends final finally float for if implements import instanceof int interface long native new null package private protected public return short static super switch synchronized this throw throws try void volatile while true false var val fun when object override string using namespace"), line: "//", block: true },
  rb: { kw: kw("alias and begin break case class def defined do else elsif end ensure false for if in module next nil not or redo rescue retry return self super then true undef unless until when while yield require attr_accessor"), line: "#" },
  php: { kw: kw("abstract and array as break case catch class const continue declare default do echo else elseif empty extends final for foreach function global if implements include isset list namespace new or private protected public require return static switch throw trait try unset use var while true false null"), line: "//", block: true, vars: true },
  sql: { kw: kw("select from where and or not insert into values update set delete create table drop alter add index primary key foreign references join left right inner outer on group by order having limit offset as distinct union all null is in like between exists case when then else end count sum avg min max default constraint unique view grant revoke"), line: "--", block: true, ci: true },
  lua: { kw: kw("and break do else elseif end false for function goto if in local nil not or repeat return then true until while"), line: "--" },
  css: { kw: kw("important media import keyframes from to"), block: true },
  json: { kw: kw("true false null"), keys: true },
  yaml: { kw: kw("true false null yes no on off"), line: "#", yamlKeys: true },
  toml: { kw: kw("true false"), line: "#", yamlKeys: true },
  ini: { kw: kw("true false"), line: ";", yamlKeys: true },
  docker: { kw: kw("FROM RUN CMD LABEL EXPOSE ENV ADD COPY ENTRYPOINT VOLUME USER WORKDIR ARG ONBUILD STOPSIGNAL HEALTHCHECK SHELL AS"), line: "#" },
  plain: { kw: new Set(), line: null },
};
const ALIAS = {
  javascript: "js", jsx: "js", ts: "js", tsx: "js", typescript: "js", mjs: "js", cjs: "js", node: "js",
  python: "py", python3: "py", py3: "py", bash: "sh", shell: "sh", zsh: "sh", console: "sh", shellscript: "sh", fish: "sh", ps1: "sh", powershell: "sh",
  golang: "go", rs: "rust", "c++": "c", cpp: "c", cc: "c", h: "c", hpp: "c", objc: "c", csharp: "java", cs: "java", kotlin: "java", kt: "java", scala: "java", swift: "java", dart: "java",
  ruby: "rb", postgres: "sql", postgresql: "sql", mysql: "sql", sqlite: "sql", plsql: "sql", scss: "css", less: "css",
  jsonc: "json", json5: "json", yml: "yaml", dockerfile: "docker", conf: "ini", cfg: "ini", env: "ini", properties: "ini",
  text: "plain", txt: "plain", "": "plain",
};
function langOf(tag) {
  const t = String(tag || "").trim().toLowerCase().split(/[\s{,]/)[0];
  if (Object.hasOwn(LANGS, t)) return t; // own keys: a ```constructor fence is an unknown language, not Object
  if (Object.hasOwn(ALIAS, t)) return ALIAS[t];
  return null; // unknown: generic strings/numbers/comments
}

// Highlight one code line. `st` carries multi-line state (block comment, py
// triple-quote) between lines of the same fence; it is mutated in place.
function highlight(line, lang, C, st) {
  const L = (Object.hasOwn(LANGS, lang) && LANGS[lang]) || { kw: new Set(), line: "#", generic: true };
  const s = sanitizeTerm(stripSgr(line));
  const com = (x) => C.gray(x), str = (x) => C.green(x), num = (x) => C.yellow(x), key = (x) => C.mag(x), fn = (x) => C.cyan(x), vr = (x) => C.cyan(x);
  let out = "", i = 0;
  // continue an open block comment / triple-quoted string
  if (st.block) { const e = s.indexOf("*/"); if (e < 0) return com(s); out += com(s.slice(0, e + 2)); i = e + 2; st.block = false; }
  if (st.triple) { const e = s.indexOf(st.triple); if (e < 0) return str(s); out += str(s.slice(0, e + 3)); i = e + 3; st.triple = null; }
  if (L.yamlKeys && i === 0) {
    const m = s.match(/^(\s*-?\s*)([\w.\-"'\[\]]+)(\s*[:=])/);
    if (m && !s.trim().startsWith(L.line || "\0")) { out += m[1] + fn(m[2]) + m[3]; i = m[0].length; }
  }
  while (i < s.length) {
    const ch = s[i], rest = s.slice(i);
    if (L.line && rest.startsWith(L.line) && (L.line !== "#" || L.generic || lang !== "sh" || i === 0 || /\s/.test(s[i - 1]))) { out += com(rest); break; }
    if (L.generic && rest.startsWith("//")) { out += com(rest); break; }
    if (L.block && rest.startsWith("/*")) { const e = s.indexOf("*/", i + 2); if (e < 0) { out += com(rest); st.block = true; break; } out += com(s.slice(i, e + 2)); i = e + 2; continue; }
    if (L.triple && (rest.startsWith('"""') || rest.startsWith("'''"))) { const q = rest.slice(0, 3); const e = s.indexOf(q, i + 3); if (e < 0) { out += str(rest); st.triple = q; break; } out += str(s.slice(i, e + 3)); i = e + 3; continue; }
    if (ch === '"' || ch === "'" || ch === "`") {
      let j = i + 1; while (j < s.length && s[j] !== ch) j += s[j] === "\\" ? 2 : 1;
      const lit = s.slice(i, Math.min(j + 1, s.length));
      const isKey = L.keys && /^\s*:/.test(s.slice(j + 1));
      out += isKey ? fn(lit) : str(lit); i = j + 1; continue;
    }
    if (L.vars && ch === "$") { const m = rest.match(/^\$(\{[^}]*\}|[A-Za-z_]\w*|[0-9@#?*!$-])/); if (m) { out += vr(m[0]); i += m[0].length; continue; } }
    const nm = /[0-9]/.test(ch) && (i === 0 || !/[\w$]/.test(s[i - 1])) && rest.match(/^(0[xX][0-9a-fA-F_]+|0[bB][01_]+|\d[\d_]*(\.\d+)?([eE][+-]?\d+)?)\b/);
    if (nm) { out += num(nm[0]); i += nm[0].length; continue; }
    const wm = rest.match(/^[A-Za-z_$@][\w$]*/);
    if (wm) {
      const w = wm[0];
      if (L.kw.has(L.ci ? w.toLowerCase() : w)) out += key(w);
      else if (/^\s*\(/.test(s.slice(i + w.length)) && !L.ci) out += fn(w);
      else out += w;
      i += w.length; continue;
    }
    out += ch; i++;
  }
  return out;
}

function diffLine(line, C) {
  const s = sanitizeTerm(stripSgr(line));
  if (/^(\+\+\+|---)\s/.test(s)) return C.bold(s);
  if (s.startsWith("@@")) return C.cyan(s);
  if (s.startsWith("+")) return C.green(s);
  if (s.startsWith("-")) return C.red(s);
  return C.gray(s);
}

// ---- inline extras (applied before the caller's inline painter) -------------
// [text](url) -> underlined text plus the url in gray (the url is kept: a terminal
// user needs it to follow the link, and clicking it opens it). Bare URLs are
// underlined too. Never touches text inside `inline code`.
function linkify(line, C) {
  const md = /\[([^\]\n]+)\]\((https?:\/\/[^)\s]+|[^)\s]+\.[a-z]{1,5})\)|(https?:\/\/[^\s<>"'`\]\[{}|\\^]+)/g;
  return line.split(/(`[^`]*`)/).map((seg, k) => k % 2 ? seg : seg.replace(md, (_, t, u, bare) => {
    if (bare) { const url = trimUrl(bare); return C.underline(url) + bare.slice(url.length); }
    return t === u ? C.underline(u) : C.underline(t) + C.gray(" (" + u + ")");
  })).join("");
}
function italicize(line, C) {
  return line.split(/(`[^`]*`)/).map((seg, k) => k % 2 ? seg : seg.replace(/(^|[\s(])[*_]([^*_\s][^*_\n]*?[^*_\s]|[^*_\s])[*_](?=$|[\s.,;:!?)])/g, (_, a, t) => a + C.italic(t))).join("");
}

// ---- tables -----------------------------------------------------------------
const SEP_RE = /^\s*\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?\s*$/;
const isRow = (l) => /^\s*\|.*\|\s*$/.test(l) || (/\S\s*\|\s*\S/.test(l) && !/^\s*```/.test(l));
function cells(l) {
  let t = l.trim(); if (t.startsWith("|")) t = t.slice(1); if (t.endsWith("|") && !t.endsWith("\\|")) t = t.slice(0, -1);
  const out = []; let cur = "", tick = false;
  for (let i = 0; i < t.length; i++) {
    const c = t[i];
    if (c === "\\" && t[i + 1] === "|") { cur += "|"; i++; continue; }
    if (c === "`") tick = !tick;
    if (c === "|" && !tick) { out.push(cur.trim()); cur = ""; continue; }
    cur += c;
  }
  out.push(cur.trim());
  return out;
}
function renderTable(rows, align, width, C, paint) {
  const n = Math.max(...rows.map((r) => r.length));
  const P = rows.map((r) => Array.from({ length: n }, (_, k) => paint(r[k] || "")));
  const W = Array.from({ length: n }, (_, k) => Math.max(1, ...P.map((r) => strWidth(r[k]))));
  const total = W.reduce((a, b) => a + b, 0) + 3 * (n - 1) + 4;
  const bar = (l, m, r) => C.gray(l + W.map((w) => "─".repeat(w + 2)).join(m) + r);
  if (total <= width) {
    const pad = (s, w, a) => { const g = w - strWidth(s); if (a === "r") return " ".repeat(g) + s; if (a === "c") return " ".repeat(g >> 1) + s + " ".repeat(g - (g >> 1)); return s + " ".repeat(g); };
    const row = (r, head) => C.gray("│ ") + r.map((c, k) => pad(head ? C.bold(c) : c, W[k], align[k])).join(C.gray(" │ ")) + C.gray(" │");
    const out = [bar("┌", "┬", "┐"), row(P[0], true), bar("├", "┼", "┤")];
    for (let i = 1; i < P.length; i++) out.push(row(P[i], false));
    out.push(bar("└", "┴", "┘"));
    return out;
  }
  // Too wide for the terminal: one record per row, "Header: value", wrapped.
  const out = [];
  const head = rows[0];
  for (let i = 1; i < rows.length; i++) {
    if (out.length) out.push(C.gray("·"));
    for (let k = 0; k < n; k++) {
      const label = C.bold(paint(head[k] || "col " + (k + 1))) + C.gray(": ");
      const lines = ansiWrap(label + paint(rows[i][k] || ""), Math.max(4, width - 4));
      lines.forEach((ln, j) => out.push((j ? "    " : "") + ln));
    }
  }
  return out;
}

// ---- main -------------------------------------------------------------------
function renderMd(text, width, C) {
  C = Object.assign({ inline: id, gray: id, dim: id, mag: id, green: id, yellow: id, cyan: id, red: id, bold: id, italic: id, underline: id }, C || {});
  width = Math.max(10, width | 0);
  const src = String(text == null ? "" : text).replace(/\r\n?/g, "\n").split("\n");
  const out = [];
  const prose = (l) => { for (const w of ansiWrap(italicize(linkify(l, C), C), width)) out.push(C.inline(w)); };
  let fence = null; // { mark, lang, st, diff }
  for (let i = 0; i < src.length; i++) {
    const line = src[i];
    const fm = line.match(/^\s*(`{3,}|~{3,})\s*([^`\s]*)/);
    if (fence) {
      if (fm && fm[1][0] === fence.mark[0] && fm[1].length >= fence.mark.length && !fm[2]) { out.push(C.gray("╰─")); fence = null; continue; }
      const painted = fence.diff ? diffLine(line, C) : highlight(line, fence.lang, C, fence.st);
      const rows = ansiWrap(painted, Math.max(4, width - 2));
      for (const r of rows.length ? rows : [""]) out.push(C.gray("│ ") + r);
      continue;
    }
    if (fm) {
      const tag = sanitizeTerm(fm[2] || ""); // the label is echoed raw: an ESC ] in it would set the title / clipboard
      const lang = langOf(tag);
      fence = { mark: fm[1], lang: lang || "", st: {}, diff: /^(diff|patch)$/i.test(tag) };
      out.push(C.gray("╭─" + (tag ? " " + tag : "")));
      continue;
    }
    // table: a header row followed by a separator row
    if (isRow(line) && i + 1 < src.length && SEP_RE.test(src[i + 1]) && src[i + 1].includes("-")) {
      const align = cells(src[i + 1]).map((c) => (/^:-+:$/.test(c) ? "c" : /-:$/.test(c) ? "r" : "l"));
      const rows = [cells(line)];
      let j = i + 2;
      while (j < src.length && src[j].trim() && isRow(src[j])) rows.push(cells(src[j++]));
      const paint = (c) => C.inline(italicize(linkify(sanitizeTerm(c), C), C)); // cells skip ansiWrap, so strip OSC/CSI here
      out.push(...renderTable(rows, align, width, C, paint));
      i = j - 1; continue;
    }
    const q = line.match(/^\s*>\s?(.*)$/);
    if (q) { for (const w of ansiWrap(linkify(q[1], C), Math.max(4, width - 2))) out.push(C.gray("▎ ") + C.italic(C.gray(stripSgr(w).replace(/`([^`]+)`/g, "$1")))); continue; }
    if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(line)) { out.push(C.gray("─".repeat(Math.min(width, 48)))); continue; }
    if (!line.length) { out.push(""); continue; }
    prose(line);
  }
  return out;
}

module.exports = { renderMd, highlight, langOf, renderTable, cells, linkify, italicize };

"use strict";
// json_query — pull one value out of a JSON file (package.json scripts, a key in
// a big config or lockfile, one record of a data dump) instead of reading the
// whole file into context. Accepts JSONC (comments + trailing commas, as in
// tsconfig.json / VS Code settings). Path syntax: a.b.c, items[0].name,
// deps["@scope/pkg"], and * to map over every key/element.

const fs = require("fs");
const path = require("path");

const MAX_FILE = 50 * 1024 * 1024;
const MAX_OUT = 12000;

// Remove // and /* */ comments and trailing commas, leaving string contents alone.
function stripJsonc(t) {
  let o = "", q = false;
  for (let i = 0; i < t.length; i++) {
    const c = t[i], n = t[i + 1];
    if (q) { o += c; if (c === "\\") { o += n == null ? "" : n; i++; } else if (c === '"') q = false; continue; }
    if (c === '"') { q = true; o += c; continue; }
    if (c === "/" && n === "/") { while (i < t.length && t[i] !== "\n") i++; o += "\n"; continue; }
    if (c === "/" && n === "*") { i += 2; while (i < t.length && !(t[i] === "*" && t[i + 1] === "/")) i++; i++; continue; }
    o += c;
  }
  return o.replace(/,(\s*[}\]])/g, "$1");
}

// "a.b[0]['x.y'].*" → ["a","b",0,"x.y","*"]
function parsePath(q) {
  const out = [];
  const s = String(q || "").trim().replace(/^\$\.?/, "").replace(/^\./, "");
  const re = /\[\s*(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'|(-?\d+)|(\*))\s*\]|\.?([^.[\]]+)/g;
  let m, last = 0;
  while ((m = re.exec(s))) {
    if (m.index !== last) return null;
    last = re.lastIndex;
    if (m[1] != null) out.push(m[1].replace(/\\(.)/g, "$1"));
    else if (m[2] != null) out.push(m[2].replace(/\\(.)/g, "$1"));
    else if (m[3] != null) out.push(Number(m[3]));
    else if (m[4]) out.push("*");
    else out.push(/^-?\d+$/.test(m[5]) ? Number(m[5]) : m[5]);
  }
  return last === s.length ? out : null;
}

function walk(v, segs) {
  if (!segs.length) return { found: true, value: v };
  const [h, ...rest] = segs;
  if (v == null || typeof v !== "object") return { found: false };
  if (h === "*") {
    const keys = Array.isArray(v) ? v.map((_, i) => i) : Object.keys(v);
    const res = Array.isArray(v) ? [] : {};
    let any = false;
    for (const k of keys) { const r = walk(v[k], rest); if (r.found) { any = true; if (Array.isArray(res)) res.push(r.value); else res[k] = r.value; } }
    return any ? { found: true, value: res } : { found: false };
  }
  let key = h;
  if (Array.isArray(v) && typeof h === "number" && h < 0) key = v.length + h;
  if (!Object.prototype.hasOwnProperty.call(v, key)) return { found: false, at: v };
  return walk(v[key], rest);
}

const describe = (v) => Array.isArray(v) ? "array(" + v.length + ")" : v && typeof v === "object" ? "object(" + Object.keys(v).length + " keys)" : typeof v;

function jsonQueryTool(a, cwd, rp) {
  const file = a.path || a.file;
  if (!file) return { error: "json_query needs {path, query} — e.g. {path:\"package.json\", query:\"scripts\"}" };
  let fp, raw;
  try { fp = rp(file); const st = fs.statSync(fp); if (st.size > MAX_FILE) return { error: "file is " + Math.round(st.size / 1048576) + " MB — too big to parse here" }; raw = fs.readFileSync(fp, "utf8"); }
  catch (e) { return { error: e.message }; }
  let data;
  try { data = JSON.parse(raw); } catch (_) { try { data = JSON.parse(stripJsonc(raw)); } catch (e) { return { error: "not valid JSON/JSONC: " + e.message }; } }
  const q = a.query == null ? "" : String(a.query);
  const segs = parsePath(q);
  if (!segs) return { error: "could not parse query \"" + q + "\" — use a.b.c, items[0].name, deps[\"@scope/pkg\"] or * (e.g. dependencies.*)" };
  const r = walk(data, segs);
  const rel = path.relative(cwd, fp);
  if (!r.found) {
    const at = r.at;
    return { error: "\"" + q + "\" not found in " + rel + (at && typeof at === "object" && !Array.isArray(at) ? " — keys there: " + Object.keys(at).slice(0, 40).join(", ") : at && Array.isArray(at) ? " — that level is an array of " + at.length : "") };
  }
  const v = r.value;
  const out = { file: rel, query: q || "(root)", type: describe(v) };
  if (a.keys_only || a.keysOnly) { out.keys = v && typeof v === "object" ? (Array.isArray(v) ? v.length + " elements" : Object.keys(v)) : []; return out; }
  let s = JSON.stringify(v, null, 1);
  if (s.length > MAX_OUT) {
    out.truncated = true;
    out.note = "value is " + s.length + " chars — showing the start; narrow the query" + (v && typeof v === "object" && !Array.isArray(v) ? " (keys: " + Object.keys(v).slice(0, 30).join(", ") + ")" : Array.isArray(v) ? " (e.g. [0] or [-1])" : "");
    s = s.slice(0, MAX_OUT);
  }
  out.value = s;
  return out;
}

module.exports = { jsonQueryTool, parsePath, walk, stripJsonc };

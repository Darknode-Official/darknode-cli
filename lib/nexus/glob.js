"use strict";
// The one glob -> RegExp used by search/find, replace_in_files, attest, invariants and the
// governance path policy (protected / approval paths). * and ? stay inside one path
// segment, **/ spans whole directories (zero or more), {a,b} picks an alternative,
// [ch] / [!ch] match one character from / not from a set (never a /).
// Copies of this drifted: the policy one lacked braces and let **/ swallow part of a
// name, so a protected-path rule like *.{pem,key} matched nothing.
// Index of the "}" closing the "{" at i (nesting-aware), or -1.
function braceEnd(g, i) {
  for (let d = 0, k = i; k < g.length; k++) { if (g[k] === "{") d++; else if (g[k] === "}" && --d === 0) return k; }
  return -1;
}
// Split a brace body at its top-level commas: "a,{b,c},d" -> ["a", "{b,c}", "d"].
function braceAlts(body) {
  const out = []; let d = 0, start = 0;
  for (let k = 0; k < body.length; k++) { if (body[k] === "{") d++; else if (body[k] === "}") d--; else if (body[k] === "," && d === 0) { out.push(body.slice(start, k)); start = k + 1; } }
  out.push(body.slice(start));
  return out;
}
function globSrc(g) {
  let re = "";
  for (let i = 0; i < g.length; i++) {
    const c = g[i];
    if (c === "*") { if (g[i + 1] === "*") { i++; if (g[i + 1] === "/") { re += "(?:.*/)?"; i++; } else re += ".*"; } else re += "[^/]*"; }
    else if (c === "?") re += "[^/]";
    // each alternative is a full glob ({secrets/**,*.pem} must reach nested files under secrets/)
    else if (c === "{") { const j = braceEnd(g, i); if (j > i) { re += "(?:" + braceAlts(g.slice(i + 1, j)).map(globSrc).join("|") + ")"; i = j; } else re += "\\{"; }
    else if (c === "[") { const j = g.indexOf("]", i + 2); if (j > i) { let body = g.slice(i + 1, j); const neg = body[0] === "!" || body[0] === "^"; if (neg) body = body.slice(1); body = body.replace(/\//g, "").replace(/[\\\]^]/g, "\\$&"); re += neg ? "[^/" + body + "]" : "[" + body + "]"; i = j; } else re += "\\["; }
    else if (".+^$()|[]\\}".includes(c)) re += "\\" + c;
    else re += c;
  }
  return re;
}
function globToRe(g) { return new RegExp("^" + globSrc(String(g)) + "$"); }

module.exports = { globToRe };

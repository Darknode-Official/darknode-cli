"use strict";
// The one glob -> RegExp used by search/find, replace_in_files, attest, invariants and the
// governance path policy (protected / approval paths). * and ? stay inside one path
// segment, **/ spans whole directories (zero or more), {a,b} picks an alternative,
// [ch] / [!ch] match one character from / not from a set (never a /), and \x is a literal x.
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
    else if (c === "[") {
      // the closing "]" skips escaped ones; a "]" right after "[" / "[!" is a member, not the end
      let j = i + 1; if (g[j] === "!" || g[j] === "^") j++; if (g[j] === "]") j++;
      while (j < g.length && g[j] !== "]") j += g[j] === "\\" ? 2 : 1;
      if (j < g.length) { let body = g.slice(i + 1, j); const neg = body[0] === "!" || body[0] === "^"; if (neg) body = body.slice(1); body = body.replace(/\\(.)|[\\\]^/]/g, (m, e) => e == null ? (m === "/" ? "" : "\\" + m) : e === "/" ? "" : /\w/.test(e) ? e : "\\" + e); re += neg ? "[^/" + body + "]" : "[" + body + "]"; i = j; } else re += "\\[";
    }
    // \x matches x literally: app/\[id\]/page.tsx is the Next.js route folder, not a [id] class
    else if (c === "\\" && i + 1 < g.length) { const n = g[++i]; re += /\w/.test(n) ? n : "\\" + n; }
    else if (".+^$()|[]\\}".includes(c)) re += "\\" + c;
    else re += c;
  }
  return re;
}
function globToRe(g) { return new RegExp("^" + globSrc(String(g)) + "$"); }

module.exports = { globToRe };

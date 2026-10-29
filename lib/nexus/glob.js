"use strict";
// The one glob -> RegExp used by search/find, replace_in_files, attest, invariants and the
// governance path policy (protected / approval paths). * and ? stay inside one path
// segment, **/ spans whole directories (zero or more), {a,b} picks an alternative.
// Copies of this drifted: the policy one lacked braces and let **/ swallow part of a
// name, so a protected-path rule like *.{pem,key} matched nothing.
function globToRe(g) {
  let re = "";
  for (let i = 0; i < g.length; i++) {
    const c = g[i];
    if (c === "*") { if (g[i + 1] === "*") { i++; if (g[i + 1] === "/") { re += "(?:.*/)?"; i++; } else re += ".*"; } else re += "[^/]*"; }
    else if (c === "?") re += "[^/]";
    else if (c === "{") { const j = g.indexOf("}", i); if (j > i) { re += "(?:" + g.slice(i + 1, j).split(",").map((x) => x.replace(/[.+^$()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]")).join("|") + ")"; i = j; } else re += "\\{"; }
    else if (".+^$()|[]\\}".includes(c)) re += "\\" + c;
    else re += c;
  }
  return new RegExp("^" + re + "$");
}

module.exports = { globToRe };

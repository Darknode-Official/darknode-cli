"use strict";
// /snippet: saved prompt templates in .nexus/snippets.json.
//
//   getSnippet(store, name)        -> the saved text, or null (never an Object.prototype member)
//   saveBody(argstr)               -> the text after "save <name> ", exactly as typed (newlines kept)
//   expandSnippet(body, rest)      -> body with $ARGUMENTS = rest and $1..$n = rest's words

function getSnippet(store, name) {
  if (!store || !name || !Object.prototype.hasOwnProperty.call(store, name)) return null;
  return typeof store[name] === "string" ? store[name] : null;
}

function saveBody(argstr) {
  const m = /^\s*\S+\s+\S+\s+([\s\S]*)$/.exec(String(argstr || ""));
  return m ? m[1].trim() : "";
}

// One pass, so a $1 inside the substituted arguments is not expanded again.
function expandSnippet(body, rest) {
  const r = String(rest || "").trim(), words = r ? r.split(/\s+/) : [];
  return String(body).replace(/\$ARGUMENTS|\$(\d+)/g, (m, n) => (n ? words[+n - 1] || "" : r));
}

module.exports = { getSnippet, saveBody, expandSnippet };

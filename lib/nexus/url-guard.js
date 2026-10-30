"use strict";
// Pure URL / hostname injection guards. These reject values that would be unsafe
// to hand to a shell-invoked fetcher (curl and friends): shell metacharacters, a
// leading '-' that curl parses as an option, non-http(s) schemes, over-long input.
// Kept standalone and unit-tested (test/run.js) so any shell-out route can reuse
// them. The in-process http_fetch tool does NOT shell out — it has its own
// SSRF/local-address guard — so it does not need these.

function isValidHostname(s) {
  return typeof s === "string" && s.length > 0 && s.length <= 253 &&
    /^[a-zA-Z0-9](?:[a-zA-Z0-9._-]*[a-zA-Z0-9])?$/.test(s);
}

function isSafeUrl(s) {
  if (typeof s !== "string" || s.length > 2048) return false;
  if (/^-/.test(s)) return false; // a leading '-' makes curl parse the quoted arg as an OPTION (-o<file> writes a file, -K<file> reads config), not a URL — quoting stops word-splitting but not curl's own argv parsing
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:(?!\d)/i.test(s) ? s : "http://" + s); // curl treats "file:/etc/passwd" / "gopher:/h/x" as that scheme (no // needed); "host:8080" stays host:port
    return (u.protocol === "http:" || u.protocol === "https:") && !/[\s"'`$;|&<>\\\0]/.test(s); // \0: not whitespace to \s, and a NUL in an argv makes the spawn throw
  } catch (_) { return false; }
}

module.exports = { isValidHostname, isSafeUrl };

"use strict";
// Capability index — a native Nexus code-intelligence pass.
//
// Statically label every source module with the sensitive capabilities it
// actually exercises (dynamic eval, process/shell execution, secret access,
// filesystem writes, network I/O, env, reads, crypto), each with line-level
// evidence and a risk score, then roll the repo up and flag the modules that
// can do the most damage. Answer "what can this code DO?" before you trust,
// ship, audit, or hand a repo to an agent.
//
// Pure: text in, labels out. No fs/network here so it stays trivially testable;
// the CLI layer walks the tree and feeds files in.
//
// Heuristic, by design: it is a static text match on non-comment lines, so a
// file that merely *mentions* a dangerous API (a pattern DB, a security
// knowledge base, this file's own regexes) is labelled for it. That is a
// deliberate bias toward "surface everything worth a human's eyes," not a
// claim of reachable behavior — treat the index as a review worklist.

// Ordered high-risk first. A file can carry several tags. Patterns are matched
// per line (comment lines excluded) so each hit carries a real line number.
const CAPABILITIES = [
  { tag: "eval", label: "Dynamic code execution", risk: 10, patterns: [
      /\beval\s*\(/, /\bnew\s+Function\s*\(/, /\brequire\(\s*['"]vm['"]\s*\)/, /\bvm\.(runIn|compileFunction)/ ] },
  { tag: "exec", label: "Process / shell execution", risk: 9, patterns: [
      /\brequire\(\s*['"]child_process['"]\s*\)/, /\bchild_process\b/, /\bexec(Sync|File|FileSync)?\s*\(/, /\bspawn(Sync)?\s*\(/, /\bexeca\b/ ] },
  { tag: "secrets", label: "Secret / credential access", risk: 7, patterns: [
      /\bprocess\.env\.[A-Za-z0-9_]*(KEY|TOKEN|SECRET|PASS|PWD|CRED|AUTH)/i,
      /\b(apiKey|api_key|accessToken|authToken|privateKey|clientSecret|refreshToken)\b/,
      /GOOGLE_APPLICATION_CREDENTIALS/ ] },
  { tag: "fs-write", label: "Filesystem write / delete", risk: 6, patterns: [
      /\bwriteFile(Sync)?\s*\(/, /\bcreateWriteStream\s*\(/, /\bappendFile(Sync)?\s*\(/,
      /\b(unlink|rmdir|rm|rimraf|mkdir|rename)(Sync)?\s*\(/ ] },
  { tag: "net", label: "Network I/O", risk: 5, patterns: [
      /\bfetch\s*\(/, /\brequire\(\s*['"](https?|net|dgram|dns|tls)['"]\s*\)/,
      /\b(axios|undici|node-fetch|got)\b/, /\bnew\s+WebSocket\s*\(/, /\bXMLHttpRequest\b/ ] },
  { tag: "env", label: "Environment access", risk: 4, patterns: [ /\bprocess\.env\b/ ] },
  { tag: "fs-read", label: "Filesystem read", risk: 3, patterns: [
      /\breadFile(Sync)?\s*\(/, /\breaddir(Sync)?\s*\(/, /\bcreateReadStream\s*\(/, /\bexistsSync\s*\(/ ] },
  { tag: "crypto", label: "Cryptography", risk: 2, patterns: [
      /\brequire\(\s*['"]crypto['"]\s*\)/, /\bcreateHash\s*\(/, /\bcreatecipher/i,
      /\brandomBytes\s*\(/, /\bsubtle\.(encrypt|decrypt|digest|sign)/ ] },
];

// score -> level. Discrete cap risks land these at: 2-3 low, 4-6 medium,
// 7-8 high, 9-10 critical, 0 none.
const LEVELS = [[9, "critical"], [7, "high"], [4, "medium"], [1, "low"], [0, "none"]];
function levelFor(score) {
  for (const [min, name] of LEVELS) if (score >= min) return name;
  return "none";
}

function isCommentLine(line) { return /^\s*(\/\/|\*|\/\*|#)/.test(line); }

// Scan one module's source. Returns [{ tag, label, risk, hits:[{line,match}] }]
// for every capability present, highest-risk first (CAPABILITIES order).
function scanCapabilities(code) {
  const lines = String(code == null ? "" : code).split("\n");
  const found = [];
  for (const cap of CAPABILITIES) {
    const hits = [];
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (isCommentLine(line)) continue;
      for (const re of cap.patterns) {
        const m = line.match(re);
        if (m) { hits.push({ line: i + 1, match: String(m[0]).slice(0, 60) }); break; }
      }
    }
    if (hits.length) found.push({ tag: cap.tag, label: cap.label, risk: cap.risk, hits });
  }
  return found;
}

// A module's risk = its highest-risk capability (the worst thing it can do).
function fileRisk(caps) {
  let score = 0;
  for (const c of caps || []) if (c.risk > score) score = c.risk;
  return { score, level: levelFor(score) };
}

// Index a repo. files = [{ path, code }]. Pure.
function indexFiles(files) {
  const out = [];
  const byTag = {};
  for (const f of files || []) {
    const caps = scanCapabilities(f.code);
    const r = fileRisk(caps);
    for (const c of caps) byTag[c.tag] = (byTag[c.tag] || 0) + 1;
    out.push({ path: f.path, tags: caps.map((c) => c.tag), score: r.score, level: r.level, caps });
  }
  out.sort((a, b) => b.score - a.score || a.path.localeCompare(b.path));
  const critical = out.filter((f) => f.level === "critical" || f.level === "high").map((f) => f.path);
  const maxScore = out.reduce((m, f) => Math.max(m, f.score), 0);
  return { files: out, rollup: { total: out.length, byTag, critical, maxScore, maxLevel: levelFor(maxScore) } };
}

// Render the index to plain lines (the CLI adds color). Pure.
function renderIndex(index, opts) {
  const o = opts || {};
  const top = o.top || index.files.length;
  const lines = [];
  lines.push("Capability index — " + index.rollup.total + " modules, worst risk: " + index.rollup.maxLevel);
  const tags = Object.keys(index.rollup.byTag).sort((a, b) => index.rollup.byTag[b] - index.rollup.byTag[a]);
  if (tags.length) lines.push("  " + tags.map((t) => t + ":" + index.rollup.byTag[t]).join("  "));
  lines.push("");
  for (const f of index.files.slice(0, top)) {
    if (!f.tags.length && !o.all) continue;
    lines.push(f.level.toUpperCase().padEnd(9) + f.path + (f.tags.length ? "  [" + f.tags.join(", ") + "]" : ""));
  }
  if (index.rollup.critical.length) {
    lines.push("");
    lines.push("High-risk modules (" + index.rollup.critical.length + "): " + index.rollup.critical.slice(0, 12).join(", "));
  }
  return lines;
}

module.exports = { CAPABILITIES, scanCapabilities, fileRisk, levelFor, indexFiles, renderIndex };

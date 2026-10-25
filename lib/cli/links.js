"use strict";
// Clickable links in the Nexus transcript (NTUI-061, done with the TUI's own
// mouse capture instead of OSC 8): every terminal that reports clicks gets
// working links, and nothing extra is written into the frame, so widths and
// the frame differ are untouched.
//
//   findLinks(rows, width) -> [{ row, c0, c1, url, kind }]
//     rows   visible body rows, ANSI already stripped
//     width  the row width the transcript was wrapped to; a URL that reaches a
//            full row's edge continues on the next row and both parts open the
//            whole URL
//     c0/c1  0-based display columns, inclusive (wide glyphs count as 2)
//
//   openLink(url, { platform, spawn }) -> boolean
//     http(s) only; launches a fixed binary with an argv array (no shell), so a
//     model-written URL can never become a command.
const { charWidth } = require("./tui-format");

const URL_RE = /https?:\/\/[^\s<>"'`\]\[{}|\\^]+/g;
const ID_RES = [
  { kind: "cve", re: /\bCVE-\d{4}-\d{4,7}\b/g, url: (m) => "https://nvd.nist.gov/vuln/detail/" + m },
  { kind: "ghsa", re: /\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b/g, url: (m) => "https://github.com/advisories/" + m },
  { kind: "cwe", re: /\bCWE-(\d{1,4})\b/g, url: (m, n) => "https://cwe.mitre.org/data/definitions/" + n + ".html" },
];
const URL_CH = /[^\s<>"'`\]\[{}|\\^]/;

// Trim what prose wraps around a URL: trailing punctuation, and a closing
// bracket that has no opener inside the URL ("(see https://x.io/a)").
function trimUrl(u) {
  for (;;) {
    const last = u[u.length - 1];
    if (/[.,;:!?*_~]/.test(last)) { u = u.slice(0, -1); continue; }
    if (last === ")" && (u.match(/\(/g) || []).length < (u.match(/\)/g) || []).length) { u = u.slice(0, -1); continue; }
    return u;
  }
}

// display column of each code-unit index in s (cols[i] = column where s[i] starts)
function columns(s) {
  const cols = new Array(s.length + 1); let c = 0, i = 0;
  for (const ch of s) { for (let k = 0; k < ch.length; k++) cols[i + k] = c; i += ch.length; c += charWidth(ch); }
  cols[s.length] = c;
  return cols;
}

// Leading decoration a wrapped continuation row starts with: indent, the
// answer bullet, a code gutter, a quote bar.
const LEAD_RE = /^[ ●│▎]*/;

function findLinks(rows, width) {
  const out = [];
  const W = Math.max(1, width | 0);
  const from = new Map(); // row -> code-unit index already consumed by a URL continued from above
  for (let r = 0; r < rows.length; r++) {
    const s = String(rows[r] || "");
    const cols = columns(s);
    const start = from.get(r) || 0;
    const taken = start ? [[0, start]] : [];
    let m; URL_RE.lastIndex = start;
    while ((m = URL_RE.exec(s))) {
      let url = trimUrl(m[0]);
      const a = m.index, b = a + url.length; // [a, b)
      if (url.length < 10) continue;
      taken.push([a, b]);
      const parts = [{ row: r, c0: cols[a], c1: cols[b] - 1 }];
      // a URL that runs to the edge of a full row was wrapped: follow it down
      let rr = r, edge = url === m[0] && b === s.trimEnd().length && cols[s.length] >= W - 1;
      while (edge && rr + 1 < rows.length) {
        const nx = String(rows[rr + 1] || "");
        const lead = (nx.match(LEAD_RE) || [""])[0].length;
        let k = lead; while (k < nx.length && URL_CH.test(nx[k])) k++;
        if (k === lead) break;
        const raw = nx.slice(lead, k), piece = trimUrl(raw), nc = columns(nx);
        url += piece; rr++;
        parts.push({ row: rr, c0: nc[lead], c1: nc[lead + piece.length] - 1 });
        from.set(rr, lead + piece.length);
        edge = piece === raw && k === nx.trimEnd().length && nc[nx.length] >= W - 1;
      }
      for (const p of parts) out.push(Object.assign(p, { url, kind: "url" }));
      if (rr > r) break; // the rest of this row is the URL; the next row resumes after it
    }
    for (const { kind, re, url } of ID_RES) {
      re.lastIndex = 0;
      while ((m = re.exec(s))) {
        const a = m.index, b = a + m[0].length;
        if (taken.some(([x, y]) => a < y && b > x)) continue; // inside a URL
        out.push({ row: r, c0: cols[a], c1: cols[b] - 1, url: url(m[0], m[1]), kind });
      }
    }
  }
  return out;
}

function openLink(url, opts) {
  const o = opts || {};
  const u = String(url || "");
  if (!/^https?:\/\/[^\s]+$/i.test(u) || /[\x00-\x1f\x7f"]/.test(u)) return false;
  const platform = o.platform || process.platform;
  const spawn = o.spawn || require("child_process").spawn;
  const [cmd, args] = platform === "darwin" ? ["open", [u]]
    : platform === "win32" ? ["rundll32", ["url.dll,FileProtocolHandler", u]] // no cmd.exe: & | ^ in a URL stay literal
    : ["xdg-open", [u]];
  try { const ch = spawn(cmd, args, { stdio: "ignore", detached: true }); if (ch && ch.on) ch.on("error", () => {}); if (ch && ch.unref) ch.unref(); return true; } catch (_) { return false; }
}

module.exports = { findLinks, openLink, trimUrl };

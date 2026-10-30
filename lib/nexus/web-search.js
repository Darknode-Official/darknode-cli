"use strict";
// web_search — DuckDuckGo's HTML endpoint (no API key). Each result block is
// parsed on its own, so a result without a snippet can't shift every later
// snippet onto the wrong link; ads are dropped; and DuckDuckGo's rate-limit
// (captcha) page is reported as such instead of as "no results".

const https = require("https");

const ENT = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };
const decode = (s) => s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => e[0] === "#" ? (() => { const n = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : +e.slice(1); try { return String.fromCodePoint(n); } catch (_) { return m; } })() : (Object.prototype.hasOwnProperty.call(ENT, e.toLowerCase()) ? ENT[e.toLowerCase()] : m));
const strip = (s) => decode(s.replace(/<[^>]+>/g, "")).replace(/\s+/g, " ").trim();
const deref = (u) => { const m = /[?&]uddg=([^&]+)/.exec(u); if (m) { try { return decodeURIComponent(m[1]); } catch (_) {} } return u.startsWith("//") ? "https:" + u : decode(u); };

function parseDdg(html, max) {
  max = max || 8;
  const results = [];
  const blocks = String(html).split(/<div[^>]+class="result /).slice(1);
  for (const b of blocks) {
    if (results.length >= max) break;
    if (/^[^"]*result--ad/.test(b)) continue;
    const a = /<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/.exec(b);
    if (!a) continue;
    const url = deref(a[1]);
    if (/duckduckgo\.com\/y\.js/.test(url)) continue; // ad redirect
    const r = { title: strip(a[2]), url };
    const sn = /class="result__snippet"[^>]*>([\s\S]*?)<\/(?:a|div|td)>/.exec(b);
    if (sn) { const t = strip(sn[1]); if (t) r.snippet = t.length > 240 ? t.slice(0, 240) + "…" : t; }
    results.push(r);
  }
  return results;
}

const isBlocked = (status, html) => status === 202 || /anomaly-modal|class="anomaly|challenge-form/i.test(html);

function webSearchTool(a, opts) {
  opts = opts || {};
  const q = a.query || a.q || a.pattern;
  if (!q) return Promise.resolve({ error: "web_search needs a query" });
  const max = Math.max(1, Math.min(15, +a.max_results || +a.max || 8));
  const get = opts.get || ((cb0) => {
    let done = false; const cb = (...x) => { if (!done) { done = true; clearTimeout(deadline); cb0(...x); } };
    // overall deadline: the socket timeout only fires when idle, so a server that drips bytes (or a reset mid-body, which never emits "end") hung the call forever
    const deadline = setTimeout(() => { req.destroy(); cb(new Error("search timed out after 15s")); }, 15000);
    const req = https.request({ host: "html.duckduckgo.com", path: "/html/?q=" + encodeURIComponent(q), method: "GET", headers: { "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Nexus", "Accept": "text/html" }, timeout: 15000 }, (res) => {
      const chunks = []; let n = 0;
      const end = () => cb(null, res.statusCode, Buffer.concat(chunks).toString("utf8"));
      res.on("data", (c) => { if (n < 600000) { chunks.push(c); n += c.length; } if (n >= 600000) { res.destroy(); end(); } });
      res.on("end", end);
      res.on("error", (e) => cb(e));
      res.on("close", () => { if (!res.complete) cb(new Error("search response was cut off")); });
    });
    req.on("timeout", () => { req.destroy(); cb(new Error("search timed out after 15s")); });
    req.on("error", (e) => cb(e)); req.end();
  });
  return new Promise((resolve) => {
    try {
      get((err, status, html) => {
        if (err) return resolve({ error: err.message });
        if (isBlocked(status, html)) return resolve({ query: q, results: [], error: "DuckDuckGo is rate-limiting this machine (captcha page) — wait a minute, or http_fetch a known URL (docs site, GitHub, npm) directly" });
        if (status >= 400) return resolve({ query: q, results: [], error: "search failed: HTTP " + status });
        const results = parseDdg(html, max);
        resolve(results.length ? { query: q, results } : { query: q, results: [], note: /No\s+(?:more\s+)?results/i.test(html) ? "no results — try fewer or different words" : "no parseable results — try http_fetch on a specific URL" });
      });
    } catch (e) { resolve({ error: e.message }); }
  });
}

module.exports = { webSearchTool, parseDdg, isBlocked };

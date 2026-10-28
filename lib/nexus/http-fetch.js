"use strict";
// http_fetch — fetch a URL for the agent.
//  • follows redirects (up to 5), re-running the SSRF guard on EVERY hop, so a
//    public URL can't bounce the agent to cloud metadata or an internal host
//  • HTML pages come back as readable text (scripts, styles and markup removed,
//    links kept as [text](url)) — usually a fraction of the tokens of the raw
//    page; raw:true returns the markup when the HTML itself is the subject
//  • bodies are decoded as whole UTF-8 (no split multi-byte characters), binary
//    responses are described instead of dumped, and a cut body says so

const MAX_DOWNLOAD = 2 * 1024 * 1024;
const MAX_BODY = 20000;

const ENT = { amp: "&", lt: "<", gt: ">", quot: "\"", apos: "'", nbsp: " ", mdash: "—", ndash: "–", hellip: "…", copy: "©", reg: "®", rsquo: "’", lsquo: "‘", rdquo: "”", ldquo: "“", bull: "•", middot: "·" };
function decodeEntities(s) {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
    if (e[0] === "#") { const n = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); try { return String.fromCodePoint(n); } catch (_) { return m; } }
    return ENT[e.toLowerCase()] != null ? ENT[e.toLowerCase()] : m;
  });
}

// HTML → readable text. Not a full parser — enough to give a model the page's words.
function htmlToText(html, base) {
  let h = String(html);
  const title = (h.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1];
  h = h.replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<(script|style|noscript|svg|template|iframe|canvas)\b[\s\S]*?<\/\1\s*>/gi, "")
    .replace(/<head\b[\s\S]*?<\/head\s*>/i, "");
  h = h.replace(/<a\b[^>]*?href\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>([\s\S]*?)<\/a\s*>/gi, (m, _q, d1, d2, d3, inner) => {
    const href = d1 || d2 || d3 || ""; const text = inner.replace(/<[^>]+>/g, "").replace(/\s+/g, " ").trim();
    if (!text) return ""; if (/^(javascript:|#)/i.test(href)) return text;
    let abs = href; try { abs = new URL(decodeEntities(href), base).href; } catch (_) {}
    return "[" + text + "](" + abs + ")";
  });
  h = h.replace(/<(h[1-6])\b[^>]*>/gi, (m, t) => "\n\n" + "#".repeat(+t[1]) + " ")
    .replace(/<\/h[1-6]\s*>/gi, "\n\n")
    .replace(/<li\b[^>]*>/gi, "\n- ")
    .replace(/<(br|hr)\b[^>]*\/?>/gi, "\n")
    .replace(/<\/?(p|div|section|article|header|footer|main|nav|aside|ul|ol|table|tr|blockquote|pre|form|figure|dl|dt|dd)\b[^>]*>/gi, "\n")
    .replace(/<\/?(td|th)\b[^>]*>/gi, " | ")
    .replace(/<[^>]+>/g, "");
  h = decodeEntities(h).replace(/[ \t ]+/g, " ").replace(/ *\n */g, "\n").replace(/\n{3,}/g, "\n\n").trim();
  return (title ? "# " + decodeEntities(title.trim()) + "\n\n" : "") + h;
}

// Honour the declared charset (header, else an HTML meta tag) so Latin-1 / Shift_JIS pages aren't mojibake.
function decodeBody(buf, ct) {
  let cs = (ct.match(/charset\s*=\s*["']?([\w.:-]+)/i) || [])[1];
  if (!cs && /html/i.test(ct)) cs = (buf.subarray(0, 2048).toString("latin1").match(/<meta[^>]+charset\s*=\s*["']?([\w.:-]+)/i) || [])[1];
  if (cs && !/^utf-?8$/i.test(cs)) { try { return new TextDecoder(cs).decode(buf); } catch (_) {} }
  return buf.toString("utf8");
}

const isText = (ct) => !ct || /^text\/|json|xml|javascript|ecmascript|x-www-form-urlencoded|yaml|toml|csv|graphql/i.test(ct);

// The URL check sees only the hostname's text; a public-looking name can resolve to 127.0.0.1 or
// 169.254.169.254 (or be re-pointed between check and connect). Every resolved address is checked
// here, at connect time, and the connection uses exactly the address that was checked.
function guardedLookup(isLocal) {
  const dns = require("dns");
  return (host, opts, cb) => dns.lookup(host, opts, (err, addr, fam) => {
    if (err) return cb(err);
    const list = Array.isArray(addr) ? addr : [{ address: addr, family: fam }];
    const bad = list.find((x) => isLocal("http://" + (String(x.address).includes(":") ? "[" + x.address + "]" : x.address) + "/"));
    if (bad) { const e = new Error(host + " resolves to a local/private address (" + bad.address + ")"); e.code = "ESSRF"; return cb(e); }
    cb(null, addr, fam);
  });
}

function request(url, a, timeoutMs, lookup) {
  return new Promise((resolve) => {
    let lib; try { lib = url.protocol === "https:" ? require("https") : require("http"); } catch (e) { return resolve({ error: e.message }); }
    const headers = Object.assign({ "user-agent": "Nexus/1.0 (+https://darknode.ai)", accept: "text/html,application/json,text/plain,*/*;q=0.8" }, a.headers || {});
    // an object body goes out as JSON; without the header JSON APIs (express.json, etc.) ignore it
    if (a.body != null && typeof a.body !== "string" && !Object.keys(headers).some((k) => /^content-type$/i.test(k))) headers["content-type"] = "application/json";
    const req = lib.request(url, Object.assign({ method: a.method || "GET", headers, timeout: timeoutMs }, lookup ? { lookup } : {}), (res) => {
      const chunks = []; let size = 0, capped = false;
      // stop at the cap (and at the overall deadline): an endless stream - SSE, a log tail - never
      // ends, and the socket timeout only fires when idle, so the call used to hang forever
      const finish = () => { clearTimeout(deadline); resolve({ res, buf: Buffer.concat(chunks), capped }); };
      res.on("data", (c) => { if (size < MAX_DOWNLOAD) { chunks.push(c); size += c.length; } if (size >= MAX_DOWNLOAD && !capped) { capped = true; res.destroy(); finish(); } });
      res.on("end", finish);
      res.on("error", (e) => { clearTimeout(deadline); if (capped) return; resolve({ error: e.message }); });
    });
    const deadline = setTimeout(() => { req.destroy(); resolve({ error: "timed out after " + Math.round(timeoutMs / 1000) + "s" }); }, timeoutMs);
    req.on("timeout", () => { clearTimeout(deadline); req.destroy(); resolve({ error: "timed out after " + Math.round(timeoutMs / 1000) + "s" }); });
    req.on("error", (e) => { clearTimeout(deadline); resolve({ error: e.message }); });
    if (a.body != null) req.write(typeof a.body === "string" ? a.body : JSON.stringify(a.body));
    req.end();
  });
}

// deps.isLocal(url) -> true if the SSRF guard must block it
async function httpFetchTool(a, deps) {
  deps = deps || {};
  if (!a.url) return { error: "http_fetch needs a url" };
  let url; try { url = new URL(String(a.url)); } catch (_) { return { error: "invalid url: " + a.url }; }
  if (!/^https?:$/.test(url.protocol)) return { error: "only http and https URLs are supported" };
  const blocked = (u) => deps.isLocal && deps.isLocal(u.href);
  const BLOCK = "http_fetch blocked: refusing to reach a local/private/link-local address (SSRF guard — protects cloud metadata and internal services). A server YOU started with run_background is allowed on localhost; for any other local service use run_command (e.g. curl) so it passes through the shell guard.";
  if (blocked(url)) return { error: BLOCK };
  const method = String(a.method || "GET").toUpperCase();
  const hops = [];
  let r;
  for (let i = 0; ; i++) {
    // a name already judged by its text (localhost a server you started is on) keeps that verdict; any other name is checked by what it resolves to
    const lookup = deps.isLocal && !require("../governance/default-guard").isLocalTarget(url.href) ? guardedLookup(deps.isLocal) : null;
    r = await request(url, Object.assign({}, a, { method }), Math.min(60000, (+a.timeout_s || 15) * 1000), lookup);
    if (r.error) return { error: /resolves to a local\/private address/.test(r.error) ? BLOCK + " (" + r.error + ")" : r.error, url: url.href };
    const loc = r.res.headers.location;
    if (r.res.statusCode >= 300 && r.res.statusCode < 400 && loc && a.follow_redirects !== false && (method === "GET" || method === "HEAD")) {
      if (i >= 5) return { error: "too many redirects", redirects: hops };
      let next; try { next = new URL(loc, url); } catch (_) { return { error: "bad redirect location: " + loc }; }
      if (!/^https?:$/.test(next.protocol)) return { error: "redirect to unsupported protocol: " + next.protocol };
      if (blocked(next)) return { error: BLOCK + " (reached via a redirect from " + url.href + ")", redirects: hops.concat(next.href) };
      // credentials go only to the host they were given for (curl and browsers drop them on a cross-host hop)
      if (next.host !== url.host && a.headers) { const h = {}; for (const [k, v] of Object.entries(a.headers)) if (!/^(authorization|cookie|proxy-authorization|x-api-key|api-key)$/i.test(k)) h[k] = v; a = Object.assign({}, a, { headers: h }); }
      hops.push(next.href); url = next; continue;
    }
    break;
  }
  const res = r.res, ct = String(res.headers["content-type"] || "");
  const out = { status: res.statusCode, contentType: ct || undefined };
  if (hops.length) out.finalUrl = url.href;
  if (!isText(ct)) { out.binary = true; out.bytes = r.buf.length; out.note = "binary response (" + (ct || "unknown type") + ") — not shown"; return out; }
  let body = decodeBody(r.buf, ct);
  if (/html/i.test(ct) && !a.raw) { body = htmlToText(body, url.href); out.format = "text (HTML converted — raw:true for the markup)"; }
  if (body.length > MAX_BODY || r.capped) {
    out.truncated = "showing the first " + Math.min(MAX_BODY, body.length) + " of " + (r.capped ? "over " + MAX_DOWNLOAD : body.length) + " chars";
    body = body.slice(0, MAX_BODY);
  }
  out.body = body;
  return out;
}

module.exports = { httpFetchTool, htmlToText, decodeEntities };

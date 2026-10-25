"use strict";
// ============================================================================
// cachewarm — PURE helpers for prompt-cache warmth. Anthropic's prompt cache
// keeps a conversation's prefix for a TTL (5 minutes by default, or 1 hour);
// a follow-up sent while it is warm re-reads that context at the cheap
// cache-READ rate, but once it goes cold the next turn re-WRITES it at the
// (much higher) write rate. Knowing how long you have left is a lossless saver.
//
// The host records the last time a call touched the cache plus which TTL the
// writes used (both straight from the real API usage buckets). Everything here
// is a function of those numbers + `now`, so it is fully testable.
// ============================================================================

const IDENT = (s) => s;
function theme(c) { c = c || {}; return { gray: c.gray || IDENT, green: c.green || IDENT, yellow: c.yellow || IDENT, bold: c.bold || IDENT, dim: c.dim || IDENT }; }

const TTL_5M = 5 * 60 * 1000, TTL_1H = 60 * 60 * 1000;
const COOLING_MS = 60 * 1000;   // last minute: warn
const COLD_SHOW_MS = 10 * 60 * 1000; // keep a "cold" chip this long after expiry, then hide

// Which TTL did this call's cache writes use? Majority of written tokens wins;
// a call with no writes (pure cache read) keeps the previous TTL.
function ttlFromWrites(w5m, w1h, prevTtl) {
  w5m = Math.max(0, w5m || 0); w1h = Math.max(0, w1h || 0);
  if (!w5m && !w1h) return prevTtl || TTL_5M;
  return w1h > w5m ? TTL_1H : TTL_5M;
}

// cacheState({ lastAt, ttl, now }) -> { state: "none"|"warm"|"cooling"|"cold"|"hidden", leftMs }
function cacheState(o) {
  o = o || {};
  if (!o.lastAt) return { state: "none", leftMs: 0 };
  const ttl = o.ttl || TTL_5M;
  const left = o.lastAt + ttl - (o.now || Date.now());
  if (left > COOLING_MS) return { state: "warm", leftMs: left };
  if (left > 0) return { state: "cooling", leftMs: left };
  if (-left < COLD_SHOW_MS) return { state: "cold", leftMs: left };
  return { state: "hidden", leftMs: left };
}

function fmtLeft(ms) { const s = Math.max(0, Math.ceil(ms / 1000)); if (s >= 3600) return Math.floor(s / 3600) + "h" + String(Math.floor((s % 3600) / 60)).padStart(2, "0") + "m"; if (s >= 60) return Math.ceil(s / 60) + "m"; return s + "s"; }

// The status-bar chip: "cache 3m" (green) · "cache 42s" (yellow) · "cache cold" (dim). "" when none/hidden.
function chip(st, colors) {
  const t = theme(colors);
  if (!st || st.state === "none" || st.state === "hidden") return "";
  if (st.state === "warm") return t.green("cache " + fmtLeft(st.leftMs));
  if (st.state === "cooling") return t.yellow("cache " + fmtLeft(st.leftMs));
  return t.dim("cache cold");
}

// What a follow-up would cost for the context NOW (warm → read) vs after it
// goes cold (→ re-write). price: { cr, cw5, cw1h } USD/M; ctxTok = context size.
function followUpCost(ctxTok, price, ttl) {
  price = price || {};
  const n = Math.max(0, ctxTok || 0) / 1e6;
  const write = ttl === TTL_1H ? price.cw1h : price.cw5;
  return { warm: price.cr != null ? n * price.cr : null, cold: write != null ? n * write : null };
}

function money(n) { return "$" + ((n || 0) < 1 ? (n || 0).toFixed(4) : n.toFixed(2)); }
function fmtK(n) { n = Math.max(0, Math.round(n || 0)); return n >= 1000 ? (n / 1000).toFixed(n >= 100000 ? 0 : 1) + "k" : String(n); }

// The /warm explainer.  o: { lastAt, ttl, now, ctxTok, price, engine, colors }
function explain(o) {
  o = o || {};
  const t = theme(o.colors);
  if (o.engine !== "claude") return [t.gray("prompt caching is tracked on the claude engine — this engine (" + (o.engine || "?") + ") doesn't report it")];
  const st = cacheState(o);
  if (st.state === "none") return [t.gray("no cached context yet — after your first turn, the conversation prefix is cached and follow-ups re-read it cheaply")];
  const ttlName = (o.ttl || TTL_5M) === TTL_1H ? "1-hour" : "5-minute";
  const out = [];
  if (st.state === "warm" || st.state === "cooling") out.push((st.state === "warm" ? t.green("● warm") : t.yellow("◐ cooling")) + t.gray("  prompt cache stays warm for ") + t.bold(fmtLeft(st.leftMs)) + t.gray(" more (" + ttlName + " TTL, refreshed by every turn)"));
  else out.push(t.dim("○ cold") + t.gray("  the " + ttlName + " cache expired " + fmtLeft(-st.leftMs) + " ago — the next turn re-writes the context"));
  const fc = followUpCost(o.ctxTok, o.price, o.ttl);
  if (o.ctxTok && fc.warm != null && fc.cold != null) {
    out.push(t.gray("  ≈" + fmtK(o.ctxTok) + " tokens of context: ") + t.bold(money(fc.warm)) + t.gray(" to re-read while warm vs ") + t.bold(money(fc.cold)) + t.gray(" to re-write once cold" + (fc.warm > 0 ? " (" + Math.round(fc.cold / fc.warm) + "×)" : "")));
  }
  if (st.state !== "cold") out.push(t.gray("  tip: send the follow-up before it cools — any turn resets the clock"));
  return out;
}

module.exports = { TTL_5M, TTL_1H, ttlFromWrites, cacheState, chip, followUpCost, explain, fmtLeft };

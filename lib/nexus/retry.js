"use strict";
// Retry a model API call through TRANSIENT failures — rate limits (429), the
// provider being overloaded (529/503) or a gateway hiccup (502/504), and
// connections dropped mid-request — so one blip doesn't end a long agent turn.
// Honors Retry-After; otherwise backs off 2s, 4s, 8s. Never retries real errors
// (bad key, bad request, model not found), a refused connection (Ollama not
// running) or a 5-minute no-response timeout, and stops at once on interrupt.

const RETRYABLE = new Set([408, 425, 429, 500, 502, 503, 504, 529]);
const NET = /^(ECONNRESET|EPIPE|ETIMEDOUT|EAI_AGAIN|ENETUNREACH|EHOSTUNREACH)$/;
const MAX_WAIT = 60000;

// Attach the HTTP status + Retry-After of `res` to an error.
function tag(err, res) {
  if (res) { err.status = res.statusCode; const ra = res.headers && res.headers["retry-after"]; if (ra) err.retryAfter = ra; }
  return err;
}

const isRetryable = (e) => !!e && ((e.status && RETRYABLE.has(e.status)) || NET.test(e.code || "") || /socket hang up/i.test(e.message || ""));

// Retry-After is seconds or an HTTP date.
function retryAfterMs(v, now) {
  if (v == null || v === "") return null;
  if (/^\d+(\.\d+)?$/.test(String(v).trim())) return Math.round(parseFloat(v) * 1000);
  const t = Date.parse(v); if (isNaN(t)) return null;
  return Math.max(0, t - (now || Date.now()));
}

const sleep = (ms, signal) => new Promise((resolve, reject) => {
  if (signal && signal.aborted) return reject(new Error("interrupted"));
  const t = setTimeout(done, ms);
  function done() { if (signal) signal.removeEventListener("abort", ab); resolve(); }
  function ab() { clearTimeout(t); reject(new Error("interrupted")); }
  if (signal) signal.addEventListener("abort", ab, { once: true });
});

async function withRetry(fn, signal, opts) {
  opts = opts || {};
  const retries = opts.retries == null ? 3 : opts.retries;
  const wait = opts.sleep || sleep;
  for (let i = 0; ; i++) {
    try { return await fn(); }
    catch (e) {
      if ((signal && signal.aborted) || !isRetryable(e) || i >= retries) {
        if (i > 0 && e && e.message && !/after \d+ retr/.test(e.message)) e.message += " (after " + i + " retr" + (i === 1 ? "y" : "ies") + ")";
        throw e;
      }
      const ra = retryAfterMs(e.retryAfter);
      const ms = Math.min(MAX_WAIT, ra != null ? ra : 2000 * Math.pow(2, i) + Math.floor(Math.random() * 500));
      if (opts.onRetry) { try { opts.onRetry({ attempt: i + 1, waitMs: ms, error: e }); } catch (_) {} }
      await wait(ms, signal);
    }
  }
}

module.exports = { withRetry, tag, isRetryable, retryAfterMs, RETRYABLE };

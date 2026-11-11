"use strict";
// ============================================================================
// cheap — PURE helpers for /cheap on the claude engine. Claude Code owns the
// conversation, tools and caching there, so Nexus can only change how it is
// launched, stop avoidable cache rebuilds, and report what really happened.
// Nothing here alters what the model sees or does, and no price is adjusted:
// every figure is real token counts at Anthropic's list rates.
// ============================================================================

const { costOf, priceOf, claudeKey } = require("./pricing");

const HOUR_MS = 60 * 60 * 1000;
const HOLD_MS = 60 * 1000; // repeat the same /model within this window to confirm
const OPUS_55 = "claude-opus-5-5", OPUS_5 = "claude-opus-5";

// Settings /cheap changes; /cheap off puts these back. Effort is deliberately
// absent: it is the user's choice, and clearing it can raise spend.
const PRESET_KEYS = ["cache", "tightEdits", "cheapSide", "lean", "minimizeCalls", "stepCap", "trimOutput", "autoCompact", "autoCompactAt"];

// Moves per-machine context out of the system prompt so sessions in different
// folders can share the cached prefix. Safe on --resume in either direction.
function launchFlags(on) { return on ? ["--exclude-dynamic-system-prompt-sections"] : []; }

const sameModel = (a, b) => {
  const ka = claudeKey(a), kb = claudeKey(b);
  return ka && kb ? ka.key === kb.key : a === b;
};

// The bucket that carries the session: helpers on a small model must not be
// compared as if they were the main model.
function mainBucket(byModel) {
  let best = null, top = -1;
  for (const name of Object.keys(byModel || {})) {
    const c = costOf(name, byModel[name]);
    if (c > top) { top = c; best = name; }
  }
  return best;
}

// Real tokens, priced for the model used and for the Opus models on the same
// tokens. Returns null until something was measured.
function spendReport(byModel) {
  const model = mainBucket(byModel);
  if (!model) return null;
  const t = byModel[model];
  const written = (t.cacheWrite5m || 0) + (t.cacheWrite1h || 0), read = t.cacheRead || 0, input = t.input || 0, output = t.output || 0;
  if (!written && !read && !input && !output) return null;
  const prompt = written + read + input;
  return { model, input, written, read, output, hitRate: prompt ? read / prompt : 0, cost: costOf(model, t), opus55: costOf(OPUS_55, t), opus5: costOf(OPUS_5, t) };
}

// What a model switch adds: each model has its own cache, so the whole context
// is written at the new model's rate instead of read at the old model's.
function switchCost(o) {
  const to = priceOf(o.to), from = priceOf(o.from);
  const write = o.ttl >= HOUR_MS ? (to.cw1h != null ? to.cw1h : to.in) : (to.cw5 != null ? to.cw5 : to.in);
  const read = from.cr != null ? from.cr : from.in;
  return Math.max(0, (o.ctxTok || 0) * (write - read) / 1e6);
}

// Hold a model switch that would throw away a warm cache until it is repeated.
// Returns { hold, pending, cost }; the caller keeps `pending` for the next call.
function switchHold(o) {
  const live = o.cheap && o.engine === "claude" && o.sid && o.warm && o.ctxTok > 0 && o.from && !sameModel(o.from, o.to);
  if (!live) return { hold: false, pending: null, cost: 0 };
  const p = o.pending;
  if (p && sameModel(p.to, o.to) && o.now - p.at <= HOLD_MS) return { hold: false, pending: null, cost: 0 };
  return { hold: true, pending: { to: o.to, at: o.now }, cost: switchCost(o) };
}

module.exports = { PRESET_KEYS, HOLD_MS, launchFlags, mainBucket, spendReport, switchCost, switchHold };

"use strict";
// ============================================================================
// cheap — PURE helpers for /cheap on the claude engine. Claude Code owns the
// conversation, tools and caching there, so Nexus can only change how it is
// launched, stop avoidable cache rebuilds, and report what really happened.
// Nothing here alters what the model sees or does, and no price is adjusted:
// every figure is real token counts at Anthropic's list rates.
// ============================================================================

const fs = require("fs"), path = require("path");
const { costOf, priceOf, claudeKey } = require("./pricing");

const HOUR_MS = 60 * 60 * 1000;
const HOLD_MS = 60 * 1000; // repeat the same /model within this window to confirm
const OPUS_55 = "claude-opus-5-5", OPUS_5 = "claude-opus-5";

// Settings /cheap changes; /cheap off puts these back. Effort is deliberately
// absent: it is the user's choice, and clearing it can raise spend.
const PRESET_KEYS = ["cache", "tightEdits", "cheapSide", "lean", "minimizeCalls", "stepCap", "trimOutput", "autoCompact", "autoCompactAt"];

// Moves per-machine context out of the system prompt so sessions in different
// folders can share the cached prefix. Safe on --resume in either direction.
// skillOverrides ride along per launch, so the user's own settings stay untouched.
// `quiet` (keep-warm pings only) turns hooks off: hooks are not part of the
// cached prefix, and a ping is not work that a Stop or review hook should see.
function launchFlags(on, overrides, quiet) {
  if (!on) return [];
  const flags = ["--exclude-dynamic-system-prompt-sections"], settings = {};
  if (overrides) settings.skillOverrides = overrides;
  if (quiet) settings.disableAllHooks = true;
  if (Object.keys(settings).length) flags.push("--settings", JSON.stringify(settings));
  return flags;
}

// Keep-warm: on a 1-hour cache, coming back after the hour rewrites the whole
// context at the write rate (about 80x a read on Fable). A one-turn ping just
// before expiry reads it instead and restarts the hour. The ping runs on a
// throwaway fork that is never saved, so the conversation itself is unchanged.
const KEEP_WARM_LEAD_MS = 4 * 60 * 1000;  // ping inside the last 4 minutes
const KEEP_WARM_CAP_MS = 6 * HOUR_MS;      // stop after 6 hours away: a long absence costs more in pings than one rebuild
const KEEP_WARM_MIN_CTX = 20000;           // small contexts are cheap to rebuild
const KEEP_WARM_PROMPT = "Nexus keep-alive check. Reply with only: ok";
function keepWarmDue(o) {
  if (!o || !o.cheap || o.engine !== "claude" || !o.sid || o.busy || !o.lastAt) return false;
  if (!(o.ttl >= HOUR_MS) || (o.ctxTok || 0) < KEEP_WARM_MIN_CTX) return false; // on a 5-minute cache a rebuild costs less than the pings
  const left = o.lastAt + o.ttl - o.now;
  if (left <= 0 || left > KEEP_WARM_LEAD_MS) return false;                       // expired already, or not yet near expiry
  return o.now - (o.lastHumanAt || o.lastAt) < KEEP_WARM_CAP_MS;
}
const keepWarmFlags = () => ["--fork-session", "--no-session-persistence", "--max-turns", "1"];

// Every skill's long description is resent in every session, used or not.
// "name-only" keeps the skill listed and invocable and drops just that text.
const DAY_MS = 24 * HOUR_MS, USE_WINDOW_MS = 30 * DAY_MS;
const KEEP_ON = ["claude-api"]; // its description carries the rules for when it must load
const bare = (n) => String(n).split(":").pop();

// null unless both the listing and a finished usage scan are known: without
// evidence of what is unused, nothing is trimmed.
function skillOverrides(listed, used, keep) {
  if (!Array.isArray(listed) || !listed.length || !Array.isArray(used)) return null;
  const on = new Set(used.concat(KEEP_ON, keep || []).map(bare)), out = {};
  for (const n of listed) if (!on.has(bare(n))) out[n] = "name-only";
  return Object.keys(out).length ? out : null;
}

// Skills that ship with the project describe its own workflows: never trim them.
function projectSkills(cwd) {
  const names = (dir) => { try { return fs.readdirSync(path.join(cwd, ".claude", dir)); } catch (_) { return []; } };
  return names("skills").concat(names("commands").map((f) => f.replace(/\.md$/, "")));
}

const USE_RE = /"name":"Skill","input":\{[^}]*?"skill":"([^"]+)"|<command-name>\/([^<]+)<\/command-name>/g;

// Which skills recent Claude Code transcripts really used. Reads in chunks so a
// large history never blocks the UI; the overlap catches matches split across chunks.
async function scanSkillUse(root, sinceMs, chunk) {
  const used = new Set(), size = chunk || (4 << 20), OVERLAP = 512;
  const walk = (dir, out) => { let es = []; try { es = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) {} for (const e of es) { const f = path.join(dir, e.name); if (e.isDirectory()) walk(f, out); else if (e.name.endsWith(".jsonl")) out.push(f); } return out; };
  for (const f of walk(root, [])) {
    let h;
    try {
      if (fs.statSync(f).mtimeMs < sinceMs) continue;
      h = await fs.promises.open(f, "r");
      const buf = Buffer.alloc(size); let tail = "";
      for (;;) {
        const { bytesRead } = await h.read(buf, 0, size, null);
        if (!bytesRead) break;
        const text = tail + buf.toString("latin1", 0, bytesRead);
        for (const m of text.matchAll(USE_RE)) used.add(m[1] || m[2]);
        tail = text.slice(-OVERLAP);
      }
    } catch (_) {} finally { if (h) await h.close().catch(() => {}); }
  }
  return Array.from(used);
}

const storeFile = (home) => path.join(home, ".nexus", "cheap-skills.json");
const readStore = (home) => { try { return JSON.parse(fs.readFileSync(storeFile(home), "utf8")) || {}; } catch (_) { return {}; } };
const writeStore = (home, patch) => { try { fs.mkdirSync(path.dirname(storeFile(home)), { recursive: true }); fs.writeFileSync(storeFile(home), JSON.stringify(Object.assign(readStore(home), patch))); } catch (_) {} };

function rememberListed(home, skills) { if (Array.isArray(skills) && skills.length) writeStore(home, { listed: skills }); }
function overridesFor(home, cwd) { const s = readStore(home); return skillOverrides(s.listed, s.used, projectSkills(cwd)); }

// Refresh the usage scan at most once a day, off the hot path.
let scanning = false;
async function refreshUse(home, now, root) {
  now = now || Date.now();
  if (scanning || now - (readStore(home).at || 0) < DAY_MS) return false;
  scanning = true;
  try { writeStore(home, { at: now, used: await scanSkillUse(root || path.join(home, ".claude", "projects"), now - USE_WINDOW_MS) }); return true; }
  finally { scanning = false; }
}

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

module.exports = { PRESET_KEYS, HOLD_MS, KEEP_WARM_PROMPT, KEEP_WARM_CAP_MS, keepWarmDue, keepWarmFlags, skillOverrides, projectSkills, scanSkillUse, rememberListed, overridesFor, refreshUse, launchFlags, mainBucket, spendReport, switchCost, switchHold };

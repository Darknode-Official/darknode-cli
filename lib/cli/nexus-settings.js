"use strict";
// ============================================================================
// Persistent, user-toggleable TUI settings — ~/.nexus/settings.json.
//
// Two jobs:
//   1. DEFAULTS. Every default that LIMITS what the user can do starts OFF.
//      Budget cap, auto-compaction, the "minimize tool calls" nudge, step
//      caps, tool-output trimming, the response cache and repo-map injection
//      are all opt-in. Protective safety features (filestate guard, guard /
//      redact / permission modes, loopguard) are NOT governed here — they stay
//      on in the host.
//   2. PERSISTENCE. A setting the user changes is saved the moment it changes
//      and loaded at TUI start. Writes are atomic (temp file + rename); a
//      corrupt file is ignored and the defaults are used. Precedence per key:
//      an explicit env var / CLI flag for this launch  >  the saved file  >
//      the built-in default.
//
// Pure except for the small fs read/write helpers, which never throw.
// ============================================================================

const fs = require("fs");
const os = require("os");
const path = require("path");

// Built-in defaults. Anything that caps / trims / shortens the user's work is
// off here; it becomes active only once the user turns it on with a command.
const DEFAULTS = {
  budgetCap: 0,        // 0 = unlimited (no --max-budget-usd sent). /budget <n> turns it on.
  autoCompact: false,  // auto-compaction is off; when on, it fires only near the real context limit
  autoCompactAt: 0,    // /autocompact <amount>: compact at that many tokens (0 = Nexus picks the point)
  minimizeCalls: false,// the "2-5 tool calls" system-prompt nudge
  stepCap: false,      // the native-loop step cap (20/12); off = run until the model stops
  trimOutput: false,   // tool-output / elision trimming outside lean mode
  cache: false,        // response cache (can serve a stale-feeling repeat) — off by default
  map: false,          // repo-map auto-injection
  lean: false,
  effort: "",
  style: "",           // "" = engine/launch default; persists the user's /style choice
  redact: false,       // mask secrets before cloud send; persists the user's /redact choice
  notify: false,
  theme: "",           // "" = keep the launch default / legacy state.json theme
  mode: null,          // null = keep the launch default
  model: "",           // "" = the engine default; persists the user's /model choice
  syntaxGate: "warn",  // after an edit, warn (never block) if it introduced a syntax error; "off" disables
};

// Env vars that pin a key for THIS launch (highest precedence). A present +
// non-empty value wins over the saved file and the default.
const ENV_KEYS = {
  budgetCap: (v) => { const n = parseFloat(v); return isNaN(n) ? undefined : n; },
  autoCompact: (v) => truthy(v),
  minimizeCalls: (v) => truthy(v),
  stepCap: (v) => truthy(v),
  trimOutput: (v) => truthy(v),
  cache: (v) => truthy(v),
  map: (v) => truthy(v),
  lean: (v) => truthy(v),
  effort: (v) => v || undefined,
  syntaxGate: (v) => (/^(off|warn)$/i.test(String(v).trim()) ? String(v).trim().toLowerCase() : undefined),
};
// NEXUS_<KEY> env name for each governed key.
const ENV_NAME = {
  budgetCap: "NEXUS_BUDGET", autoCompact: "NEXUS_AUTOCOMPACT", minimizeCalls: "NEXUS_MINIMIZE_CALLS",
  stepCap: "NEXUS_STEP_CAP", trimOutput: "NEXUS_TRIM_OUTPUT", cache: "NEXUS_CACHE", map: "NEXUS_MAP",
  lean: "NEXUS_LEAN", effort: "NEXUS_EFFORT", syntaxGate: "NEXUS_SYNTAX_GATE",
};

function truthy(v) { return /^(1|true|on|yes)$/i.test(String(v || "").trim()); }

function settingsPath(home) { return path.join(home || os.homedir(), ".nexus", "settings.json"); }

// Read the saved file. A missing file returns {} (fall back to defaults). A
// CORRUPT file is moved aside to settings.json.corrupt-<ts> (so the next save
// can't silently overwrite the user's settings) and its path is recorded in
// readSaved.corrupt for the host to report. Never throws.
function readSaved(home) {
  const p = settingsPath(home);
  let raw;
  try { raw = fs.readFileSync(p, "utf8"); } catch (_) { return {}; }
  try {
    const obj = JSON.parse(raw);
    if (obj && typeof obj === "object" && !Array.isArray(obj)) return obj;
  } catch (_) {}
  if (!raw.trim()) return {};
  const bak = p + ".corrupt-" + Date.now();
  try { fs.renameSync(p, bak); readSaved.corrupt = bak; } catch (_) {}
  return {};
}

// Atomic write: temp file in the same dir, then rename over the original.
function writeSaved(obj, home) {
  let tmp = null;
  try {
    const p = settingsPath(home);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    tmp = p + ".tmp-" + process.pid + "-" + Date.now();
    const fd = fs.openSync(tmp, "w", 0o600);
    try { fs.writeFileSync(fd, JSON.stringify(obj, null, 2) + "\n"); fs.fsyncSync(fd); } finally { fs.closeSync(fd); } // flushed before the rename, so a crash can't leave an empty settings.json
    try { fs.chmodSync(tmp, 0o600); } catch (_) {}
    fs.renameSync(tmp, p);
    return true;
  } catch (_) { if (tmp) try { fs.unlinkSync(tmp); } catch (__) {} return false; }
}

// Build the effective settings for a launch, recording each key's source
// ("default" | "saved" | "env"). env defaults to process.env.
function resolve(home, env) {
  env = env || process.env;
  readSaved.corrupt = null;
  const saved = readSaved(home);
  const corrupt = readSaved.corrupt;
  const value = {}, source = {};
  for (const k of Object.keys(DEFAULTS)) {
    value[k] = DEFAULTS[k]; source[k] = "default";
    // a hand-edited "autoCompact": "false" is a truthy string: only take a saved value of the default's type
    if (Object.prototype.hasOwnProperty.call(saved, k) && saved[k] !== undefined && saved[k] !== null && (DEFAULTS[k] === null || typeof saved[k] === typeof DEFAULTS[k])) { value[k] = saved[k]; source[k] = "saved"; }
    const envName = ENV_NAME[k];
    if (envName && env[envName] != null && env[envName] !== "" && ENV_KEYS[k]) {
      const ev = ENV_KEYS[k](env[envName]);
      if (ev !== undefined) { value[k] = ev; source[k] = "env"; }
    }
  }
  return { value, source, saved, corrupt };
}

// Create a store bound to a home dir. set() persists immediately (merging into
// whatever is on disk, so concurrent keys aren't lost) and updates the live
// value map. Env-pinned keys are still persisted when changed, but the env
// continues to win on the next resolve() for that launch.
function createStore(home, env) {
  const r = resolve(home, env);
  const store = {
    value: r.value,
    source: r.source,
    corrupt: r.corrupt || null, // path the unreadable settings file was moved to, if any
    get(k) { return store.value[k]; },
    // A saved key outside DEFAULTS (e.g. aliases): read straight from the file.
    getSaved(k) { const own = (o) => (Object.prototype.hasOwnProperty.call(o, k) ? o[k] : undefined), v = own(readSaved(home)); return v === undefined ? own(store.value) : v; },
    set(k, v) {
      store.value[k] = v;
      if (store.source[k] !== "env") store.source[k] = "saved";
      const cur = readSaved(home); cur[k] = v; return writeSaved(cur, home);
    },
    all() { return Object.assign({}, store.value); },
    describe() {
      return Object.keys(DEFAULTS).map((k) => ({ key: k, value: store.value[k], source: store.source[k], def: DEFAULTS[k] }));
    },
  };
  return store;
}

module.exports = { DEFAULTS, ENV_NAME, settingsPath, readSaved, writeSaved, resolve, createStore, truthy };

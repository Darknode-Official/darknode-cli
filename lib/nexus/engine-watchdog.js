"use strict";
// Hung-engine watchdog for external agent CLIs (claude / codex / opencode …).
// A long agent turn is normal — an hour of tool calls is fine — so this is NOT a
// wall clock: it fires only after `ms` with no output at all, and never while the
// engine is waiting on the user's ask popup (it is silent by design then). A fixed
// 40-minute cap used to SIGKILL long turns mid-question, and the user's answer
// went nowhere.

const ENGINE_IDLE_MS = 40 * 60 * 1000;
const engineWaits = { n: 0 }; // > 0 while an ask_user popup raised by an engine is open

// kill() is called once the engine has been silent for `ms` and nobody is waiting
// on the user. touch() on every chunk of output; clear() when the child exits.
function idleWatchdog(kill, ms, waits) {
  ms = ms || ENGINE_IDLE_MS; waits = waits || engineWaits;
  let t = null;
  const fire = () => { if (waits.n > 0) return arm(); t = null; kill(); };
  const arm = () => { if (t) clearTimeout(t); t = setTimeout(fire, ms); };
  arm();
  return { touch: arm, clear: () => { if (t) clearTimeout(t); t = null; } };
}

module.exports = { idleWatchdog, engineWaits, ENGINE_IDLE_MS };

"use strict";
// Pure helpers for Nexus's Claude-style auto-updater. The side-effecting parts
// (git fetch/pull, npm view/install, spawning the background check) live in
// darknode.js; everything here is deterministic and unit-tested in test/run.js.

// a > b for dotted numeric versions ("2.10.0" > "2.9.0"); non-numeric tails are ignored.
function semverGt(a, b) {
  const pa = String(a).split(".").map((n) => parseInt(n, 10) || 0);
  const pb = String(b).split(".").map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    if ((pa[i] || 0) > (pb[i] || 0)) return true;
    if ((pa[i] || 0) < (pb[i] || 0)) return false;
  }
  return false;
}

// Normalise the stored preference. Missing/unknown -> "on" (auto-apply, like Claude Code).
function autoUpdateMode(state) {
  const m = state && state.autoUpdate;
  return (m === "check" || m === "off") ? m : "on";
}

// Decide whether the background check should run this launch. Skips when disabled,
// when the offline lock is on (nothing should leave the machine), and when the last
// check was under `intervalMs` ago (default 4h) so launches stay fast and quiet.
function shouldCheck(state, now, offline, intervalMs) {
  if (offline) return false;
  if (autoUpdateMode(state) === "off") return false;
  const iv = intervalMs == null ? 4 * 3600 * 1000 : intervalMs;
  const last = state && state.lastUpdateCheck;
  if (last && now - last < iv) return false;
  return true;
}

module.exports = { semverGt, autoUpdateMode, shouldCheck };

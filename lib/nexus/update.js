"use strict";
// Pure helpers for Nexus's Claude-style auto-updater. The side-effecting parts
// (git fetch/pull, npm view/install, spawning the background check) live in
// darknode.js; everything here is deterministic and unit-tested in test/run.js.

// a > b for dotted numeric versions ("2.10.0" > "2.9.0"), semver precedence for the rest: a
// leading "v" and "+build" are ignored, and a pre-release sorts BELOW its release. Splitting the
// whole string on "." read "1.0.0-rc.1" as 1.0.0.1 > 1.0.0 (a registry rc would downgrade-install
// over the release) and "v1.2.0" as 0.2.0; garbage ("<html>") parses as 0 and never wins.
function semverGt(a, b) {
  const parse = (v) => { const s = String(v == null ? "" : v).trim().replace(/^v/i, "").split("+")[0], i = s.indexOf("-"); return { core: (i < 0 ? s : s.slice(0, i)).split(".").map((n) => parseInt(n, 10) || 0), pre: i < 0 ? [] : s.slice(i + 1).split(".") }; };
  const pa = parse(a), pb = parse(b);
  for (let i = 0; i < Math.max(pa.core.length, pb.core.length); i++) {
    if ((pa.core[i] || 0) > (pb.core[i] || 0)) return true;
    if ((pa.core[i] || 0) < (pb.core[i] || 0)) return false;
  }
  if (!pa.pre.length || !pb.pre.length) return !pa.pre.length && pb.pre.length > 0; // release > its pre-release
  for (let i = 0; i < Math.max(pa.pre.length, pb.pre.length); i++) {
    const x = pa.pre[i], y = pb.pre[i];
    if (x === undefined || y === undefined) return y === undefined; // more identifiers wins on a tie
    const nx = /^\d+$/.test(x), ny = /^\d+$/.test(y);
    if (nx && ny) { if (+x !== +y) return +x > +y; continue; }
    if (nx !== ny) return ny; // numeric identifiers sort below alphanumeric
    if (x !== y) return x > y;
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

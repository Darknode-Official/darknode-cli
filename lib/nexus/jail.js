"use strict";
// ============================================================================
// Path jail — the single canonical resolver every file tool shares, so a model
// (or a prompt-injected one) cannot read or write outside the project root.
//
// String checks like `resolve(cwd, p).startsWith(cwd)` are defeated by symlinks
// and by a non-existent tail: a link inside the root pointing outside passes the
// string test but the real file is elsewhere. resolveInJail() realpath-resolves
// the longest existing prefix (following symlinks) and re-appends the normalized
// non-existent tail, then compares against the realpath of the root. It also
// expands a leading ~, refuses NUL bytes, and caps path length.
//
// Pure except for fs.realpathSync (inherent to resolving symlinks). Zero deps.
// ============================================================================

const fs = require("fs");
const os = require("os");
const path = require("path");

const MAX_PATH = 4096;

// Expand a leading ~ / ~\ to the home dir. No env-var expansion: it only widens
// reach, and the containment check would reject an escape anyway.
function expandHome(p, home) {
  home = home || os.homedir();
  if (p === "~") return home;
  if (p.startsWith("~/") || p.startsWith("~\\")) return path.join(home, p.slice(2));
  return p;
}

// realpath the longest existing ancestor of `abs` (resolving symlinks), then
// re-append the normalized non-existent tail. Never throws for a missing path.
function canonical(abs, hops) {
  hops = hops || 0;
  let head = path.resolve(abs);
  const tail = [];
  for (;;) {
    try {
      const real = fs.realpathSync.native(head);
      return tail.length ? path.join(real, ...tail.reverse()) : real;
    } catch (_) {
      // A DANGLING symlink fails realpath like a missing file, but writing through it creates
      // its target - possibly outside the root. Follow it by hand (bounded, so a loop ends).
      let link = null; try { if (fs.lstatSync(head).isSymbolicLink()) link = fs.readlinkSync(head); } catch (_) {}
      if (link != null && hops < 40) return canonical(path.join(path.resolve(path.dirname(head), link), ...tail.reverse()), hops + 1);
      const parent = path.dirname(head);
      if (parent === head) return tail.length ? path.join(head, ...tail.reverse()) : head; // hit the fs root
      tail.push(path.basename(head));
      head = parent;
    }
  }
}

// Resolve `p` against `root` to a canonical absolute path and report whether it
// lands inside the jail. Throws on a NUL byte or an over-long path.
function resolveInJail(p, root, opts) {
  opts = opts || {};
  const raw = String(p == null ? "" : p);
  if (raw.indexOf("\0") !== -1) throw new Error("path contains a NUL byte");
  if (raw.length > MAX_PATH) throw new Error("path too long (" + raw.length + " > " + MAX_PATH + ")");
  const base = canonical(path.resolve(String(root == null || root === "" ? "." : root)));
  const abs = path.resolve(base, expandHome(raw, opts.home));
  const real = canonical(abs);
  const inside = real === base || real.startsWith(base + path.sep);
  return { path: real, inside, root: base };
}

// Return the canonical path if it is inside the jail, else throw the standard
// error. The thrown message is caught by the tool dispatchers and reported as a
// tool error, never a crash.
function assertInJail(p, root, opts) {
  const r = resolveInJail(p, root, opts);
  if (!r.inside) throw new Error("path escapes the project directory: " + p);
  return r.path;
}

module.exports = { resolveInJail, assertInJail, canonical, expandHome, MAX_PATH };

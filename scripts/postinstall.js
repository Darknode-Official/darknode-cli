#!/usr/bin/env node
"use strict";
// Runs after `npm install`. So Nexus works "out of the box" with a free local
// engine, this installs Ollama + the useful local models as part of the download.
//
// Safe by design: it only runs in an INTERACTIVE terminal (a real TTY) and never
// in CI or automated installs, and it can never fail the install. Skip it with
// DARKNODE_NO_SETUP=1. Re-run any time with `darknode setup`.
try {
  var skip = process.env.DARKNODE_NO_SETUP || process.env.SENTINEL_NO_SETUP || process.env.CI || process.env.NODE_ENV === "production" || !process.stdout.isTTY;
  if (skip) {
    console.log("Darknode installed. Run `darknode setup` to install Ollama + the local models (free, on-device).");
    process.exit(0);
  }
  console.log("Darknode: one-time setup — installing Ollama + local models so Nexus works offline.");
  console.log("  (Ctrl-C to skip · DARKNODE_NO_SETUP=1 to disable · `darknode setup` to run later)");
  var path = require("path");
  require("child_process").spawnSync(
    process.execPath,
    [path.join(__dirname, "..", "darknode.js"), "nexus", "setup", "-y"],
    { stdio: "inherit" }
  );
} catch (_) {
  // never fail the install over optional local-model setup
}
process.exit(0);

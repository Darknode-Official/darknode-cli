#!/usr/bin/env node
"use strict";
// Runs after `npm install`. By policy this script does NOTHING but print a
// short hint: a global `npm i -g` must never reach out to the network or run a
// system installer on its own (it is surprising, it can fail a CI install, and
// npm quarantines packages whose install scripts do it). The free local engine
// (Ollama + models) is set up on demand instead — either the first time you run
// `nexus` in a real terminal, or whenever you run `nexus setup` yourself.
//
// Skip this hint entirely with DARKNODE_NO_SETUP=1.
try {
  if (process.env.DARKNODE_NO_SETUP || process.env.SENTINEL_NO_SETUP || process.env.CI) process.exit(0);
  console.log("");
  console.log("  Darknode CLI installed.  Start the agent with:  nexus");
  console.log("  For the free on-device AI, run once:            nexus setup");
  console.log("");
} catch (_) {
  // a hint must never fail an install
}
process.exit(0);

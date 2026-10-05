"use strict";
// NX-011 — emit the command reference as JSON from the runtime's OWN source of
// truth (lib/cli/reference.js COMMAND_GROUPS). Marketing/docs surfaces render
// from this generated artifact instead of a hand-maintained list that drifts.
//
//   node scripts/export-command-ref.js          # regenerate command-ref.json
//
// A unit test (test/run.js, NX-011 group) regenerates in memory and fails if the
// committed command-ref.json differs, so `npm test` (and therefore CI) fails when
// the reference is stale. Copy command-ref.json to the web surface on release.
const fs = require("fs"), path = require("path");
const { COMMAND_GROUPS } = require("../lib/cli/reference");
const pkg = require("../package.json");

function build() {
  const groups = COMMAND_GROUPS.map((g) => ({
    title: g.title,
    commands: g.rows.map((r) => ({ usage: r[0], desc: r[1] })),
  }));
  const commandCount = groups.reduce((n, g) => n + g.commands.length, 0);
  return { generatedFrom: "lib/cli/reference.js COMMAND_GROUPS", version: pkg.version, commandCount, groups };
}

function serialize() { return JSON.stringify(build(), null, 2) + "\n"; }

const OUT = path.join(__dirname, "..", "command-ref.json");

if (require.main === module) {
  fs.writeFileSync(OUT, serialize());
  console.log("wrote command-ref.json (" + build().commandCount + " commands, v" + pkg.version + ")");
}

module.exports = { build, serialize, OUT };

#!/usr/bin/env node
"use strict";
// Generate docs/NEXUS-COMMANDS.md from the live command tables in darknode.js
// (the same data the TUI menu, /help, /keys and /docs use), via
// lib/cli/nexus-docs.js. `--check` exits 1 if the committed file is stale.
const fs = require("fs");
const path = require("path");
const { buildReference } = require("../lib/cli/nexus-docs");

const ROOT = path.join(__dirname, "..");
const OUT = path.join(ROOT, "docs", "NEXUS-COMMANDS.md");
const src = fs.readFileSync(path.join(ROOT, "darknode.js"), "utf8");

// Pull a pure-literal declaration out of the source: `const NAME = [ … ];` / `{ … };`
function literal(name, open, close, indent) {
  const head = indent + "const " + name + " = " + open;
  const i = src.indexOf(head);
  if (i < 0) throw new Error("gen-nexus-docs: " + name + " not found in darknode.js");
  const end = src.indexOf("\n" + indent + close + ";", i);
  if (end < 0) throw new Error("gen-nexus-docs: end of " + name + " not found");
  return new Function("return " + open + src.slice(i + head.length, end) + "\n" + close)(); // literals only — no code runs
}

function generate() {
  const side = /const SIDE_CMDS = new Set\((\[[^\]]*\])\)/.exec(src);
  const order = /const DOC_ORDER = (\[[^\]]*\])/.exec(src);
  return buildReference({
    cmds: literal("CMDS", "[", "]", "    "),
    help: literal("HELP_SECTIONS", "[", "]", "    "),
    keys: literal("KEY_SECTIONS", "[", "]", "    "),
    side: side ? JSON.parse(side[1]) : [],
    topics: literal("NEXUS_DOCS", "{", "}", ""),
    topicOrder: order ? JSON.parse(order[1]) : undefined,
  });
}

if (require.main === module) {
  const md = generate();
  if (process.argv.includes("--check")) {
    const cur = fs.existsSync(OUT) ? fs.readFileSync(OUT, "utf8") : "";
    if (cur !== md) { console.error("docs/NEXUS-COMMANDS.md is stale — run: node scripts/gen-nexus-docs.js"); process.exit(1); }
    console.log("docs/NEXUS-COMMANDS.md is up to date");
  } else { fs.writeFileSync(OUT, md); console.log("wrote " + path.relative(ROOT, OUT) + " (" + md.split("\n").length + " lines)"); }
}

module.exports = { generate };

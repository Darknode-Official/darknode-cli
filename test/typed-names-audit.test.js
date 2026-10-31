"use strict";
// Commands that look a typed name up in a built-in table (/theme, /color, /gradient, /mode,
// /engine) must not treat Object.prototype members as entries: "/theme toString" used to crash Nexus.
const fs = require("fs"), path = require("path");
const { ENGINES } = require("../lib/nexus/engines");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };

ok("ENGINES has a null prototype", Object.getPrototypeOf(ENGINES) === null && !ENGINES.toString && !ENGINES.constructor && ENGINES.claude);
ok("Object.keys(ENGINES) still lists only engines", !Object.keys(ENGINES).includes("__proto__"));
const src = fs.readFileSync(path.join(__dirname, "..", "darknode.js"), "utf8");
const { catalogGet } = require("../lib/nexus/mcp-catalog");
const { CHEATS } = require("../lib/toolkit/cheats");
const { allStyles, STYLES } = require("../lib/cli/styles");
ok("MCP catalog: /mcp add toString is not a server", catalogGet("toString") === null && catalogGet("constructor") === null);
ok("darknode payloads <class> table has a null prototype", Object.getPrototypeOf(require("../lib/toolkit/payloads").PAYLOADS_CLI) === null);
ok("CHEATS and STYLES have null prototypes", Object.getPrototypeOf(CHEATS) === null && Object.getPrototypeOf(STYLES) === null);
ok("allStyles (the /style table) has no prototype members", allStyles("/nonexistent").toString === undefined);
for (const t of ["THEMES", "COLORS", "PRESETS", "LAB_TARGETS", "NEXUS_DOCS"]) ok(t + " is declared with a null prototype", new RegExp("const " + t + " = \\{ __proto__: null").test(src));

ok("an unknown saved style falls back to default at startup", /if \(style !== "default" && styleMap\[style\] === undefined\) style = "default";/.test(src));

console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (typed names)");
process.exit(fail ? 1 : 0);

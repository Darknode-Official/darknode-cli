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
for (const t of ["THEMES", "COLORS", "PRESETS"]) ok(t + " is declared with a null prototype", new RegExp("const " + t + " = \\{ __proto__: null,").test(src));

console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (typed names)");
process.exit(fail ? 1 : 0);

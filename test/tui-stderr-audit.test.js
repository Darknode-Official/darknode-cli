"use strict";
// The TUI owns the screen: a child process that inherits stderr prints over it (git's
// "fatal: your current branch 'master' does not have any commits yet" from /git and /recent).
// Every execSync in darknode.js must pipe or drop stderr.
const fs = require("fs"), path = require("path");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };

const src = fs.readFileSync(path.join(__dirname, "..", "darknode.js"), "utf8");
const leaks = [];
src.split("\n").forEach((line, i) => {
  for (const m of line.matchAll(/execSync\(/g)) {
    const seg = line.slice(m.index, m.index + 400);
    const call = seg.slice(0, (seg.indexOf("})") + 2) || seg.length);
    if (!/stdio/.test(call) && !/2>\/dev\/null/.test(call)) leaks.push((i + 1) + ": " + call.slice(0, 90));
  }
});
ok("no execSync in darknode.js inherits stderr" + (leaks.length ? "\n    " + leaks.join("\n    ") : ""), leaks.length === 0);
ok("/git shows an empty history instead of 'not a git repo'", /log = "\(no commits yet\)"/.test(src));
ok("/recent falls back to uncommitted files when there are no commits", /const fromLog = list\.length > 0/.test(src) && /fromLog \? "last commits" : "uncommitted"/.test(src));

console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (tui stderr)");
process.exit(fail ? 1 : 0);

"use strict";
// Terminal-mode registry suite (lib/cli/term.js) — LIFO teardown, idempotency,
// isolated writes, and the fs.writeSync crash path.
const fs = require("fs"), os = require("os"), path = require("path");
const Term = require("../lib/cli/term");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const eq = (name, a, b) => ok(name + "  (" + JSON.stringify(a) + " === " + JSON.stringify(b) + ")", JSON.stringify(a) === JSON.stringify(b));
const group = (t) => console.log("\n\x1b[1m" + t + "\x1b[0m");

group("teardown — reverse order, idempotent");
{
  const w = [];
  const r = Term.createRegistry({ write: (s) => w.push(s) });
  r.register("raw", "RAWon", "RAWoff");
  r.register("paste", "PASTEon", "PASTEoff");
  r.register("mouse", "MOUSEon", "MOUSEoff");
  eq("teardown ran", r.teardown(), true);
  eq("disable bytes written in reverse registration order", w, ["MOUSEoff", "PASTEoff", "RAWoff"]);
  eq("a second teardown writes nothing", r.teardown(), false);
  eq("no extra writes after the second teardown", w.length, 3);
}

group("enable / disable strings");
{
  const r = Term.createRegistry({ write: () => {} });
  r.register("a", "A+", "A-");
  r.register("b", "B+", "B-");
  eq("enableString is registration order", r.enableString(), "A+B+");
  eq("disableString is reverse order", r.disableString(), "B-A-");
  eq("disableString does not tear down (still armed)", r.isTornDown, false);
}

group("re-register — dedupe, move to top, re-arm");
{
  const w = [];
  const r = Term.createRegistry({ write: (s) => w.push(s) });
  r.register("x", "X+", "X-");
  r.register("y", "Y+", "Y-");
  r.register("x", "X+", "X2-");    // same name: replaces and moves to top
  eq("size stays at the distinct names", r.size, 2);
  r.teardown();
  eq("re-registered x tears down first with its new disable", w, ["X2-", "Y-"]);
  // registering after a teardown re-arms it; teardown re-writes all live modes
  r.register("z", "Z+", "Z-");
  const before = w.length;
  eq("teardown runs again after a new register", r.teardown(), true);
  eq("the re-armed teardown writes all modes, newest first", w.slice(before), ["Z-", "X2-", "Y-"]);
}

group("isolated writes — one failure does not skip the rest");
{
  const w = [];
  const r = Term.createRegistry({ write: (s) => { if (s === "BOOM") throw new Error("write failed"); w.push(s); } });
  r.register("one", "", "ONE");
  r.register("boom", "", "BOOM");
  r.register("three", "", "THREE");
  r.teardown(); // order: THREE, BOOM(throws), ONE
  eq("writes on either side of the failing one still happen", w, ["THREE", "ONE"]);
}

group("crash path — default writer uses fs.writeSync to the fd");
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nx-term-"));
  const file = path.join(dir, "out.txt");
  try {
    const fd = fs.openSync(file, "w");
    const r = Term.createRegistry({ fd });
    r.register("alt", "ALTon", "ALToff");
    r.register("cur", "CURon", "CURoff");
    r.teardown();
    fs.closeSync(fd);
    eq("disable bytes reached the fd synchronously", fs.readFileSync(file, "utf8"), "CURoffALToff");
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (terminal registry)");
process.exit(fail ? 1 : 0);

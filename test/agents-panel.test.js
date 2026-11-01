"use strict";
// Agents panel suite (lib/cli/agents.js): the live spinner and activity meter must stay
// valid for REAL timestamps. Regression for the "undefined review: logic" bug — a bit-op
// (`now | 0`) truncated Date.now() to 32 bits, went negative, and a negative `% len`
// indexed the spinner array out of range to `undefined`, which the panel printed verbatim.
const A = require("../lib/cli/agents.js");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const group = (t) => console.log("\n\x1b[1m" + t + "\x1b[0m");

group("spinner & meter are defined for real timestamps");
{
  const base = Date.now();
  let spinBad = 0, meterBad = 0;
  // sweep a wide window so the 32-bit wrap boundary is crossed many times
  for (let i = 0; i < 300000; i++) {
    const now = base + i * 41;
    const g = A.spinGlyph(now);
    if (typeof g !== "string" || g.length === 0 || /undefined/.test(g)) spinBad++;
    const m = A.meter(now, 5);
    if (typeof m !== "string" || m.length !== 5 || /undefined/.test(m)) meterBad++;
  }
  ok("spinGlyph is never undefined across a 32-bit-wrapping timestamp sweep", spinBad === 0);
  ok("meter stays a full 5-cell bar (never undefined) across the same sweep", meterBad === 0);
  ok("spinGlyph cycles through all four phases", new Set([0, 120, 240, 360].map((d) => A.spinGlyph(base + d))).size === 4);
  ok("spinGlyph tolerates a missing argument", typeof A.spinGlyph() === "string" && A.spinGlyph().length > 0);
}

group("panel never renders the literal word undefined for running agents");
{
  const now = Date.now();
  const agents = ["review: logic", "review: edge cases", "review: state & resources", "review: callers"]
    .map((task, i) => ({ id: "ag" + i, task, status: "run", start: now - 1000 }));
  const rows = A.panelRows(agents, { now, sel: -1, width: 120, max: 6, colors: {} });
  const plain = rows.join("\n").replace(/\x1b\[[0-9;]*m/g, "");
  ok("a panel of running review agents has no 'undefined' in it", !/undefined/.test(plain));
  ok("each agent's task text is still shown", ["logic", "edge cases", "state & resources", "callers"].every((s) => plain.includes(s)));
}

console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m");
process.exit(fail ? 1 : 0);

"use strict";
// Secret scanning runs on every file the agent writes and every tool output it shows. The
// key: value rule opened with ^(\s*-?\s* under the m flag, so from each line start \s* ran
// across the rest of a blank-line run and the two \s* split it every way: 3,000 newlines took
// 12s per call (cubic) and a log with 30k blank lines hung the turn.
const S = require("../lib/governance/security.js"), R = require("../lib/nexus/redact.js");
let pass = 0, fail = 0;
const tmp = require("fs").mkdtempSync(require("path").join(require("os").tmpdir(), "nx-sg-"));
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const timed = (fn) => { const t = Date.now(); fn(); return Date.now() - t; };

const SHAPES = { newlines: "\n".repeat(100000), crlf: "\r\n".repeat(50000), spaces: " ".repeat(100000) + "x", dashes: " -".repeat(50000) + "x", blankAfterKey: "token:" + "\n".repeat(100000) };
for (const [k, s] of Object.entries(SHAPES)) {
  ok("scanSecrets " + k, timed(() => S.scanSecrets(s)) < 1000);
  ok("maskSecrets " + k, timed(() => S.maskSecrets(s)) < 1000);
  ok("redact " + k, timed(() => R.redact(s, "k")) < 1000);
}
const doc = "db:\n  password: s3cr3t!9x\n\n\nnext: 1\r\nAPI_TOKEN=abcdef12345\r\n\r\nend";
ok("still detects key: value", S.scanSecrets(doc).some((f) => /credential/.test(f)));
const m = S.maskSecrets(doc);
ok("masks the value", !m.includes("s3cr3t!9x") && !m.includes("abcdef12345"));
ok("keeps the blank lines after a masked line", m.includes("[redacted credential]\n\n\nnext: 1"));
const r = R.redact(doc, "k").text;
ok("redact keeps blank lines and CRLF", /kv-secret:0000\]\n\n\nnext: 1\r\n/.test(r) && !r.includes("s3cr3t!9x"));
ok("indented YAML list item still caught", S.scanSecrets("items:\n  - api_key: q9w8e7r6t5\n").length > 0);

// The syntax gate runs on every JS file the agent writes; its ESM sniff had the same ^\s* (6s on
// 100k blank lines) plus a lazy import...from scan that restarted at every "import" line.
const G = require("../lib/nexus/syntax-gate.js");
for (const [k, s] of Object.entries({ newlines: "\n".repeat(200000) + "x;", importLines: "import x\n".repeat(50000) }))
  ok("syntax gate " + k, timed(() => G.check(require("path").join(tmp, "a.js"), s)) < 3000);

// The transcript renderer: every message passes through ansiWrap and renderMd. A run of zero-width
// marks re-measured an ever-growing cluster (30k: 12s); a run of "[" rescanned to the end of the line
// from each one (300k: 53s); a long blank YAML line split its indent every way.
const F = require("../lib/cli/tui-format.js"), M = require("../lib/cli/md-render.js");
for (const [k, s] of Object.entries({ zeroWidth: "\u200b".repeat(100000), zwj: " \u200d".repeat(50000), brackets: "[".repeat(200000), yamlIndent: "```yaml\n" + " ".repeat(200000) + "!\n```" }))
  ok("render " + k, timed(() => { F.ansiWrap(s, 80); M.renderMd(s, 80); }) < 2500);
ok("a space at a wrap never takes merged text with it", F.ansiWrap("ab \u200dq cd", 3).join("").replace(/\s/g, "").includes("q"));
ok("emoji ZWJ sequence stays one 2-cell glyph", F.ansiWrap("\u{1F468}\u200d\u{1F469}\u200d\u{1F467}", 80)[0].length > 4 && F.strWidth(F.ansiWrap("\u{1F468}\u200d\u{1F469}\u200d\u{1F467}", 80)[0]) === 2);
const C = { underline: (x) => "<" + x + ">", gray: (x) => "{" + x + "}" };
ok("link text after a stray [ is the inner text", M.linkify("x[b [t](https://a.b)", C) === "x[b <t>{ (https://a.b)}");

require("fs").rmSync(tmp, { recursive: true, force: true });
console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (hot-path speed)");
process.exit(fail ? 1 : 0);

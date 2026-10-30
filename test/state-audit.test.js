"use strict";
// State-module audit regressions: instructions (symlink escape, oversize announced), filestate
// (aliases share one entry), loopguard (paging is not oscillation, key order), memory (tab dedup),
// pricing (claude-3-<family> ids are not the newest model).
process.env.HOME = "/tmp/nxhome-state";
const fs = require("fs"), path = require("path"), os = require("os");
const { loadInstructions } = require("../lib/nexus/instructions");
const { makeFileState } = require("../lib/nexus/filestate");
const { makeLoopGuard, signature } = require("../lib/nexus/loopguard");
const { mergeMemory } = require("../lib/nexus/memory");
const { priceOf, costOf } = require("../lib/nexus/pricing");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const eq = (name, a, b) => ok(name + "  (" + JSON.stringify(a) + " === " + JSON.stringify(b) + ")", JSON.stringify(a) === JSON.stringify(b));
const group = (t) => console.log("\n\x1b[1m" + t + "\x1b[0m");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "nx-state-"));

group("instructions");
{
  const repo = path.join(tmp, "repo"), sub = path.join(repo, "sub"), sec = path.join(tmp, "dotssh");
  fs.mkdirSync(path.join(repo, ".git"), { recursive: true }); fs.mkdirSync(sub); fs.mkdirSync(sec);
  fs.writeFileSync(path.join(sec, "id_rsa"), "PRIVATE-KEY-MATERIAL\n");
  fs.symlinkSync(path.join("..", "dotssh", "id_rsa"), path.join(repo, "AGENTS.md"));
  const r = loadInstructions(sub);
  ok("a symlink out of the repo is not read into the prompt", !/PRIVATE-KEY/.test(r.text));
  ok("...and the refusal is announced", /not loaded: .*AGENTS\.md \(links outside the repo\)/.test(r.text));
  ok("allowOutside (trusted) still follows it", /PRIVATE-KEY/.test(loadInstructions(sub, { allowOutside: true }).text));
  fs.writeFileSync(path.join(repo, "GEMINI.md"), "use tabs\n");
  fs.symlinkSync("GEMINI.md", path.join(repo, "CLAUDE.md"));
  ok("an in-repo symlink (CLAUDE.md -> GEMINI.md) still loads", /use tabs/.test(loadInstructions(sub).text));
  fs.writeFileSync(path.join(sub, "AGENTS.md"), "x".repeat(600 * 1024));
  ok("an oversize file is announced, not silently dropped", /AGENTS\.md \(over 512 KB\)/.test(loadInstructions(sub).text));
  fs.writeFileSync(path.join(sub, "AGENTS.md"), "﻿nested rule\r\n");
  const t = loadInstructions(sub).text;
  ok("BOM stripped, nested file after the root one", t.indexOf("use tabs") < t.indexOf("nested rule") && !/﻿/.test(t));
}

group("filestate");
{
  const real = path.join(tmp, "real.txt"), link = path.join(tmp, "link.txt");
  fs.writeFileSync(real, "v1"); fs.symlinkSync(real, link);
  const fg = makeFileState();
  fg.recordRead(real, "v1");
  ok("read via the real path counts as seen via a symlink alias", fg.hasSeen(link));
  ok("an on-disk change is caught when writing through the alias", fg.checkOverwrite(link, "v2").stale);
  ok("unchanged through the alias is not stale", !fg.checkOverwrite(link, "v1").stale);
  fg.recordWrite(link, "v3");
  ok("a write via the alias updates the one entry", !fg.checkOverwrite(real, "v3").stale && fg._seen.size === 1);
  fg.forget(real);
  ok("forget via either name drops it", !fg.hasSeen(link));
  ok("a not-yet-created file is simply unseen", !fg.hasSeen(path.join(tmp, "nope", "new.txt")) && !fg.checkOverwrite(path.join(tmp, "new.txt"), "x").stale);
}

group("loopguard");
{
  const lg = makeLoopGuard();
  const rd = (p, o) => signature("read_file", { path: p, offset: o });
  const v = [lg.note(rd("a", 1), 1, "h1"), lg.note(rd("b", 1), 1, "h2"), lg.note(rd("a", 200), 1, "h3"), lg.note(rd("b", 200), 1, "h4"), lg.note(rd("a", 400), 1, "h5")];
  eq("paging two files side by side is not an oscillation", v.map((x) => x && x.action), [null, null, null, null, null]);
  const lg2 = makeLoopGuard();
  const w = [lg2.note("A", 1, "x"), lg2.note("B", 1, "y"), lg2.note("A", 1, "x"), lg2.note("B", 1, "y"), lg2.note("A", 1, "x")];
  eq("a real A,B,A,B stall still nudges then breaks", w.map((x) => x && x.action), [null, null, null, "nudge", "break"]);
  const lg3 = makeLoopGuard();
  eq("no outcome passed: oscillation behaves as before", [lg3.note("A", 1), lg3.note("B", 1), lg3.note("A", 1), lg3.note("B", 1)].map((x) => x && x.action), [null, null, null, "nudge"]);
  ok("reordered arg keys give one signature", signature("todo_write", { x: 1, y: { b: 1, a: 2 } }) === signature("todo_write", { y: { a: 2, b: 1 }, x: 1 }));
  ok("different nested values give different signatures", signature("todo_write", { todos: [{ content: "a" }] }) !== signature("todo_write", { todos: [{ content: "b" }] }));
}

group("memory");
{
  eq("a tab-separated repeat dedups", mergeMemory("## Remembered\n- run tests with npm\n", "run\ttests with npm").added, false);
  eq("a different fact is still added", mergeMemory("## Remembered\n- run tests with npm\n", "lint with eslint").added, true);
}

group("pricing");
{
  const o3 = priceOf("claude-3-opus-20240229"), h3 = priceOf("claude-3-haiku-20240307");
  ok("claude-3-opus is flagged unlisted, not 'known' Opus 5.5", o3.known === false);
  ok("claude-3-haiku is flagged unlisted", h3.known === false);
  eq("claude-3-5-haiku keeps its exact row", [priceOf("claude-3-5-haiku-20241022").label, priceOf("claude-3-5-haiku-20241022").in], ["Claude Haiku 3.5", 0.8]);
  eq("claude-sonnet-4-20250514 -> Sonnet 4", priceOf("claude-sonnet-4-20250514").label, "Claude Sonnet 4");
  eq("bare alias stays newest and known", [priceOf("opus").label, priceOf("opus").known], ["Claude Opus 5.5", true]);
  eq("cost math: Opus 5.5 1M in + 1M out + 1M cache read", +costOf("claude-opus-5-5", { input: 1e6, output: 1e6, cacheRead: 1e6 }).toFixed(6), 24.2);
}

fs.rmSync(tmp, { recursive: true, force: true });
console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (state audit)");
process.exit(fail ? 1 : 0);

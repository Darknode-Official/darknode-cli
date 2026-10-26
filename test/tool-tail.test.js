"use strict";
// Live command tail suite (lib/cli/tool-tail.js): split chunks, progress bars,
// control-sequence firewall, the 256 KiB bound, and the shell hook.
const { createTail, pushTail, tailLines, tailText, lineCount } = require("../lib/cli/tool-tail");
const { coderShell } = require("../lib/nexus/shell-run");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const eq = (name, a, b) => ok(name + "  (" + JSON.stringify(a) + " === " + JSON.stringify(b) + ")", JSON.stringify(a) === JSON.stringify(b));
const group = (t) => console.log("\n\x1b[1m" + t + "\x1b[0m");

(async () => {
  group("tail");
  {
    const t = createTail();
    pushTail(t, "one\ntw"); pushTail(t, "o\nthree\n\n"); pushTail(t, "fou");
    eq("lines split across chunks are joined", tailLines(t, 3), ["two", "three", "fou"]);
    eq("blank lines are skipped in the tail", tailLines(t, 4), ["one", "two", "three", "fou"]);
    eq("line count includes the unfinished line", lineCount(t), 5);
    eq("tail of an empty tail", tailLines(createTail(), 3), []);
  }

  group("progress bars and control sequences");
  {
    const t = createTail();
    pushTail(t, "downloading 10%\rdownloading 55%\rdownloading 90%");
    eq("a \\r progress bar shows its latest frame", tailLines(t, 1), ["downloading 90%"]);
    pushTail(t, "\r\ndone\r\n");
    eq("CRLF line endings are not treated as a redraw", tailLines(t, 2), ["downloading 90%", "done"]);
    const e = createTail();
    pushTail(e, "\x1b[31mred\x1b[0m \x1b]0;evil title\x07ok \x1b[2J\x1b[Hx\x07\x1b]52;c;ZXZpbA==\x07\n");
    const s = tailLines(e, 1)[0];
    ok("ANSI colour, OSC title / clipboard, screen clears and BEL are removed", s === "red ok x" && !/[\x00-\x1f\x7f]/.test(s));
    const tab = createTail(); pushTail(tab, "a\tb\n"); eq("tabs expand", tailLines(tab, 1), ["a  b"]);
    const spin = createTail(); for (let i = 0; i < 5000; i++) pushTail(spin, "\rframe " + i);
    ok("a spinner with no newline stays bounded", spin.partial.length < 5000 && tailLines(spin, 1)[0] === "frame 4999");
  }

  group("256 KiB bound");
  {
    const t = createTail();
    const line = "x".repeat(99) + "\n";
    for (let i = 0; i < 4000; i++) pushTail(t, line); // ~400 KiB
    ok("memory stays within the bound", t.bytes <= 256 * 1024);
    ok("dropped lines are counted", t.dropped > 0 && lineCount(t) === 4000);
    ok("the full text says what was dropped", /^\[\d[\d,]* earlier lines \(\d+ KiB\) dropped/.test(tailText(t)));
    const huge = createTail(); pushTail(huge, "y".repeat(10000) + "\n");
    ok("a single huge line is cut", tailLines(huge, 1)[0].length < 2100);
  }

  group("shell hook");
  {
    const seen = [];
    const r = await coderShell("printf 'a\\nb\\n'; printf 'err\\n' 1>&2", process.cwd(), { onData: (d) => seen.push(d) });
    const t = createTail(); seen.forEach((d) => pushTail(t, d));
    ok("onData receives stdout and stderr as it arrives", r.code === 0 && ["a", "b", "err"].every((x) => tailLines(t, 3).includes(x)));
    const r2 = await coderShell("echo fine", process.cwd(), { onData: () => { throw new Error("boom"); } });
    ok("a throwing onData never breaks the command", r2.code === 0 && /fine/.test(r2.output));
    const card = {}; Object.defineProperty(card, "live", { value: createTail(), configurable: true });
    ok("the live buffer is not serialized with the card", !("live" in JSON.parse(JSON.stringify(card))));
  }

  console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (live command tail)");
  process.exit(fail ? 1 : 0);
})();

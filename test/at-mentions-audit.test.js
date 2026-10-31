"use strict";
// @path mention suite (lib/cli/at-mentions.js): prose punctuation after a mention, a file
// cut to the cap, devices / FIFOs / directories and binary files.
const fs = require("fs"), os = require("os"), path = require("path"), cp = require("child_process");
const { expandAts } = require("../lib/cli/at-mentions");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nx-at-"));
fs.mkdirSync(path.join(dir, "src"));
fs.writeFileSync(path.join(dir, "src", "app.js"), "const a = 1;\n");
fs.writeFileSync(path.join(dir, "big.txt"), "x".repeat(10000));
fs.writeFileSync(path.join(dir, "img.png"), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x00, 0x01]));
fs.writeFileSync(path.join(dir, "my notes.md"), "notes\n");
const run = (t, o) => expandAts(t, Object.assign({ cwd: dir }, o || {}));

const plain = run("fix @src/app.js please");
ok("a mention inlines the file", plain.includes("--- src/app.js ---\nconst a = 1;\n") && plain.includes("--- end src/app.js ---"));
ok("text around the mention is kept", plain.startsWith("fix ") && plain.endsWith(" please"));

const dot = run("fix the bug in @src/app.js.");
ok("a trailing full stop no longer stops the file attaching", dot.includes("--- src/app.js ---") && dot.endsWith("--- end src/app.js ---\n."));
ok("a trailing comma or bracket also works", run("see (@src/app.js), then").includes("--- src/app.js ---") && run("look at @src/app.js!").includes("const a = 1;"));
ok("a file whose real name ends in punctuation still matches first", (() => { fs.writeFileSync(path.join(dir, "v1."), "dotted\n"); return run("@v1.").includes("--- v1. ---\ndotted"); })());

const big = run("@big.txt");
ok("a long file is cut to the cap", big.includes("x".repeat(6000)) && !big.includes("x".repeat(6001)));
ok("the cut is stated, so the model knows it has a partial file", /truncated: only the first 6000 chars of big\.txt \(10000 bytes\)/.test(big));
ok("a short file carries no truncation note", !plain.includes("truncated"));

const seen = [];
run("@src/app.js @big.txt", { onRead: (abs) => seen.push(path.basename(abs)) });
ok("only a fully shown file counts as read", seen.length === 1 && seen[0] === "app.js");

ok("a binary file is not pasted in", run("@img.png") === "@img.png");
ok("a directory is left as typed", run("@src") === "@src");
ok("a missing file is left as typed", run("@nope.js.") === "@nope.js." && run("hi @claude") === "hi @claude");
ok("an email address is not a mention", run("mail me at a@b.com") === "mail me at a@b.com");
ok("a quoted path with spaces works", run('read @"my notes.md"').includes("--- my notes.md ---\nnotes"));
ok("the lean cap is honoured", run("@big.txt", { max: 3000 }).includes("x".repeat(3000)) && !run("@big.txt", { max: 3000 }).includes("x".repeat(3001)));

// devices and FIFOs must not be read (readFileSync on /dev/zero never returns)
if (fs.existsSync("/dev/zero")) {
  const t0 = Date.now(); const z = run("@/dev/zero");
  ok("@/dev/zero returns at once and is left as typed", z === "@/dev/zero" && Date.now() - t0 < 2000);
}
if (process.platform !== "win32") {
  const fifo = path.join(dir, "pipe");
  try { cp.execFileSync("mkfifo", [fifo]); ok("a FIFO is left as typed (no blocking read)", run("@pipe") === "@pipe"); } catch (_) {}
}

// darknode.js uses the shared helper in both places
const src = fs.readFileSync(path.join(__dirname, "..", "darknode.js"), "utf8");
ok("the TUI uses expandAts", /const inlineAts = \(t\) => expandAts\(/.test(src));
ok("line mode uses expandAts", /const userMsg = expandAts\(task,/.test(src));
ok("no copy of the old unguarded reader is left", !/readFileSync\(path\.resolve\(cwd, (f|p)\), "utf8"\); if \(c\.length <=/.test(src));

fs.rmSync(dir, { recursive: true, force: true });
console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (@path mentions)");
process.exit(fail ? 1 : 0);

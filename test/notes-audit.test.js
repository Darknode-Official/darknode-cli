"use strict";
// "#note" suite (lib/cli/notes.js): what counts as a note, and where it lands in NEXUS.md.
const fs = require("fs"), path = require("path");
const { noteText, addNote } = require("../lib/cli/notes");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };

// detection
ok("a one-line # is a note", noteText("# always run npm test first") === "always run npm test first" && noteText("#use tabs") === "use tabs");
ok("a pasted markdown document is a prompt, not a note", noteText("# Spec\n\nBuild a login page with MFA.") === null);
ok("a shebang line is a prompt", noteText("#!/bin/bash fails on line 3, why?") === null);
ok("C preprocessor lines are prompts", noteText("#include <stdio.h> not found") === null && noteText("#define MAX is wrong") === null && noteText("# pragma once breaks it") === null);
ok("a word that merely starts like a directive is still a note", noteText("#includes go at the top") === "includes go at the top");
ok("an empty # saves nothing", noteText("#") === null && noteText("#   ") === null);
ok("ordinary prompts are not notes", noteText("fix #123") === null && noteText("") === null && noteText(null) === null);

// placement
ok("a new file gets a Notes section", addNote("", "a") === "## Notes\n- a\n");
ok("an existing file gains a Notes section at the end", addNote("# Project\nUse pnpm.\n", "a") === "# Project\nUse pnpm.\n\n## Notes\n- a\n");
ok("a file that starts with ## Notes gets no second heading", addNote("## Notes\n- old\n", "new") === "## Notes\n- old\n- new\n");
const mid = "# P\n\n## Notes\n- old\n\n## Commands\nnpm test\n";
const got = addNote(mid, "new");
ok("a note lands in the Notes section, not under the last section", got === "# P\n\n## Notes\n- old\n- new\n\n## Commands\nnpm test\n");
ok("### subheadings stay inside the Notes section", addNote("## Notes\n- a\n### deeper\n- b\n\n## Other\nx\n", "c") === "## Notes\n- a\n### deeper\n- b\n- c\n\n## Other\nx\n");
ok("a file with no trailing newline is handled", addNote("## Notes\n- a", "b") === "## Notes\n- a\n- b\n");

// wiring
const src = fs.readFileSync(path.join(__dirname, "..", "darknode.js"), "utf8");
ok("submit and the queue both use noteText", /const nt = noteText\(t\)/.test(src) && /else if \(noteText\(nxt\) !== null\)/.test(src));
ok("no raw '#' prefix check is left", !/\[0\] === "#" && (t|nxt)\.length > 1/.test(src));
ok("addMemory writes through addNote", /fs\.writeFileSync\(md, addNote\(c, line\)\)/.test(src));
ok("the composer is green only for a real note", /clean\[0\] === "#" && noteText\(input\) !== null/.test(src));

console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (#notes)");
process.exit(fail ? 1 : 0);

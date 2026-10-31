"use strict";
// Conversation lifecycle suite: /export (lib/cli/convo-text.js exportMarkdown), /branch
// (lib/cli/branches.js) and the read-dedup indices on every context reset in darknode.js.
const fs = require("fs"), path = require("path");
const { exportMarkdown } = require("../lib/cli/convo-text");
const B = require("../lib/cli/branches");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };

// /export
const tr = [
  { role: "art" },
  { role: "user", text: "fix it" },
  { role: "nexus", items: [{ type: "text", full: "done" }, { type: "tool", label: "\x1b[36mRead\x1b[0m(a.js)" }] },
  { role: "system", text: "alias \x1b[36m/x\x1b[0m set" },
  { role: "system", lines: ["line one", "\x1b[90mline two\x1b[0m"] },
  { role: "compacted", auto: false, before: 9000, summary: "The user asked to fix a.js; it was fixed." },
  { role: "recap", text: "You fixed a.js." },
  { role: "diff", text: "--- a/a.js\n+++ b/a.js\n@@\n-x\n+y\n" },
];
const md = exportMarkdown(tr, { date: "D", engine: "ollama", cwd: "/p" });
ok("export keeps the header line", md.startsWith("# Nexus conversation\n\n_D · ollama · /p_\n"));
ok("export has no terminal colour codes", !/\x1b\[/.test(md));
ok("a system note's text is exported plain", md.includes("> alias /x set"));
ok("a lines-array system note is exported, not 'undefined'", md.includes("> line one line two") && !md.includes("undefined"));
ok("tool labels are exported plain", md.includes("- `Read(a.js)`"));
ok("the compaction summary is exported", md.includes("## Summary of the earlier conversation\n\nThe user asked to fix a.js; it was fixed."));
ok("a recap is exported", md.includes("> recap: You fixed a.js."));
ok("a /diff block is exported as a diff fence", md.includes("```diff\n--- a/a.js\n+++ b/a.js\n@@\n-x\n+y\n```"));
ok("user prompts and answers are exported", md.includes("## You\n\nfix it\n") && md.includes("## Nexus\n\ndone\n"));

// /branch files
ok("branch names are sanitized into the branch folder", B.branchFile("/d", "../x y") === path.join("/d", ".._x_y.json"));
const sess = { model: "qwen", ctxUsed: 50, inTok: 10, outTok: 5, cost: 1.5, byModel: { a: 1 }, readCache: { "/a": 1 }, fileSnap: new Map([["/a", 3]]) };
const rec = B.branchRecord({ engine: "ollama", transcript: [{ role: "user", text: "k=1" }, { role: "system", text: "tmp", ephemeral: true }], sess, oMsgs: [{ role: "system", content: "s" }] }, (b) => (b.text ? Object.assign({}, b, { text: "[R]" }) : b));
ok("a branch file does not store readCache or fileSnap", !("readCache" in rec.sess) && !("fileSnap" in rec.sess) && sess.fileSnap instanceof Map);
ok("a branch file drops ephemeral notes and redacts blocks", rec.transcript.length === 1 && rec.transcript[0].text === "[R]");
ok("a branch file round-trips through JSON", JSON.parse(JSON.stringify(rec)).oMsgs.length === 1);
const live = { model: "qwen", ctxWindow: 32768, ctxUsed: 9, inTok: 100, outTok: 50, cost: 2, byModel: { qwen: 1 }, readCache: { "/b": 2 }, fileSnap: new Map([["/b", 1]]) };
B.applyBranchSess(live, { sess: { model: "claude-opus-5-5", ctxWindow: 200000, ctxUsed: 321, inTok: 1, outTok: 1, cost: 0, byModel: {}, readCache: { "/c": 1 }, fileSnap: {} } });
ok("loading a branch keeps the model in use", live.model === "qwen" && live.ctxWindow === 32768);
ok("loading a branch never rolls back spend (budget cap)", live.cost === 2 && live.inTok === 100 && live.outTok === 50 && live.byModel.qwen === 1);
ok("loading a branch adopts its context size", live.ctxUsed === 321);
ok("loading a branch leaves fileSnap a Map and both indices empty", live.fileSnap instanceof Map && live.fileSnap.size === 0 && Object.keys(live.readCache).length === 0);
B.applyBranchSess(live, {});
ok("a branch with no sess has zero context", live.ctxUsed === 0);

// darknode.js wiring
const src = fs.readFileSync(path.join(__dirname, "..", "darknode.js"), "utf8");
const exportLine = src.split("\n").find((l) => l.includes('cmd === "/export"')) || "";
ok("/export uses exportMarkdown", exportLine.includes("exportMarkdown(transcript"));
ok("/export takes the whole argument as the path (spaces allowed)", /const fp = argstr \?/.test(exportLine) && !/arg && arg\.trim\(\)/.test(exportLine));
const branchBlock = src.slice(src.indexOf('cmd === "/branch"'), src.indexOf('cmd === "/api"'));
ok("/branch saves through branchRecord, owner-only", /Branches\.branchRecord\(/.test(branchBlock) && /mode: 0o600/.test(branchBlock));
ok("/branch load no longer Object.assigns the saved sess", /Branches\.applyBranchSess\(sess, s\)/.test(branchBlock) && !/Object\.assign\(sess, s\.sess\)/.test(branchBlock));
ok("/branch new refuses to overwrite an existing branch", /already exists/.test(branchBlock));
ok("/branch switch drops the other branch's claude session", /claudeSid = ""; oneShotRan = false; carryNote = buildCarryNote\(transcript\)/.test(branchBlock));
const resets = src.split("\n").filter((l) => /oMsgs\.length = 1/.test(l));
ok("every context reset also clears the read-dedup indices", resets.length >= 5 && resets.every((l) => /sess\.readCache = \{\}/.test(l)));
const restore = src.slice(src.indexOf("const restoreSession = (s) =>"), src.indexOf("const saveSession = () =>"));
ok("/resume resets fileSnap to a Map after adopting the saved sess", /Object\.assign\(sess, s\.sess\)[\s\S]*sess\.fileSnap = new Map\(\)/.test(restore));

console.log("convo-lifecycle-audit: " + pass + " passed, " + fail + " failed");
if (fail) process.exit(1);

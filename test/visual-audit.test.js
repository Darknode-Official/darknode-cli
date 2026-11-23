"use strict";
// Regression tests for the Nexus visual-audit fixes (F1-F18): pure helpers are driven
// directly, the CLI is spawned against a scripted fake Ollama, and the TUI wiring that
// only exists inside darknode.js is checked from its source.
const fs = require("fs");
const os = require("os");
const path = require("path");
const http = require("http");
const { spawn, spawnSync } = require("child_process");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  FAIL " + name); } };
const ROOT = path.join(__dirname, "..");
const BIN = path.join(ROOT, "darknode.js");
const src = fs.readFileSync(BIN, "utf8");
const strip = (s) => String(s).replace(/\x1b\[[0-9;]*m/g, "");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "nx-vaudit-"));
const HOME = path.join(tmp, "home"); fs.mkdirSync(HOME);
const env = (extra) => Object.assign({}, process.env, { HOME, USERPROFILE: HOME, NO_COLOR: "1", DARKNODE_FAST: "1", NO_MOTION: "1", DARKNODE_API_BASE: "", OPENAI_BASE_URL: "", OPENAI_API_BASE: "" }, extra || {});

// A scripted Ollama: /api/chat answers with the next reply in the list.
function fakeOllama(replies) {
  const calls = [];
  const srv = http.createServer((req, res) => {
    let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => {
      if (req.url === "/api/tags") return res.end(JSON.stringify({ models: [{ name: "fake:latest" }] }));
      if (req.url === "/api/version") return res.end(JSON.stringify({ version: "0.9.0" }));
      if (req.url === "/api/chat") { let j = {}; try { j = JSON.parse(b); } catch (_) {} calls.push(j.messages || []); const r = replies[Math.min(calls.length - 1, replies.length - 1)]; return res.end(JSON.stringify({ message: { role: "assistant", content: typeof r === "string" ? r : JSON.stringify(r) }, done: true })); }
      res.statusCode = 404; res.end("{}");
    });
  });
  return new Promise((resolve) => srv.listen(0, "127.0.0.1", () => resolve({ port: srv.address().port, calls, close: () => new Promise((r) => srv.close(r)) })));
}
function run(args, extra, cwd) {
  return new Promise((resolve) => {
    const p = spawn(process.execPath, [BIN].concat(args), { cwd: cwd || tmp, env: env(extra), stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    p.stdout.on("data", (c) => (out += c)); p.stderr.on("data", (c) => (err += c));
    const t = setTimeout(() => { try { p.kill(); } catch (_) {} }, 60000);
    p.on("close", (code) => { clearTimeout(t); resolve({ code, out: strip(out), err: strip(err) }); });
  });
}
async function printTurn(prompt, replies) {
  const fo = await fakeOllama(replies);
  const proj = fs.mkdtempSync(path.join(tmp, "p-"));
  fs.writeFileSync(path.join(proj, "app.js"), "module.exports = 1;\n");
  const r = await run(["nexus", "-p", prompt, "-e", "ollama", "-m", "fake:latest"], { OLLAMA_HOST: "127.0.0.1:" + fo.port }, proj);
  await fo.close();
  return Object.assign(r, { calls: fo.calls, proj });
}

(async () => {
  // ---- F2: .nexus/ ignores itself ----
  {
    const ND = require("../lib/nexus/nexus-dir");
    const d = fs.mkdtempSync(path.join(tmp, "nd-"));
    fs.writeFileSync(path.join(d, ".gitignore"), "node_modules\n");
    const sub = ND.ensureNexusDir(d, "cache");
    ok("F2: ensureNexusDir creates .nexus/<sub> and returns its path", sub === path.join(d, ".nexus", "cache") && fs.statSync(sub).isDirectory());
    ok("F2: .nexus/.gitignore holds '*' and the project's own .gitignore is untouched", fs.readFileSync(path.join(d, ".nexus", ".gitignore"), "utf8") === "*\n" && fs.readFileSync(path.join(d, ".gitignore"), "utf8") === "node_modules\n");
    fs.writeFileSync(path.join(d, ".nexus", ".gitignore"), "custom\n"); ND.ensureNexusDir(d);
    ok("F2: an existing .nexus/.gitignore is never overwritten", fs.readFileSync(path.join(d, ".nexus", ".gitignore"), "utf8") === "custom\n");
    const d2 = fs.mkdtempSync(path.join(tmp, "nd-"));
    require("../lib/governance/usage").appendUsage(d2, { engine: "ollama", ok: true });
    ok("F2: writing usage.jsonl (the first thing a turn writes) also drops .nexus/.gitignore", fs.existsSync(path.join(d2, ".nexus", ".gitignore")));
    const g = spawnSync("git", ["init", "-q"], { cwd: d2 });
    if (!g.error && g.status === 0) { const st = spawnSync("git", ["status", "--porcelain", "--untracked-files=all"], { cwd: d2, encoding: "utf8" }); ok("F2: git status shows nothing from .nexus/", !/\.nexus/.test(st.stdout || "")); }
    ok("F2: darknode.js has no bare mkdir of .nexus left (all go through ensureNexusDir)", !/fs\.mkdirSync\(path\.join\(cwd, "\.nexus"\), \{ recursive: true \}\)/.test(src) && (src.match(/ensureNexusDir\(/g) || []).length >= 15);
  }

  // ---- F4: loop guard notice ----
  {
    const { makeLoopGuard } = require("../lib/nexus/loopguard");
    const lg = makeLoopGuard(); let r = null;
    for (let i = 0; i < 6 && !r; i++) r = lg.note(lg.signature("read_file", { path: "a" }), true, lg.hashStr("same"));
    ok("F4: a loop-guard nudge carries a user-facing notice (the model message stays separate)", r && r.action === "nudge" && /^loop guard: /.test(r.notice) && r.notice !== r.message && !/\bYOU\b/.test(r.notice));
    ok("F4: the TUI shows the notice once as a dim note in the turn, not as a model reply", /const _nt = _lg\.notice \|\| _lg\.message; if \(!block\.items\.some\(\(i\) => i\.type === "note" && i\.text === _nt\)\) block\.items\.push\(\{ type: "note", text: _nt \}\);/.test(src) && /else if \(it\.type === "note"\) \{[^\n]*\n\s*if \(prevType\) L\.push\(""\);\s*for \(const ln of wrap\(it\.text, 3\)\) L\.push\("  " \+ dim\(gray\(ln\)\)\);/.test(src));
  }

  // ---- F1/F10/F15: local loop helpers ----
  {
    const LL = require("../lib/nexus/local-loop");
    ok("F10: requests about the files here want tools", ["fix the bug in app.js", "list the files here", "run the tests", "refactor the auth module", "what is in this repo?"].every(LL.wantsToolWork));
    ok("F10: general questions and 'no tools' requests are not sent back to use a tool", !["say hi", "what is 2+2", "explain closures", "write a python function that reverses a string", "Do not use tools. Reply with a table of 3 fruits"].some(LL.wantsToolWork));
    ok("F10: forbidsTools spots 'do not use tools' / 'without tools' / 'no tool calls'", LL.forbidsTools("Do not use tools.") && LL.forbidsTools("answer without using tools") && LL.forbidsTools("no tool calls please") && !LL.forbidsTools("use the tools you need"));
    ok("F1: sameText spots a thought that only repeats the answer", LL.sameText("the answer is 4", "The answer is 4.") && !LL.sameText("I will read app.js first", "4") && !LL.sameText("", "4"));
    ok("F1: the TUI skips a thought that only repeats the final answer", /if \(o\.thought && !\(o\.action === "final" && LocalLoop\.sameText\(o\.thought, o\.final\)\)\)/.test(src));
    ok("F10/F15: no loop still sends 'Do the real work first.'", !/content: "Do the real work first\."/.test(src));
  }

  // ---- F15: nexus -p against a scripted model ----
  {
    let r = await printTurn("what is 2+2", [{ action: "final", final: "4" }]);
    ok("F15: -p answers a plain question on the first reply (no hidden nudge round)", r.code === 0 && r.out.trim() === "4" && r.calls.length === 1);
    r = await printTurn("what is 2+2", [{ action: "final", final: "" }]);
    ok("F15: -p with no answer prints nothing on stdout, says so on stderr and exits 1 (never the literal 'done')", r.code === 1 && r.out.trim() === "" && /no answer/.test(r.err) && !/\bdone\b/.test(r.out));
    r = await printTurn("list the files here", [{ action: "final", final: "I can't see files." }, { action: "tool", tool: "list_dir", args: { path: "." } }, { action: "final", final: "app.js" }]);
    ok("F15: a request about the files here is sent back once to look first", r.code === 0 && r.calls.length === 3 && r.calls[1].some((m) => m.role === "tool" && /use a tool first/.test(m.content)) && /app\.js/.test(r.out));
    r = await printTurn("Do not use tools. Name one fruit.", [{ action: "tool", tool: "write_file", args: { path: "x.txt", content: "y" } }, { action: "final", final: "apple" }]);
    ok("F10: with 'do not use tools' a tool call is not run and the model is told to answer directly", r.code === 0 && r.out.trim() === "apple" && !fs.existsSync(path.join(r.proj, "x.txt")) && r.calls[1].some((m) => m.role === "tool" && /asked you not to use tools/.test(m.content)));
  }

  // ---- F13: flags ----
  {
    let r = await run(["nexus", "--frobnicate"]);
    ok("F13: an unknown --flag exits 2 with a usage hint instead of becoming a one-shot task", r.code === 2 && /unknown option --frobnicate/.test(r.err) && /nexus --help/.test(r.err));
    r = await run(["nexus", "--continu"]);
    ok("F13: a near-miss suggests the real option", r.code === 2 && /did you mean --continue/.test(r.err));
    r = await run(["nexus", "--continue", "--help"]);
    ok("F13: --continue is a known option (parsed, not task text)", r.code === 0 && /Nexus/.test(r.out) && /-c, --continue/.test(r.out));
    r = await run(["nexus", "-c", "--help"]);
    ok("F13: -c is a known option", r.code === 0 && /-c, --continue/.test(r.out));
    r = await run(["nexus", "--tui", "hello"]);
    ok("F13: --tui never falls through to a one-shot run", r.code === 2 && /--tui/.test(r.err) && !/▎ nexus/.test(r.out));
    ok("F13: --continue / -c / --resume map to the same resume, and a plain --resume launch is not labelled a restart", /a === "--resume" \|\| a === "--continue" \|\| a === "-c"\) resumeFlag = true;/.test(src) && /resumeFlag && process\.env\.NEXUS_SUPERVISED \? "restart" : "launch"/.test(src));
  }

  // ---- F16: help text ----
  {
    const { wrapHelp } = require("../lib/cli/tui-format");
    const w = wrapHelp("    nexus [opts] [task]               Nexus AI coder chat: -e claude|gemini|codex|opencode|aider|ollama, @file refs, /undo /diff /commit", 60).split("\n");
    ok("F16: wrapHelp keeps every row within the width and hangs wrapped text under the description column", w.length > 1 && w.every((l) => strip(l).length <= 60) && w.slice(1).every((l) => /^ {38}\S/.test(l)));
    const r = await run(["--help"]);
    const lines = r.out.split("\n");
    ok("F16: darknode --help fits an 80-column terminal", r.code === 0 && lines.length > 20 && lines.every((l) => l.length <= 80));
    ok("F16: the help hints recommend the same local model as first-run setup", !/ollama pull gpt-oss:20b/.test(src) && /ollama pull qwen2\.5-coder/.test(src));
    const nh = await run(["nexus", "--help"]);
    ok("F16: nexus --help lists the default ask mode in the shift+tab cycle", /shift\+tab cycles permissions: ask first · accept edits · plan · bypass/.test(nh.out));
  }

  // ---- F9: markdown answers ----
  {
    const { renderMd } = require("../lib/cli/md-render");
    const B = (c) => "\x1b[1m" + c + "\x1b[0m";
    const inline = (l) => l.replace(/\*\*([^*]+)\*\*/g, (_, c) => B(c)).replace(/^(\s*)(\d+[.)])(\s)/, "$1$2$3").replace(/^(\s*[-*+]\s)/, (b) => b.replace(/[-*+]/, "•"));
    const out = renderMd("1. Open the config file and find the section called **database connection settings** which controls pooling\n2. Run tests\n- a very long bullet item that keeps going and going onto the next line of the terminal ok\n\nThe final thing to note here is that you should remember the docs and **this important bold phrase that wraps across the row boundary here** at the end. 2. and - here", 56, { inline });
    const plain = out.map(strip);
    ok("F9: ordered lists keep their numbers", plain[0].startsWith("1. ") && plain.some((l) => l.startsWith("2. Run tests")));
    ok("F9: list items wrap with a hanging indent under the text", plain[1].startsWith("   ") && plain.some((l, i) => i > 0 && plain[i - 1].startsWith("• ") && l.startsWith("  ") && !l.startsWith("   ")));
    ok("F9: bold that wraps across rows is painted on both rows, with no raw ** left", !plain.some((l) => l.includes("**")) && out.filter((l) => l.includes("\x1b[1m")).length >= 3);
    ok("F9: a wrapped prose row starting with 'N. ' or '- ' gets no bullet", !plain.some((l) => /^•/.test(l) && /here$/.test(l)) && plain[plain.length - 1].includes("2. and - here"));
    ok("F9: colorMd keeps the number of an ordered item", /s = s\.replace\(\/\^\(\\s\*\)\(\\d\+\[\.\)\]\)\(\\s\)\/, \(_, sp, n, w\) => sp \+ cyan\(n\) \+ w\)/.test(src));
  }

  // ---- F3/F5/F11: only real changes count ----
  ok("F3: a file is counted as written only after the tool succeeded (and not for 'no change')", /if \(!_failed && !blocked && \["write_file", "edit_file"\]\.includes\(name\) && a\.path && !\(result && typeof result\.note === "string" && \/\^no change\/\.test\(result\.note\)\)\) \{ stat\.files\.add\(base\(a\.path\)\);/.test(src));
  ok("F3: a run_command with a non-zero exit is a failed step", /const _failed = !!\(result && \(result\.error \|\| \(name === "run_command" && typeof result\.code === "number" && result\.code !== 0\)\)\);/.test(src));
  ok("F11: the dashboard turn count survives /clear (like the turn ledger) and 'file' is singular for one", /turns: clearedTurns \+ transcript\.filter/.test(src) && /' file'\+\(f\.files\.length===1\?'':'s'\)/.test(fs.readFileSync(path.join(ROOT, "lib", "nexus", "dashboard.js"), "utf8")));

  // ---- F6/F7: interrupted turns and recaps ----
  ok("F6: an interrupted local turn ends flagged interrupted with no 'done' text", /finish\(\{ output: "", interrupted: !!\(ctl && ctl\.stopped\) \}\);/.test(src) && !/finish\(\{ output: "done" \}\)/.test(src));
  ok("F7: no recap for an interrupted turn or one with no real output", /if \(!\(res && res\.interrupted\) && \(_realReply \|\| stat\.files\.size\) &&/.test(src));
  ok("F7: auto-recap is off by default on the local engine unless the recap setting was chosen", /const recapActive = \(\) => autoRecap && \(recapChosen \|\| engine !== "ollama" \|\| apiConfigured\(\)\);/.test(src) && /let recapChosen = typeof S\.recap === "boolean";/.test(src));

  // ---- F8: /model <number> ----
  ok("F8: arg completion prefers names that start with the text and never matches a number inside a name", /const pre = items\.filter\(\(it\) => it\[0\]\.toLowerCase\(\)\.startsWith\(partial\)\);\s*if \(\/\^\\d\+\$\/\.test\(partial\)\) return pre;/.test(src));
  ok("F8: Enter runs a typed number as typed (/model 3 picks #3)", /\(_part && !\/\^\\d\+\$\/\.test\(_part\) && !_am\.some/.test(src));

  // ---- F12/F14: Esc and saving ----
  ok("F12: Esc only pops entries flagged dismissable, and that Esc does not arm the double-Esc rewind", /_last\.dismissable/.test(src) && /_lastEscTs = 0/.test(src));
  ok("F12: Esc Esc in one read is split so the idle double-Esc still clears the input", /if \(s\.length > 1 && \/\^\\x1b\+\$\/\.test\(s\)\) \{ try \{ _escFlushing = true;/.test(src));
  ok("F14: the session is saved on exit, after setting changes and after a rewind", /const cleanup = \(\) => \{ if \(cleaned\) return; cleaned = true; tuiActive = false; try \{ saveChat\(\); \} catch/.test(src) && /\(settings\|options\|config\|theme\|color\|recap\)\$\/\.test\(cmd\)\) setTimeout\(\(\) => \{ if \(!busy\) saveChat\(\); \}, 0\)/.test(src) && /try \{ saveSession\(\); \} catch \(_\) \{\} \/\/ a resume must show the rewound state/.test(src));

  // ---- F17: permission prompts on the local engine ----
  ok("F17: modes 0 and 1 ask before a command; mode 0 also asks before file changes", /if \(!blocked && _perm !== "allow" && \(mode === 0 \|\| mode === 1\)\) \{/.test(src) && /if \(_key && \(mode === 0 \|\| !_isFile\) && !sessAllow\.has\(_key\)\) \{/.test(src) && /askUser\("Allow Nexus to " \+ _what/.test(src));
  ok("F17: usage.jsonl logs mode 3 as bypass", /mode: \["normal", "auto", "plan", "bypass"\]\[mode\] \|\| "normal"/.test(src));

  // ---- F18 ----
  {
    const TF = require("../lib/cli/tui-format");
    const v = TF.toolResultView("ask_user", {}, { skipped: true, note: "the user dismissed the question" });
    ok("F18: a dismissed ask_user card reads as text, not raw JSON", v.lines.length === 1 && v.lines[0].text === "Dismissed without an answer");
    const H = require("../lib/cli/command-help");
    ok("F18: /help settings shows its arguments", /usage \/settings \[<key> on\|off/.test(strip([].concat(H.card("/settings", "")).join("\n"))));
    ok("F18: /pager with no argument opens the last reply", /want = a === "answer" \|\| \(!a && hasReply\) \? "text" : "tool"/.test(src));
    ok("F18: /mcp says how many tools it did not list", /\(s\.tools \|\| \[\]\)\.length > 8 \? gray\(" \+" \+/.test(src));
    ok("F18: /clear resets the tab title and drops a title still being made for the old chat", /titleEpoch\+\+; if \(!titleManual\) \{ sessionTitle = ""; titleAt = 0; idleTitle\(\); \}/.test(src) && /if \(t && ep === titleEpoch\)/.test(src));
    ok("F18: /model <name> on Ollama is checked against the installed models", /no local model '" \+ a \+ "' — nothing changed/.test(src));
    ok("F18: /bisect's missing-test message uses the slash form", /run \/bisect <test command> \(e\.g\. \/bisect npm test\)/.test(src));
    ok("F18: Ctrl+C on an empty prompt shows a passing hint, not a transcript line", /case "exit-confirm": \{ const _n = \{ text: "Press Ctrl\+C again to exit", ok: false \}; linkNotice = _n;/.test(src));
    ok("F18: rotating tips end with an ellipsis instead of being cut mid-word", /fitWidth\("tip  " \+ tips\[/.test(src));
    ok("F18: /settings rows keep their columns on a narrow terminal", /const fitW = cols\(\) - 4;/.test(src) && /"env vars: " \+ envLater\.join/.test(src));
  }

  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) {}
  console.log("visual-audit: " + pass + " passed, " + fail + " failed");
  if (fail) process.exit(1);
})();

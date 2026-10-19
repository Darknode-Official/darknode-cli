"use strict";
// Composer + settings suite — pure ComposerModel / key dispatch and the
// off-by-default persistent settings store. `npm test` runs it after the others.
const fs = require("fs"), os = require("os"), path = require("path");
const C = require("../lib/cli/composer");
const NS = require("../lib/cli/nexus-settings");
const T = require("../lib/cli/text");
const TF = require("../lib/cli/tui-format");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const eq = (name, a, b) => ok(name + "  (" + JSON.stringify(a) + " === " + JSON.stringify(b) + ")", JSON.stringify(a) === JSON.stringify(b));
const group = (t) => console.log("\n\x1b[1m" + t + "\x1b[0m");

// Mimic the darknode.js glue: feed(), and on a history edge-effect step history.
function drive(m, seq, env, now) {
  const eff = C.feed(m, seq, env || {}, now);
  if (eff.type === "history-up") m.historyPrev();
  else if (eff.type === "history-down") m.historyNext();
  return eff;
}
const typeStr = (m, s) => { for (const ch of s) C.feed(m, ch, {}); };

group("keymap — the key->action table");
eq("Alt+Enter = newline", C.keymap("\x1b\r"), "newline");
eq("Ctrl+J = newline", C.keymap("\n"), "newline");
eq("Shift+Enter (CSI-u) = newline", C.keymap("\x1b[13;2u"), "newline");
eq("Shift+Enter (modifyOtherKeys) = newline", C.keymap("\x1b[27;2;13~"), "newline");
eq("plain Enter = enter", C.keymap("\r"), "enter");
eq("Ctrl+Left = word-left", C.keymap("\x1b[1;5D"), "word-left");
eq("Alt+F = word-right", C.keymap("\x1bf"), "word-right");
eq("Alt+Backspace = delete-word-back", C.keymap("\x1b\x7f"), "delete-word-back");
eq("Ctrl+K = kill-to-end", C.keymap("\x0b"), "kill-to-end");
eq("Ctrl+Y = yank", C.keymap("\x19"), "yank");
eq("Ctrl+_ = undo", C.keymap("\x1f"), "undo");
eq("Ctrl+R = search", C.keymap("\x12"), "search");
eq("Ctrl+L = redraw", C.keymap("\x0c"), "redraw");
eq("Ctrl+G = editor", C.keymap("\x07"), "editor");
eq("lone Esc = esc", C.keymap("\x1b"), "esc");
eq("printable is not a mapped action", C.keymap("a"), null);

group("history — draft restore (the regression)");
{
  const m = new C.ComposerModel({ history: ["first", "second"] });
  typeStr(m, "hi");                 // live draft
  drive(m, "\x1b[A");               // Up -> "second"
  eq("Up -> newest history", m.text, "second");
  drive(m, "\x1b[A");               // Up -> "first"
  eq("Up again -> older history", m.text, "first");
  drive(m, "\x1b[B");               // Down -> "second"
  eq("Down -> newer history", m.text, "second");
  drive(m, "\x1b[B");               // Down past newest -> the saved draft
  eq("Down past newest restores the typed draft", m.text, "hi");
}

group("multiline — Up/Down move the cursor, then step into history");
{
  const m = new C.ComposerModel({ history: ["older"] });
  m.text = "ab\ncd"; m.cursor = 4;  // on the second line
  const e1 = drive(m, "\x1b[A");    // moves up within the buffer
  eq("Up within a multiline buffer moves the cursor", e1.type, "render");
  ok("cursor landed on the first line", m.cursor < 3 && m.text === "ab\ncd");
  const e2 = drive(m, "\x1b[A");    // already on the top line -> history
  eq("Up on the top line steps into history", m.text, "older");
  ok("that was a history edge", e2.type === "history-up");
}

group("reverse-i-search (Ctrl+R)");
{
  const m = new C.ComposerModel({ history: ["git status", "git commit", "npm test"] });
  drive(m, "\x12"); ok("Ctrl+R enters search mode", m.searchMode === true);
  typeStr(m, "commit");
  eq("typing filters to the matching entry", m.text, "git commit");
  drive(m, "\r"); ok("Enter accepts the match into the buffer", !m.searchMode && m.text === "git commit");
  // cycle + cancel
  const m2 = new C.ComposerModel({ history: ["aa one", "bb two", "aa three"] });
  m2.text = "draft"; m2.cursor = 5;
  drive(m2, "\x12"); typeStr(m2, "aa");
  eq("filters to the newest 'aa' match", m2.text, "aa three");
  drive(m2, "\x12");               // Ctrl+R again = older match
  eq("Ctrl+R again cycles to the older match", m2.text, "aa one");
  drive(m2, "\x1b"); ok("Esc cancels search and restores the draft", !m2.searchMode && m2.text === "draft");
}

group("paste — collapse + expand on submit");
{
  const m = new C.ComposerModel();
  const big = Array.from({ length: 12 }, (_, i) => "line " + i).join("\n");
  const r = m.paste(big);
  ok("a >10-line paste collapses", r.collapsed === true);
  ok("buffer shows the placeholder", /\[Pasted text #1 \+12 lines\]/.test(m.text));
  eq("expand restores the real text", m.expand(m.text), big);
  const small = "just a short line";
  m.paste(small);
  ok("a small paste is inserted verbatim", m.text.includes(small));
  // placeholder deletes as one unit
  const m2 = new C.ComposerModel();
  m2.paste(big); const before = m2.text.length;
  m2.backspace();
  ok("backspace removes the whole placeholder", m2.text.length < before - 5 && !/Pasted/.test(m2.text));
}

group("kill-ring + yank");
{
  const m = new C.ComposerModel({ text: "hello world" }); m.cursor = m.text.length;
  C.feed(m, "\x0b", {}); // Ctrl+K at end = no-op
  m.cursor = 6;          // before "world"
  C.feed(m, "\x0b", {}); // Ctrl+K -> kill "world"
  eq("Ctrl+K kills to end of line", m.text, "hello ");
  C.feed(m, "\x19", {}); // Ctrl+Y yank
  eq("Ctrl+Y yanks the kill back", m.text, "hello world");
  const m2 = new C.ComposerModel({ text: "alpha beta" }); m2.cursor = m2.text.length;
  C.feed(m2, "\x17", {}); // Ctrl+W -> delete word back
  eq("Ctrl+W deletes a word back", m2.text, "alpha ");
  C.feed(m2, "\x15", {}); // Ctrl+U -> kill to start
  eq("Ctrl+U kills to start of line", m2.text, "");
  C.feed(m2, "\x19", {}); // yank the Ctrl+U kill
  eq("yank restores the Ctrl+U kill", m2.text, "alpha ");
}

group("undo (Ctrl+_)");
{
  const m = new C.ComposerModel();
  typeStr(m, "abc");
  C.feed(m, "\x1f", {}); // undo last insert
  ok("undo reverts the last edit", m.text === "ab");
}

group("word jumps");
{
  const m = new C.ComposerModel({ text: "foo bar baz" }); m.cursor = m.text.length;
  C.feed(m, "\x1b[1;5D", {}); // Ctrl+Left
  eq("Ctrl+Left jumps to the last word start", m.cursor, 8);
  C.feed(m, "\x1bb", {});     // Alt+B
  eq("Alt+B jumps back another word", m.cursor, 4);
  C.feed(m, "\x1bf", {});     // Alt+F
  eq("Alt+F jumps forward a word", m.cursor, 7);
}

group("Ctrl+C state machine + Esc disambiguation");
{
  // busy -> interrupt
  const mb = new C.ComposerModel({ text: "x" });
  eq("Ctrl+C while busy interrupts", C.feed(mb, "\x03", { busy: true }).type, "interrupt");
  // non-empty idle -> clear
  const mc = new C.ComposerModel({ text: "draft" });
  C.feed(mc, "\x03", { busy: false });
  ok("Ctrl+C on a non-empty idle buffer clears it", mc.text === "");
  // empty idle -> confirm, then exit within 2s
  const md = new C.ComposerModel();
  eq("1st Ctrl+C on empty asks to confirm", C.feed(md, "\x03", { busy: false }, 1000).type, "exit-confirm");
  eq("2nd Ctrl+C within 2s exits", C.feed(md, "\x03", { busy: false }, 1500).type, "exit");
  const md2 = new C.ComposerModel();
  C.feed(md2, "\x03", { busy: false }, 1000);
  eq("2nd Ctrl+C after 2s re-confirms (no exit)", C.feed(md2, "\x03", { busy: false }, 4000).type, "exit-confirm");
  // Ctrl+D empty = exit; non-empty = forward delete
  eq("Ctrl+D on empty exits", C.feed(new C.ComposerModel(), "\x04", {}).type, "exit");
  const me = new C.ComposerModel({ text: "ab" }); me.cursor = 0;
  C.feed(me, "\x04", {});
  eq("Ctrl+D on non-empty forward-deletes", me.text, "b");
  // Esc: a lone Esc while busy interrupts; an arrow-key escape SEQUENCE does not
  eq("lone Esc while busy interrupts", C.feed(new C.ComposerModel(), "\x1b", { busy: true }).type, "interrupt");
  const mf = new C.ComposerModel({ text: "hi" }); mf.cursor = 2;
  eq("an escape SEQUENCE (arrow) is not an interrupt", C.feed(mf, "\x1b[D", { busy: true }).type, "none");
  // Esc Esc on idle clears, after saving to history
  const mg = new C.ComposerModel({ text: "scratch" });
  C.feed(mg, "\x1b", { busy: false }, 1000);          // first Esc arms
  C.feed(mg, "\x1b", { busy: false }, 1200);          // second Esc within 600ms
  ok("Esc Esc clears the idle buffer", mg.text === "");
  ok("the cleared text went into history first", mg.history[mg.history.length - 1] === "scratch");
}

group("newline chords vs submit");
{
  const m = new C.ComposerModel({ text: "a" }); m.cursor = 1;
  eq("Alt+Enter inserts a newline", C.feed(m, "\x1b\r", {}).type, "newline");
  ok("the newline landed in the buffer", m.text === "a\n");
  const m2 = new C.ComposerModel({ text: "line\\" }); m2.cursor = m2.text.length;
  const e = C.feed(m2, "\r", {});
  ok("trailing backslash + Enter = newline, not submit", e.type === "newline" && m2.text === "line\n");
  const m3 = new C.ComposerModel({ text: "send me" }); m3.cursor = m3.text.length;
  const e3 = C.feed(m3, "\r", {});
  ok("plain Enter submits", e3.type === "submit" && e3.text === "send me");
}

group("history persistence — per-project, dedup, capped, round-trip");
{
  const HOME = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-hist-"));
  const cwd = "/some/project";
  C.appendHistory("alpha", cwd, HOME);
  C.appendHistory("beta", cwd, HOME);
  C.appendHistory("beta", cwd, HOME);   // consecutive dupe — skipped
  C.appendHistory("gamma", cwd, HOME);
  const loaded = C.loadHistory(cwd, 1000, HOME);
  eq("round-trips in order, consecutive dupes dropped", loaded, ["alpha", "beta", "gamma"]);
  // scoped per project: a different cwd has its own file
  eq("a different project has independent history", C.loadHistory("/other", 1000, HOME), []);
  // cap
  for (let i = 0; i < 1100; i++) C.appendHistory("entry-" + i, "/cap/proj", HOME);
  const capped = C.loadHistory("/cap/proj", C.HISTORY_CAP, HOME);
  ok("history is capped at 1000", capped.length === 1000 && capped[capped.length - 1] === "entry-1099");
  fs.rmSync(HOME, { recursive: true, force: true });
}

group("settings — off by default, persisted, env precedence, corrupt-safe");
{
  const HOME = fs.mkdtempSync(path.join(os.tmpdir(), "nexus-set-"));
  // 1. defaults are all off / unlimited
  const r0 = NS.resolve(HOME, {});
  eq("budget cap default = 0 (unlimited)", r0.value.budgetCap, 0);
  ok("every limit default is off", r0.value.autoCompact === false && r0.value.minimizeCalls === false && r0.value.stepCap === false && r0.value.trimOutput === false && r0.value.cache === false && r0.value.map === false);
  ok("all defaults report source 'default'", Object.values(r0.source).every((s) => s === "default"));
  // 5. no --max-budget-usd flag when the budget is off (mirrors darknode's `costCap ? flag : undefined`)
  const costCap0 = r0.value.budgetCap; // 0
  eq("budget off => no --max-budget-usd argument", (costCap0 ? "flag" : undefined), undefined);
  // 2. a toggle writes, a fresh load reads it back
  const store = NS.createStore(HOME, {});
  store.set("cache", true); store.set("budgetCap", 5); store.set("map", true);
  const r1 = NS.resolve(HOME, {});
  ok("saved values come back on a fresh load", r1.value.cache === true && r1.value.budgetCap === 5 && r1.value.map === true);
  ok("saved values report source 'saved'", r1.source.cache === "saved" && r1.source.budgetCap === "saved");
  const costCap5 = r1.value.budgetCap;
  eq("budget on => a --max-budget-usd argument IS sent", (costCap5 ? "flag" : undefined), "flag");
  // 3. an env var overrides the saved value for this launch
  const r2 = NS.resolve(HOME, { NEXUS_BUDGET: "0", NEXUS_CACHE: "off" });
  eq("env NEXUS_BUDGET=0 overrides the saved cap", r2.value.budgetCap, 0);
  ok("env source is reported", r2.source.budgetCap === "env" && r2.source.cache === "env");
  eq("env NEXUS_CACHE=off overrides saved cache=on", r2.value.cache, false);
  // 4. a corrupt file falls back to defaults safely
  fs.writeFileSync(NS.settingsPath(HOME), "{ this is not json ::::");
  const r3 = NS.resolve(HOME, {});
  ok("a corrupt settings file falls back to defaults", r3.value.budgetCap === 0 && r3.value.cache === false);
  // atomic write leaves no stray temp file
  const dir = path.dirname(NS.settingsPath(HOME));
  NS.createStore(HOME, {}).set("lean", true);
  ok("atomic write leaves no .tmp file behind", !fs.readdirSync(dir).some((f) => f.includes(".tmp-")));
  fs.rmSync(HOME, { recursive: true, force: true });
}

group("@path completion — longest common prefix, not the first entry");
{
  eq("no matches -> null", T.commonPrefix([]), "");
  eq("single string is its own prefix", T.commonPrefix(["abc"]), "abc");
  eq("shared prefix of several", T.commonPrefix(["abc", "abd", "abe"]), "ab");
  eq("no shared prefix -> empty", T.commonPrefix(["abc", "xyz"]), "");
  eq("completePath: nothing matches -> null", T.completePath([], "re"), null);
  eq("completePath: one match completes fully + unique", T.completePath(["README.md"], "RE"), { value: "README.md", unique: true });
  // several matches advance to the common prefix instead of silently picking entry[0]
  eq("completePath: several matches -> common prefix", T.completePath(["apple", "apply"], "app"), { value: "appl", unique: false, count: 2 });
  // when the common prefix is already typed, don't commit to the first entry
  const amb = T.completePath(["app.js", "apple.txt"], "app");
  ok("ambiguous with no further common chars stays put (no jump to entry[0])", amb.value === "app" && amb.unique === false);
}

group("settings env docs — every governed limit documents a NEXUS_ env var");
{
  // The /settings "Limits" panel shows these keys; each row now prints the env
  // var that overrides it. Guard that the doc data stays complete + truthful.
  const limitKeys = ["budgetCap", "autoCompact", "minimizeCalls", "stepCap", "trimOutput", "cache", "map", "lean"];
  for (const k of limitKeys) ok("env var documented for " + k, typeof NS.ENV_NAME[k] === "string" && /^NEXUS_/.test(NS.ENV_NAME[k]));
}

group("deleteForward — a collapsed-paste marker deletes as one unit");
{
  // forward-delete must mirror backspace: a whole [Pasted text #N +M lines]
  // marker is removed in one keypress, never shredded into a broken marker.
  const m = new C.ComposerModel({ text: "[Pasted text #1 +12 lines]tail" }); m.cursor = 0;
  m.deleteForward();
  eq("forward-delete removes the whole paste marker", m.text, "tail");
  const mi = new C.ComposerModel({ text: "[Image#2]x" }); mi.cursor = 0;
  mi.deleteForward();
  eq("forward-delete removes the whole image marker", mi.text, "x");
  const m2 = new C.ComposerModel({ text: "abc" }); m2.cursor = 0; m2.deleteForward();
  eq("forward-delete still removes one normal char", m2.text, "bc");
}

group("Esc Esc on idle saves EXPANDED text to history (not the raw marker)");
{
  const m = new C.ComposerModel();
  m.pastes = ["the real pasted body"];
  m.text = "[Pasted text #1 +3 lines]"; m.cursor = m.text.length;
  C.feed(m, "\x1b", {}, 5000);          // first Esc arms the double-press
  const r = C.feed(m, "\x1b", {}, 5000); // second Esc within the window clears
  eq("Esc Esc clears the buffer", m.text, "");
  eq("Esc Esc returns a render", r.type, "render");
  eq("history holds the expanded text, not the marker", m.history[m.history.length - 1], "the real pasted body");
}

group("shortenPath — zero/negative width yields empty, like fitWidth");
{
  eq("max 0 -> empty", TF.shortenPath("/home/u/project", 0), "");
  eq("max negative -> empty", TF.shortenPath("/home/u/project", -5), "");
  eq("fits untouched", TF.shortenPath("/a/b", 20), "/a/b");
  ok("over-long is truncated with ellipsis", TF.shortenPath("/home/user/deep/nested/path", 10).length <= 10);
}

group("persisted prefs — /style and /redact round-trip; dead defaults removed");
{
  ok("DEFAULTS has style", "style" in NS.DEFAULTS);
  ok("DEFAULTS has redact", "redact" in NS.DEFAULTS);
  ok("dead default cowork removed", !("cowork" in NS.DEFAULTS));
  ok("dead default cheap removed", !("cheap" in NS.DEFAULTS));
  const HOME = fs.mkdtempSync(path.join(os.tmpdir(), "nx-pref-"));
  const s1 = NS.createStore(HOME, {});
  s1.set("style", "concise"); s1.set("redact", true);
  const s2 = NS.createStore(HOME, {});   // a fresh launch loads from disk
  eq("style persists across launches", s2.get("style"), "concise");
  eq("redact persists across launches", s2.get("redact"), true);
  fs.rmSync(HOME, { recursive: true, force: true });
}

console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (composer + settings)");
process.exit(fail ? 1 : 0);

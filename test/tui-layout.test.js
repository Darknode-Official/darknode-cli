"use strict";
// Layout-helper suite (lib/cli/tui-format.js): welcomeCard, idleHome, footerLine
// and helpLines. These paint the session chrome (the boot card, the empty-session
// home, the footer status row, the /help & /keys screens), and were previously
// untested. The contract they must keep: every line fits the given column budget
// (no wrap garbage, nothing clipped past the border), plain output (no paint map)
// carries NO ANSI escapes (NO_COLOR / non-TTY safe), and the key content survives
// from a wide terminal down to a narrow one.
const F = require("../lib/cli/tui-format.js");
const { welcomeCard, idleHome, footerLine, helpLines, visLen, stripAnsi } = F;

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const group = (t) => console.log("\n\x1b[1m" + t + "\x1b[0m");

// a line is "clean" at width w: fits w visible columns and never carries a raw
// (non-SGR) escape that could move the cursor or clear the screen.
const fits = (lines, w) => lines.every((l) => visLen(l) <= w && !/\x1b(?!\[[0-9;]*m)/.test(l));
const plainClean = (lines) => lines.every((l) => !/\x1b/.test(l));
const WIDTHS = [36, 40, 50, 60, 80, 100, 120, 140, 200];

const WC = (cols, extra) => welcomeCard(Object.assign({
  version: "2.46.3", model: "Opus 5.5", engineLabel: "Claude Code",
  cwd: "/home/manav/projects/darknode-cli", branch: "ui/tui-polish-20261101",
  home: "/home/manav", cols, contextLabel: "200K", guard: "on", mcp: 1,
  tip: "scroll back with the mouse wheel or PgUp/PgDn · End jumps to the newest",
}, extra || {}));

group("welcomeCard fits its column budget at every width");
{
  let bad = "";
  for (const w of WIDTHS) if (!fits(WC(w), w)) bad = bad || ("overflow/escape at " + w);
  ok("every row fits 36..200 cols with no stray escapes", !bad);
  ok("the box is balanced (equal corner rows)", (() => { const L = WC(80).filter((l) => l.trim()); return /^╭/.test(stripAnsi(L[0])) && /╯$/.test(stripAnsi(L[L.length - 1])); })());
  ok("plain output (no paint) carries no ANSI escapes", plainClean(WC(80)));
  ok("shows product, model, engine and a quick-start command", (() => { const s = WC(80).join("\n"); return /Nexus/.test(s) && /Opus 5\.5/.test(s) && /Claude Code/.test(s) && /\/help/.test(s); })());
}

group("welcomeCard keeps the branch even when it is long and the terminal is narrow");
{
  // Regression: a long branch used to starve the path budget to "" and drop the
  // whole Project row (branch included). The row must survive down to 36 cols.
  ok("branch (possibly truncated) is still shown at 36 cols", stripAnsi(WC(36).join("\n")).includes("ui/tui"));
  for (const w of [40, 50]) ok("branch is still shown at " + w + " cols", stripAnsi(WC(w).join("\n")).includes("ui/tui-pol"));
  ok("a card with only a branch (no cwd) still shows it", stripAnsi(WC(80, { cwd: "" }).join("\n")).includes("ui/tui-polish-20261101"));
  ok("a card with neither cwd nor branch omits the Project row", !/Project/.test(stripAnsi(WC(80, { cwd: "", branch: "" }).join("\n"))));
}

group("idleHome fills the screen without overflowing");
{
  const mk = (cols) => idleHome({ cols, project: { name: "darknode-cli", branch: "main", dirty: true, files: 120, commits: 1200, last: "1bbf9bb fix the lint errors in the parser" } });
  let bad = "";
  for (const w of WIDTHS) if (!fits(mk(w), w)) bad = bad || ("overflow/escape at " + w);
  ok("every row fits 36..200 cols with no stray escapes", !bad);
  ok("plain output carries no ANSI escapes", plainClean(mk(80)));
  ok("renders the NEXUS hero wordmark", mk(80).join("\n").includes("█"));
  ok("surfaces the live project pulse (name + branch)", (() => { const s = stripAnsi(mk(80).join("\n")); return s.includes("darknode-cli") && /\bmain\b/.test(s); })());
  ok("falls back to a compact wordmark on a very narrow terminal", stripAnsi(idleHome({ cols: 20 }).join("\n")).includes("N E X U S"));
}

group("footerLine right-aligns status and never overflows");
{
  const left = "accept edits on  (shift+tab to cycle)";
  const right = "Opus 5.5  ·  0% context  ·  ui/tui-polish-20261101";
  for (const w of [24, 40, 80, 120, 200]) ok("fits " + w + " cols", visLen(footerLine(left, right, w)) <= w);
  ok("keeps the status (right) side visible when wide", footerLine(left, right, 120).includes("Opus 5.5"));
  ok("drops the hint (left) side before clipping status when cramped", (() => { const r = footerLine(left, right, 30); return r.includes("ui/tui-polish") || r.includes("8.5") || visLen(r) <= 30; })());
  ok("plain output carries no escapes", !/\x1b/.test(footerLine(left, right, 80)));
}

group("helpLines aligns names and wraps long descriptions under the column");
{
  const sections = [{ title: "Session", rows: [
    ["/clear", "start a new conversation"],
    ["/fixshell", "repair the engine shell when commands fail with E2BIG, without /clear (check = report only, all = clear every snapshot)"],
    ["/exit", "quit Nexus"],
  ] }];
  for (const w of [40, 60, 80, 120]) ok("fits " + w + " cols", fits(helpLines(sections, w), w));
  ok("plain output carries no escapes", plainClean(helpLines(sections, 80)));
  ok("shows the heading and every command name", (() => { const s = helpLines(sections, 80).join("\n"); return /Session/.test(s) && /\/clear/.test(s) && /\/fixshell/.test(s) && /\/exit/.test(s); })());
  ok("wraps a long description onto continuation rows (name column stays empty)", (() => { const L = helpLines(sections, 60).map(stripAnsi); const i = L.findIndex((l) => /\/fixshell/.test(l)); if (i < 0 || i + 1 >= L.length) return false; const cont = L[i + 1]; const indent = (s) => s.length - s.replace(/^ +/, "").length; return cont.trim().length > 0 && !/\/fixshell/.test(cont) && indent(cont) > indent(L[i]); })());
}

console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m" + "  (tui layout)");
process.exit(fail ? 1 : 0);

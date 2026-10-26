"use strict";
// Pager suite (lib/cli/pager.js): movement, search, layout, limits.
const { createPager, pagerKey, pagerView, scrollBy } = require("../lib/cli/pager");
const { strWidth } = require("../lib/cli/tui-format");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const eq = (name, a, b) => ok(name + "  (" + JSON.stringify(a) + " === " + JSON.stringify(b) + ")", JSON.stringify(a) === JSON.stringify(b));
const group = (t) => console.log("\n\x1b[1m" + t + "\x1b[0m");

const doc = (n, f) => Array.from({ length: n }, (_, i) => (f ? f(i) : "line " + (i + 1))).join("\n");
const W = 60, H = 12, BH = H - 2;
const open = (text) => { const st = createPager(text, "Bash(npm test)"); pagerView(st, W, H); return st; };
const keys = (st, ks) => { let r = null; for (const k of ks) r = pagerKey(st, k, BH); return r; };
const firstNum = (st) => { const row = pagerView(st, W, H)[1]; return parseInt(row.replace(/^│\s*/, ""), 10); };

group("movement");
{
  const st = open(doc(100));
  eq("opens at the top", firstNum(st), 1);
  keys(st, ["G"]); eq("G goes to the end (last line on the last row)", pagerView(st, W, H)[BH].includes("line 100"), true);
  keys(st, ["g"]); eq("g returns to the top", firstNum(st), 1);
  keys(st, ["j", "j", "\x1b[B"]); eq("j / down scroll one line", firstNum(st), 4);
  keys(st, ["k"]); eq("k scrolls up", firstNum(st), 3);
  keys(st, ["g", " "]); eq("space pages by height-1 (one line of overlap)", firstNum(st), BH);
  keys(st, ["b"]); eq("b pages back", firstNum(st), 1);
  keys(st, ["d"]); eq("d half page", firstNum(st), 1 + BH / 2);
  keys(st, ["k", "k", "k", "k", "k", "k", "k", "k"]); eq("never scrolls above the top", firstNum(st), 1);
  keys(st, ["G", "j", "j"]); eq("never scrolls past the end", firstNum(st), 100 - BH + 1);
  scrollBy(st, -5, BH); eq("wheel scroll", firstNum(st), 100 - BH - 4);
  eq("q closes", keys(st, ["q"]), "close");
  eq("esc closes", pagerKey(open("x"), "\x1b", BH), "close");
}

group("search");
{
  const st = open(doc(100, (i) => (i === 29 || i === 79 ? "ERROR at step " + i : "ok " + i)));
  keys(st, ["/", "E", "R", "R", "\r"]);
  ok("/ search jumps to the first match", pagerView(st, W, H).some((r) => r.includes("{ERR}OR") || r.includes("{ERR}")));
  ok("the current match is on screen", pagerView(st, W, H).join("\n").includes("step 29"));
  keys(st, ["n"]); ok("n goes to the next match", pagerView(st, W, H).join("\n").includes("step 79"));
  keys(st, ["n"]); ok("n wraps to the first match", pagerView(st, W, H).join("\n").includes("step 29") && st.msg.includes("wrapped"));
  keys(st, ["N"]); ok("N goes back (wrapping)", pagerView(st, W, H).join("\n").includes("step 79"));
  const lo = open("Foo\nfoo\nFOO"); keys(lo, ["/", "f", "o", "o", "\r"]);
  eq("lowercase query is case-insensitive", lo.hits.length, 3);
  const up = open("Foo\nfoo\nFOO"); keys(up, ["/", "F", "o", "o", "\r"]);
  eq("a capital makes it case-sensitive (smart case)", up.hits.length, 1);
  const none = open(doc(20)); keys(none, ["/", "z", "z", "\r"]);
  ok("no match reports it", none.msg.includes("no match"));
  const esc = open(doc(20)); keys(esc, ["/", "a", "\x1b"]);
  ok("esc cancels typing without closing", !esc.typing && esc.query === "");
  const bs = open(doc(5)); keys(bs, ["/", "a", "b", "\x7f"]); eq("backspace edits the query", bs.input, "a");
  const special = open("a.b\naxb"); keys(special, ["/", "a", ".", "b", "\r"]); eq("search is literal, not regex", special.hits.length, 1);
  const typing = open(doc(30)); keys(typing, ["/", "q"]); ok("q while typing is text, not close", typing.input === "q");
}

group("layout");
{
  const st = open(doc(30));
  const v = pagerView(st, W, H);
  eq("exactly height rows", v.length, H);
  ok("every row is exactly the width", v.every((r) => strWidth(r) === W));
  ok("title and position in the header", v[0].includes("Bash(npm test)") && v[0].includes("30 lines"));
  const long = open("x".repeat(200));
  const lv = pagerView(long, W, H);
  ok("a long line wraps under one line number", /│\s+1 x+/.test(lv[1]) && /│\s+x+/.test(lv[2]));
  const wide = open("日本語".repeat(40)); ok("wide glyphs keep borders aligned", pagerView(wide, W, H).every((r) => strWidth(r) === W));
  const col = open("\x1b[31mred\x1b[0m\tTab\x1b]0;evil\x07"); const cv = pagerView(col, W, H)[1];
  ok("ANSI / OSC in the output is stripped and tabs expanded", cv.includes("red  Tab") && !cv.includes("\x1b]"));
  const narrow = open(doc(50)); keys(narrow, ["G"]); pagerView(narrow, 30, H);
  ok("resize keeps the view inside bounds", pagerView(narrow, 30, H).every((r) => strWidth(r) === 30));
  eq("trailing blank lines dropped", open("a\nb\n\n\n").lines.length, 2);
  eq("empty text still renders", pagerView(createPager("", "t"), W, H).length, H);
}

group("open with a query (/find)");
{
  const text = doc(100, (i) => (i === 10 || i === 60 || i === 90 ? "token leak " + i : "ok " + i));
  const last = createPager(text, "find", { query: "leak", at: "last" }); const lv = pagerView(last, W, H).join("\n");
  ok("lands on the newest match", lv.includes("{leak} 90") && last.hi === 2);
  ok("says how many matches and how to go back", /3 matches · newest shown, N for older/.test(last.msg));
  keys(last, ["N"]); ok("N steps to the older match", pagerView(last, W, H).join("\n").includes("{leak} 60"));
  const first = createPager(text, "find", { query: "leak" }); pagerView(first, W, H);
  eq("default lands on the first match", first.hi, 0);
  const none = createPager(text, "find", { query: "zzz", at: "last" }); pagerView(none, W, H);
  ok("no match is reported", /no match for "zzz"/.test(none.msg));
  const end = createPager(doc(100), "conversation", { at: "last" });
  ok("no query + at last opens at the end", pagerView(end, W, H)[BH].includes("line 100"));
}
{
  const { conversationText } = require("../lib/cli/convo-text");
  const t = conversationText([
    { role: "user", text: "check the server" },
    { role: "nexus", items: [{ type: "tool", label: "Bash(curl -I x)", status: "ok", result: { output: "HTTP/1.1 500\nServer: nginx" } }, { type: "text", full: "It returns **500**." }] },
    { role: "system", text: "\x1b[32mdone\x1b[0m" },
  ], (r) => (r && r.output) || String(r));
  ok("prompts, tool output (indented) and answers are all searchable", t.includes("❯ check the server") && t.includes("● Bash(curl -I x)\n    HTTP/1.1 500\n    Server: nginx") && t.includes("It returns **500**."));
  ok("system notes are included without colour codes", t.includes("done") && !t.includes("\x1b"));
  eq("empty transcript is empty text", conversationText([], null), "");
}

group("limits");
{
  const big = createPager(doc(250000), "big");
  ok("very long output is capped and says so", big.lines.length === 200000 && /200,000 of 250,000/.test(big.note));
  const huge = createPager("y".repeat(100000), "min"); ok("a single huge line is cut", huge.lines[0].length < 70000 && huge.lines[0].endsWith("…"));
}

console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (pager)");
process.exit(fail ? 1 : 0);

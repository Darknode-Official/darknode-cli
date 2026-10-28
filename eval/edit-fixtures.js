#!/usr/bin/env node
"use strict";
// Edit-engine fixture suite (plan metric #1, engine side).
//
// Each case is a file plus an edit written the way models get edits slightly wrong
// (lost indentation, tabs vs spaces, CRLF, copied line numbers, drifted patch line
// numbers, ...) and the one right outcome: the exact file it must become, or a refusal
// that leaves the file alone. This measures how well the ENGINE copes with those
// mistakes. It is not the real-world apply rate of a model, which needs real sessions.
//
// Scored per case:
//   correct     - applied and the file is exactly the expected text, or refused when it should be
//   refused     - refused an edit it should have applied (a missed opportunity, file untouched)
//   corrupted   - applied, but the file is not the expected text, or applied when it should refuse.
//                 This must stay 0: a refusal costs a retry, a corruption costs the user's code.
//
//   node eval/edit-fixtures.js          # scorecard
//   node eval/edit-fixtures.js --fail   # also print every case that was not correct
const E = require("../lib/nexus/edit");

const edit = (find, replace, extra) => ({ tool: "edit", edits: [Object.assign({ find, replace }, extra || {})] });
const multi = (edits) => ({ tool: "edit", edits });
const patch = (text) => ({ tool: "patch", patch: text });

const PY = "def total(items):\n    s = 0\n    for it in items:\n        s += it.price\n    return s\n";
const JS = "function load(cfg) {\n  const url = cfg.url;\n  if (!url) {\n    throw new Error('no url');\n  }\n  return fetch(url);\n}\n";
const GO = "func main() {\n\tx := 1\n\tif x > 0 {\n\t\tfmt.Println(x)\n\t}\n}\n";
const TWIN = "function a() {\n  return 1;\n}\nfunction b() {\n  return 1;\n}\n";

const CASES = [
  // ---- baseline
  { id: "exact-one-line", cat: "exact", file: JS, op: edit("const url = cfg.url;", "const url = cfg.url || cfg.href;"), want: JS.replace("cfg.url;", "cfg.url || cfg.href;") },
  { id: "exact-block", cat: "exact", file: PY, op: edit("    for it in items:\n        s += it.price\n", "    for it in items:\n        s += it.price * it.qty\n"), want: PY.replace("it.price\n", "it.price * it.qty\n") },
  { id: "replace-all", cat: "exact", file: TWIN, op: edit("return 1;", "return 2;", { replaceAll: true }), want: TWIN.replace(/return 1;/g, "return 2;") },
  { id: "multi-edit", cat: "exact", file: JS, op: multi([{ find: "cfg.url;", replace: "cfg.href;" }, { find: "'no url'", replace: "'no href'" }]), want: JS.replace("cfg.url;", "cfg.href;").replace("'no url'", "'no href'") },

  // ---- indentation the model lost or changed
  { id: "find-no-indent", cat: "indent", file: PY, op: edit("s += it.price", "s += it.price * it.qty"), want: PY.replace("it.price\n", "it.price * it.qty\n") },
  { id: "block-no-indent", cat: "indent", file: PY, op: edit("for it in items:\n    s += it.price", "for it in items:\n    if it:\n        s += it.price"), want: PY.replace("    for it in items:\n        s += it.price\n", "    for it in items:\n        if it:\n            s += it.price\n") },
  { id: "block-wrong-indent", cat: "indent", file: JS, op: edit("    if (!url) {\n      throw new Error('no url');\n    }", "    if (!url) {\n      return null;\n    }"), want: JS.replace("  if (!url) {\n    throw new Error('no url');\n  }", "  if (!url) {\n    return null;\n  }") },
  { id: "tabs-find-as-spaces", cat: "indent", file: GO, op: edit("    if x > 0 {\n        fmt.Println(x)\n    }", "    if x > 1 {\n        fmt.Println(x)\n    }"), want: GO.replace("x > 0", "x > 1") },
  { id: "tabs-new-line-as-spaces", cat: "indent", file: GO, op: edit("\tx := 1\n", "\tx := 1\n    y := 2\n"), want: null, note: "exact match; the replacement's own spaces are taken literally" },

  // ---- whitespace and line endings
  { id: "trailing-space-in-file", cat: "whitespace", file: "a = 1  \nb = 2\n", op: edit("a = 1\nb = 2", "a = 1\nb = 3"), want: "a = 1\nb = 3\n" },
  { id: "inner-space-runs", cat: "whitespace", file: "x  =  compute( a,  b )\n", op: edit("x = compute( a, b )", "x = compute(a, b, c)"), want: "x = compute(a, b, c)\n" },
  { id: "crlf-file-lf-find", cat: "whitespace", file: "one\r\ntwo\r\nthree\r\n", op: edit("one\ntwo", "one\n2"), want: "one\r\n2\r\nthree\r\n" },
  { id: "lf-file-crlf-edit", cat: "whitespace", file: "a\nb\nc\n", op: edit("a\r\nb", "a\r\nB"), want: "a\nB\nc\n" },
  { id: "dollar-in-replacement", cat: "exact", file: JS, op: edit("return fetch(url);", "return fetch(url.replace(/x/, '$&$1'));"), want: JS.replace("return fetch(url);", () => "return fetch(url.replace(/x/, '$&$1'));") },
  { id: "bom-file-flexible-first-line", cat: "whitespace", file: "\ufeffimport x\nfoo()\n", op: edit("import  x\nfoo()", "import y\nfoo()"), want: "\ufeffimport y\nfoo()\n" },
  { id: "tab-replacement-in-space-file", cat: "indent", file: "class A:\n    def f(self):\n        return 1\n", op: edit("def f(self):\n    return 1", "def f(self):\n\treturn 2"), want: "class A:\n    def f(self):\n        return 2\n" },
  { id: "tab-find-and-replacement-in-space-file", cat: "indent", file: PY, op: edit("\tfor it in items:\n\t\ts += it.price", "\tfor it in items:\n\t\ts += it.price * 2"), want: PY.replace("it.price\n", "it.price * 2\n") },
  { id: "flexible-find-trailing-newline", cat: "whitespace", file: PY, op: edit("s += it.price\n", "s += it.price * 2\n"), want: PY.replace("it.price\n", "it.price * 2\n") },
  { id: "flexible-adds-blank-line", cat: "whitespace", file: PY, op: edit("s += it.price\n", "s += it.price\n\n"), want: PY.replace("it.price\n", "it.price\n\n") },
  { id: "find-extra-blank-lines", cat: "whitespace", file: PY, op: edit("\n    return s\n\n", "\n    return round(s, 2)\n"), want: PY.replace("    return s\n", "    return round(s, 2)\n") },

  // ---- text the model copied with decoration
  { id: "grep-line-numbers", cat: "copied", file: JS, op: edit("2:  const url = cfg.url;", "2:  const url = cfg.href;"), want: JS.replace("cfg.url;", "cfg.href;") },
  { id: "grep-numbers-multiline", cat: "copied", file: JS, op: edit("3:  if (!url) {\n4:    throw new Error('no url');", "3:  if (!url) {\n4:    return null;"), want: JS.replace("throw new Error('no url');", "return null;") },
  { id: "smart-quotes-in-replacement", cat: "copied", file: JS, op: edit("Error(\u2018no url\u2019)", "Error(\u2018bad url\u2019)"), want: JS.replace("'no url'", "'bad url'") },
  { id: "smart-quotes", cat: "copied", file: JS, op: edit("throw new Error(‘no url’);", "throw new Error('missing url');"), want: JS.replace("'no url'", "'missing url'") },

  // ---- must refuse, never guess
  { id: "ambiguous-exact", cat: "refuse", file: TWIN, op: edit("return 1;", "return 2;"), want: null },
  { id: "ambiguous-flexible", cat: "refuse", file: TWIN, op: edit("return   1;", "return 2;"), want: null },
  { id: "not-present", cat: "refuse", file: JS, op: edit("const port = cfg.port;", "const port = 80;"), want: null },
  { id: "elided-middle", cat: "refuse", file: JS, op: edit("function load(cfg) {\n  ...\n}", "function load(cfg) {\n  return null;\n}"), want: null },
  { id: "multi-one-bad-is-atomic", cat: "refuse", file: JS, op: multi([{ find: "cfg.url;", replace: "cfg.href;" }, { find: "nope", replace: "x" }]), want: null },
  { id: "numbers-not-consecutive", cat: "refuse", file: JS, op: edit("2:  const url = cfg.url;\n9:  if (!url) {", "2:  const url = 1;\n9:  if (!url) {"), want: null },
  { id: "smart-quotes-file-has-them", cat: "refuse", file: "say \u201chi\u201d\nsay 'yo'\n", op: edit("say \u2018yo\u2019 now", "x"), want: null },
  { id: "decorated-but-ambiguous", cat: "refuse", file: TWIN, op: edit("2:  return 1;", "2:  return 2;"), want: null },
  { id: "empty-find", cat: "refuse", file: JS, op: edit("", "x"), want: null },

  // ---- patches
  { id: "patch-drifted-lines", cat: "patch", file: "a\nb\nc\nd\ne\n", op: patch("--- a/f\n+++ b/f\n@@ -40,3 +40,3 @@\n b\n-c\n+C\n d\n"), want: "a\nb\nC\nd\ne\n" },
  { id: "patch-stripped-blank-context", cat: "patch", file: "a\n\nb\n", op: patch("--- a/f\n+++ b/f\n@@ -1,3 +1,3 @@\n a\n\n-b\n+B\n"), want: "a\n\nB\n" },
  { id: "patch-wrong-indent", cat: "patch", file: PY, op: patch("--- a/f\n+++ b/f\n@@ -3,2 +3,2 @@\n for it in items:\n-    s += it.price\n+    s += it.price * it.qty\n"), want: PY.replace("it.price\n", "it.price * it.qty\n") },
  { id: "patch-tabs-into-space-file", cat: "patch", file: "class A:\n    def f(self):\n        return 1\n", op: patch("--- a/f\n+++ b/f\n@@ -2,2 +2,2 @@\n \tdef f(self):\n-\t\treturn 1\n+\t\treturn 2\n"), want: "class A:\n    def f(self):\n        return 2\n" },
  { id: "patch-spaces-into-tab-file", cat: "patch", file: GO, op: patch("--- a/f\n+++ b/f\n@@ -3,2 +3,3 @@\n     if x > 0 {\n         fmt.Println(x)\n+        fmt.Println(x + 1)\n"), want: GO.replace("\t\tfmt.Println(x)\n", "\t\tfmt.Println(x)\n\t\tfmt.Println(x + 1)\n") },
  { id: "patch-envelope", cat: "patch", file: JS, op: patch("*** Begin Patch\n*** Update File: f.js\n@@\n   const url = cfg.url;\n-  if (!url) {\n+  if (!url || !url.length) {\n*** End Patch\n"), want: JS.replace("if (!url) {", "if (!url || !url.length) {") },
  { id: "patch-anchor-twin", cat: "patch", file: TWIN, op: patch("*** Begin Patch\n*** Update File: f.js\n@@ function b() {\n-  return 1;\n+  return 2;\n*** End Patch\n"), want: "function a() {\n  return 1;\n}\nfunction b() {\n  return 2;\n}\n" },
  { id: "patch-twin-no-anchor", cat: "refuse", file: TWIN, op: patch("--- a/f\n+++ b/f\n@@\n-  return 1;\n+  return 2;\n"), want: null },
  { id: "patch-context-gone", cat: "refuse", file: JS, op: patch("--- a/f\n+++ b/f\n@@\n const port = 1;\n-x\n+y\n"), want: null },
];
// a case whose `want` is null with a note is an expected refusal only when it has no note
for (const c of CASES) if (c.want === null && c.note) c.want = c.file.replace("\tx := 1\n", "\tx := 1\n    y := 2\n");

function apply(c) {
  try {
    if (c.op.tool === "edit") { const r = E.applyEditsFlexible(c.file, c.op.edits); return r.ok ? { ok: true, content: r.content } : { ok: false, error: r.error }; }
    const files = E.parsePatch(c.op.patch);
    if (files.length !== 1) return { ok: false, error: "patch parsed into " + files.length + " files" };
    const r = E.applyHunks(c.file, files[0].hunks);
    return r.ok ? { ok: true, content: r.content } : { ok: false, error: r.error };
  } catch (e) { return { ok: false, error: "threw: " + e.message }; }
}

function run(cases) {
  const rows = (cases || CASES).map((c) => {
    const r = apply(c);
    const verdict = c.want === null ? (r.ok ? "corrupted" : "correct") : !r.ok ? "refused" : r.content === c.want ? "correct" : "corrupted";
    return { id: c.id, cat: c.cat, verdict, error: r.error || "", got: r.ok ? r.content : null, want: c.want };
  });
  const by = {};
  for (const r of rows) { const b = by[r.cat] || (by[r.cat] = { n: 0, correct: 0, refused: 0, corrupted: 0 }); b.n++; b[r.verdict]++; }
  const tot = rows.reduce((t, r) => (t[r.verdict]++, t), { n: rows.length, correct: 0, refused: 0, corrupted: 0 });
  return { rows, by, tot, rate: tot.correct / tot.n };
}

function main(argv) {
  const res = run();
  const pct = (a, b) => (100 * a / b).toFixed(1) + "%";
  console.log("edit engine fixtures: " + res.tot.correct + "/" + res.tot.n + " correct (" + pct(res.tot.correct, res.tot.n) + "), " + res.tot.refused + " refused, " + res.tot.corrupted + " corrupted\n");
  console.log("category     cases  correct  refused  corrupted");
  for (const [k, b] of Object.entries(res.by)) console.log(k.padEnd(12) + String(b.n).padStart(6) + String(b.correct).padStart(9) + String(b.refused).padStart(9) + String(b.corrupted).padStart(11));
  if (argv.includes("--fail")) for (const r of res.rows.filter((x) => x.verdict !== "correct")) console.log("\n" + r.verdict.toUpperCase() + " " + r.id + (r.error ? "\n  " + r.error : "") + (r.got != null ? "\n  got:  " + JSON.stringify(r.got) + "\n  want: " + JSON.stringify(r.want) : ""));
  if (res.tot.corrupted) process.exitCode = 1;
}

if (require.main === module) main(process.argv.slice(2));
module.exports = { CASES, run, apply };

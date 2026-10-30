"use strict";
// Exec/edit-tool audit (shell-run, bgjobs, edit-undo, notebook-edit, json-query, line-range,
// read-symbol, syntax-gate, retry, wait-for): each case is a bug that was reproduced first,
// plus the guarantees those fixes sit next to.
const fs = require("fs");
const os = require("os");
const path = require("path");
const { coderShell } = require("../lib/nexus/shell-run");
const { createBgJobs } = require("../lib/nexus/bgjobs");
const { createEditUndo } = require("../lib/nexus/edit-undo");
const NB = require("../lib/nexus/notebook-edit");
const JQ = require("../lib/nexus/json-query");
const { lineRange } = require("../lib/nexus/line-range");
const RS = require("../lib/nexus/read-symbol");
const SG = require("../lib/nexus/syntax-gate");
const { retryAfterMs, withRetry } = require("../lib/nexus/retry");
const { waitForTool, parseSecs } = require("../lib/nexus/wait-for");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const group = (t) => console.log("\n\x1b[1m" + t + "\x1b[0m");
const posix = process.platform !== "win32";
const hasPy = (() => { try { return require("child_process").spawnSync("python3", ["-c", "1"]).status === 0; } catch (_) { return false; } })();

const T = fs.mkdtempSync(path.join(os.tmpdir(), "nx-exec-audit-"));
const rp = (p) => path.resolve(T, p);

(async () => {
  group("line-range");
  ok("a huge numeric offset stays huge (parseInt(1e21) read it as line 1)", lineRange({ offset: 1e21 }).off === 1e21);
  ok("a tiny float offset is line 1, not 5 (parseInt(5e-7))", lineRange({ offset: 5e-7 }).off === 1);
  ok("a float offset truncates", lineRange({ offset: 12.9 }).off === 12);
  ok("0 and negative offsets clamp to line 1", lineRange({ offset: 0 }).off === 1 && lineRange({ offset: -5 }).off === 1);
  ok("string offsets still parse", lineRange({ start: "40", end: "49" }).off === 40 && lineRange({ start: "40", end: "49" }).lim === 10);
  ok("a null offset falls through to the next spelling", lineRange({ offset: null, start: 7 }).off === 7);

  group("bgjobs");
  const B = createBgJobs();
  ok("Object.prototype names are not jobs", B.get("toString") == null && B.get("constructor") == null && B.get("__proto__") == null);
  ok("stop() of a prototype name reports no such job", B.stop("constructor") === false);
  ok("write() to a prototype name is an error", !!B.write("hasOwnProperty", "x").error);
  const id = B.start("echo", null, 0);
  ok("real ids still resolve in every spelling", B.get(id) && B.get("1") && B.get("#1") && B.get("job 1"));

  group("wait-for");
  let t0 = Date.now();
  let w = await waitForTool({ file: "never", timeout_s: 0 }, T, rp);
  ok("timeout_s:0 waits ~1s, not the 30s default", !w.ready && Date.now() - t0 < 5000);
  t0 = Date.now();
  w = await waitForTool({ file: "never", timeout: "1s" }, T, rp);
  ok("deadline is honoured within 600ms", !w.ready && Date.now() - t0 >= 1000 && Date.now() - t0 < 1600);
  ok("run_command timeout_s units: \"30s\" is 30, \"2m\" 120, junk is null (was NaN -> silent 120s default)", parseSecs("30s") === 30 && parseSecs("2m") === 120 && parseSecs(45) === 45 && parseSecs("abc") === null && parseSecs(undefined) === null);
  ok("prototype names are not jobs for wait_for", !!(await waitForTool({ job: "toString" }, T, rp, { jobs: B })).error);

  group("syntax-gate");
  ok("JSON with a BOM is valid", SG.check(path.join(T, "a.json"), "﻿{\"a\":1}").ok === true);
  const cjs = "const tpl = `\nexport default 1\n`;\nrequire('fs').chmodSync('f', 0755);\n";
  ok("a CommonJS .js mentioning export in a template is not flagged (octal is fine in sloppy mode)", SG.check(path.join(T, "c.js"), cjs).ok === true);
  ok("a real ESM .js still passes", SG.check(path.join(T, "e.js"), "import fs from 'fs';\nexport const x = await 1;\n").ok === true);
  ok("a real syntax error in .js is still reported", SG.check(path.join(T, "bad.js"), "const = 1;\n").ok === false);
  ok("an ESM .js with an octal is still an error", SG.check(path.join(T, "bad2.js"), "import fs from 'fs';\nfs.chmodSync('f', 0755);\n").ok === false);
  if (hasPy) {
    ok("a .py with a UTF-8 BOM is valid", SG.check(path.join(T, "a.py"), "﻿x = 1\n").ok === true);
    ok("a .py with a BOM still reports a real error", SG.check(path.join(T, "b.py"), "﻿def f(:\n").ok === false);
    const fp = path.join(T, "edit.py"); fs.writeFileSync(fp, "﻿x = 1\n");
    const cap = SG.capture(fp); fs.writeFileSync(fp, "﻿x = (\n");
    ok("an error introduced into a BOM .py is reported (was 'already broken before')", /syntax error/.test(SG.afterEdit(cap) || ""));
  }

  group("notebook-edit");
  const nbp = path.join(T, "n.ipynb");
  fs.writeFileSync(nbp, JSON.stringify({ nbformat: 4, nbformat_minor: 5, metadata: {}, cells: [null, { cell_type: "code", source: ["a\n", "b"], metadata: {}, outputs: [], execution_count: 1 }] }));
  let threw = false, r;
  try { r = NB.notebookEditTool({ path: "n.ipynb", op: "read" }, T, rp); } catch (_) { threw = true; }
  ok("a null cell is an error result, not a throw", !threw && r && !!r.error);
  ok("source string keeps its trailing newline", JSON.stringify(NB.toSourceLines("a\nb\n")) === JSON.stringify(["a\n", "b\n"]));
  ok("a plain list of lines gets newlines", JSON.stringify(NB.toSourceLines(["import os", "import sys"])) === JSON.stringify(["import os\n", "import sys"]));
  const nb = { nbformat: 4, nbformat_minor: 4, cells: [{ cell_type: "code", source: "x", metadata: {}, outputs: [], execution_count: 1 }] };
  ok("edit index out of range is refused", !!NB.applyNotebookOp(JSON.parse(JSON.stringify(nb)), { op: "edit", index: 1, source: "y" }).error);
  ok("-1 inserts after the last cell", NB.applyNotebookOp(JSON.parse(JSON.stringify(nb)), { op: "insert", index: -1, source: "y" }).result.index === 1);

  group("json-query");
  fs.writeFileSync(path.join(T, "q.json"), "﻿{\"__proto__\":{\"x\":1},\"big\":12345678901234567890,\"a\":{\"b.c\":[1,2]}}");
  ok("an own __proto__ key is readable", JQ.jsonQueryTool({ path: "q.json", query: "__proto__.x" }, T, rp).value === "1");
  ok("inherited names are not found", !!JQ.jsonQueryTool({ path: "q.json", query: "constructor" }, T, rp).error && !!JQ.jsonQueryTool({ path: "q.json", query: "toString" }, T, rp).error);
  ok("big integers keep their digits", JQ.jsonQueryTool({ path: "q.json", query: "big" }, T, rp).value === "12345678901234567890");
  ok("quoted dotted key + negative index", JQ.jsonQueryTool({ path: "q.json", query: "a[\"b.c\"][-1]" }, T, rp).value === "2");
  ok("an unterminated bracket is a parse error", JQ.parsePath("a.b[") === null);

  group("read-symbol");
  const py = ["class A:", "    def f(self, sep=\")\"):", "        return sep", "", "    def g(self, x=\"(\"):", "        # a ( comment", "        return x", "", "def h(a,  # (", "      b):", "    return a", "", "def last():", "    pass"];
  ok("a ( inside a default string doesn't swallow the rest of the file", RS.indentEnd(py, 4) === 6);
  ok("a ( inside a header comment doesn't either", RS.indentEnd(py, 8) === 10);
  ok("a ) inside a default string still ends at the body", RS.indentEnd(py, 1) === 2);
  const js = ["function one(a = \"}\", b = /}/g) {", "  const t = `x ${a + `${\"}\"}`} }`;", "  return t;", "}", "function two() {}"];
  ok("braces in strings, regexes and nested templates don't end a JS block", RS.braceEnd(js, 0, true) === 3);

  group("retry");
  ok("Retry-After seconds", retryAfterMs("120") === 120000 && retryAfterMs(" 3 ") === 3000);
  ok("Retry-After HTTP-date", (() => { const v = retryAfterMs(new Date(Date.now() + 5000).toUTCString()); return v > 3000 && v <= 5000; })());
  ok("Retry-After garbage is ignored", retryAfterMs("soon") === null);
  const waits = []; let n = 0;
  const e429 = () => Object.assign(new Error("rate"), { status: 429, retryAfter: "99999999999" });
  await withRetry(() => { if (n++ < 2) throw e429(); return 1; }, null, { sleep: async (ms) => { waits.push(ms); } });
  ok("a huge Retry-After is capped at 60s", waits.length === 2 && waits.every((ms) => ms === 60000));
  waits.length = 0; n = 0;
  await withRetry(() => { if (n++ < 40) throw Object.assign(new Error("x"), { status: 503 }); return 1; }, null, { retries: 40, sleep: async (ms) => { waits.push(ms); } });
  ok("exponential backoff never overflows past the cap", waits.length === 40 && waits.every((ms) => Number.isFinite(ms) && ms <= 60000));

  group("shell-run");
  let s = await coderShell("printf 'h\\303'; sleep 0.2; printf '\\251llo'", T);
  ok("a UTF-8 char split across chunks survives", s.output === "héllo");
  s = await coderShell("head -c 1000000 /dev/zero | tr '\\0' a; echo; echo THE-END", T);
  ok("big output keeps head and tail, bounded", s.output.length < 13000 && /THE-END/.test(s.output) && /bytes trimmed/.test(s.output));
  if (posix) {
    t0 = Date.now();
    s = await coderShell("sleep 30 & echo started", T);
    ok("a backgrounded child holding the pipe doesn't hang the run", Date.now() - t0 < 5000 && s.code === 0);
    t0 = Date.now();
    s = await coderShell("(sleep 30; echo x); echo y", T, { timeoutMs: 1000 });
    ok("timeout kills the group and reports 124", s.code === 124 && s.timedOut && Date.now() - t0 < 4000);
  }

  group("edit-undo");
  const U = createEditUndo(), f = path.join(T, "u", "x.bin");
  let sn = U.snapshot([f]); fs.mkdirSync(path.dirname(f)); fs.writeFileSync(f, Buffer.from([0, 255, 0xc3])); U.commit(sn);
  sn = U.snapshot([f]); fs.writeFileSync(f, "text"); U.commit(sn);
  ok("undo restores binary bytes exactly", U.undo(f).ok && fs.readFileSync(f).equals(Buffer.from([0, 255, 0xc3])));
  ok("a second undo deletes the file the first edit created", U.undo(f).ok && !fs.existsSync(f));
  ok("a third undo has nothing left", !!U.undo(f).error);

  fs.rmSync(T, { recursive: true, force: true });
  console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m");
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });

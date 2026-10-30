"use strict";
// Regressions from the edit-tool audit (lib/nexus/edit.js, replace-files.js): one test per fix.
const fs = require("fs"), os = require("os"), path = require("path");
const { applyEditsFlexible, applyPatch, keepEol } = require("../lib/nexus/edit");
const { replaceInFilesTool } = require("../lib/nexus/replace-files");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const eq = (name, a, b) => ok(name + "  (" + JSON.stringify(a) + " === " + JSON.stringify(b) + ")", JSON.stringify(a) === JSON.stringify(b));
const flex = (c, find, replace, replaceAll) => applyEditsFlexible(c, [{ find, replace, replaceAll }]).content;

const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nx-edit-audit-"));
const rif = (a) => replaceInFilesTool(a, dir, (p) => path.resolve(dir, p), {});
const put = (f, c) => fs.writeFileSync(path.join(dir, f), c), get = (f) => fs.readFileSync(path.join(dir, f), "utf8");
try {
  // 1. flexible deletion of whole lines left a blank line behind (exact "foo\n" -> "" leaves none)
  eq("flexible delete takes the line break", flex("a\n  foo  \nb\n", "foo\n", ""), "a\nb\n");
  eq("flexible replace_all delete takes the line breaks", flex("x\n  foo\ny\n  foo\nz\n", "foo \n", "", true), "x\ny\nz\n");
  // 2. a flexible edit on a mostly-CRLF file rewrote an untouched lone-LF line to CRLF
  eq("flexible edit keeps other lines' endings", flex("a\r\nb\r\nc\r\nkeep\nd\r\n", "  b", "X"), "a\r\nX\r\nc\r\nkeep\nd\r\n");
  // 3. apply_patch turned a whole LF file into CRLF because one line was CRLF
  eq("patch on an LF file with one CRLF line stays LF", applyPatch("a\nb\nc\r\nd\n", "@@ -1,2 +1,2 @@\n a\n-b\n+B\n").content, "a\nB\nc\r\nd\n");
  eq("keepEol on a pure CRLF file still restores CRLF", keepEol("a\r\nb\r\n", "a\nX\nY\n"), "a\r\nX\r\nY\r\n");
  // 4. replace_in_files regex "^" / "$" also hit the phantom line after the final newline
  put("r.js", "x\ny\n");
  rif({ find: "^", replace: "// ", regex: true, glob: "r.js" });
  eq("regex ^ adds no stray line at EOF", get("r.js"), "// x\n// y\n");
  // 5. a file over the size cap that holds a match was skipped silently ("no matches")
  put("big.js", "foo\n".repeat(300000));
  const big = rif({ find: "foo", replace: "bar", glob: "big.js" });
  ok("too-big file with a match is reported as skipped", (big.skipped || []).some((s) => s.file === "big.js"));
  // 6. replace_in_files multi-line literal on a mixed file: untouched line outside the match keeps LF
  put("m.js", "keep\na\r\nb\r\nz\r\n");
  rif({ find: "a\nb", replace: "A\nB", glob: "m.js" });
  eq("replace_in_files keeps untouched line endings", get("m.js"), "keep\nA\r\nB\r\nz\r\n");
} finally { fs.rmSync(dir, { recursive: true, force: true }); }

console.log("\n" + pass + " passed, " + fail + " failed");
process.exit(fail ? 1 : 0);

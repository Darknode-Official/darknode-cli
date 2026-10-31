"use strict";
// /snippet suite (lib/cli/snippets.js + its wiring in darknode.js).
const fs = require("fs"), path = require("path");
const { getSnippet, saveBody, expandSnippet } = require("../lib/cli/snippets");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };

const store = JSON.parse('{"fix":"fix $1 in $2","all":"do: $ARGUMENTS"}');
ok("a saved snippet is found", getSnippet(store, "fix") === "fix $1 in $2");
ok("Object.prototype names are not snippets", ["toString", "constructor", "hasOwnProperty", "__proto__"].every((n) => getSnippet(store, n) === null));
ok("a missing name or store is null", getSnippet(store, "nope") === null && getSnippet(null, "fix") === null && getSnippet(store, "") === null);
ok("a non-string value in the file is ignored", getSnippet({ x: 5 }, "x") === null);

ok("save keeps the body exactly, newlines included", saveBody("save rev Review this:\n- a\n- b") === "Review this:\n- a\n- b");
ok("save keeps repeated spaces", saveBody("save t a  b") === "a  b");
ok("save with no body is empty", saveBody("save t") === "" && saveBody("save") === "");

ok("$1/$2 take words, $ARGUMENTS the whole rest", expandSnippet("fix $1 in $2", " bug  app.js ") === "fix bug in app.js" && expandSnippet("do: $ARGUMENTS", "a  b") === "do: a  b");
ok("a $1 inside the arguments is not expanded again", expandSnippet("say $ARGUMENTS", "cost is $1") === "say cost is $1");
ok("missing positional args become empty", expandSnippet("a $3 b", "x") === "a  b");

const src = fs.readFileSync(path.join(__dirname, "..", "darknode.js"), "utf8");
ok("darknode.js runs snippets through getSnippet/expandSnippet", /getSnippet\(snippets, sub\) !== null\) \{ submit\(expandSnippet\(/.test(src));
ok("save uses saveBody", /body = saveBody\(argstr\)/.test(src));
ok("reserved names are refused", /\(save\|del\|rm\|__proto__\)/.test(src));
ok("no raw snippets[sub].replace is left", !/snippets\[sub\]\.replace/.test(src));

console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (snippets)");
process.exit(fail ? 1 : 0);

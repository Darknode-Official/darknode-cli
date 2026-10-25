"use strict";
// Answer renderer suite (lib/cli/md-render.js): code fences + highlighting,
// tables, quotes, rules, links, streaming partials, and the width contract.
const { renderMd, highlight, langOf, cells } = require("../lib/cli/md-render");
const { strWidth, stripAnsi } = require("../lib/cli/tui-format");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const eq = (name, a, b) => ok(name + "  (" + JSON.stringify(a) + " === " + JSON.stringify(b) + ")", JSON.stringify(a) === JSON.stringify(b));
const group = (t) => console.log("\n\x1b[1m" + t + "\x1b[0m");

// Tag painters: make colour decisions visible as plain text.
const tag = (t) => (s) => "<" + t + ">" + s + "</" + t + ">";
const T = { gray: tag("g"), mag: tag("k"), green: tag("s"), yellow: tag("n"), cyan: tag("f"), red: tag("r"), bold: tag("b"), italic: tag("i"), underline: tag("u") };
const plain = (text, w) => renderMd(text, w || 80);

group("code fences");
{
  const out = plain("```js\nconst a = 1;\n```");
  eq("label, gutter, closing", out, ["╭─ js", "│ const a = 1;", "╰─"]);
  eq("bare fence gets an unlabeled frame", plain("```\nx\n```"), ["╭─", "│ x", "╰─"]);
  eq("unclosed fence (still streaming) keeps the gutter, no closer yet", plain("```py\nprint(1)"), ["╭─ py", "│ print(1)"]);
  eq("tilde fences work", plain("~~~sh\nls\n~~~"), ["╭─ sh", "│ ls", "╰─"]);
  eq("a ``` with a tag inside a fence is content, not a closer", plain("````md\n```js\n````"), ["╭─ md", "│ ```js", "╰─"]);
  ok("no raw ``` markers are left in the output", !plain("text\n```js\nx\n```\nmore").some((l) => l.includes("```")));
}

group("syntax highlighting");
{
  const h = (line, lang) => highlight(line, lang, T, {});
  eq("js keyword / string / number / comment", h('const a = "x" + 42; // hi', "js"), '<k>const</k> a = <s>"x"</s> + <n>42</n>; <g>// hi</g>');
  eq("function call names", h("foo(bar)", "js"), "<f>foo</f>(bar)");
  eq("escaped quote stays inside the string", h('"a\\"b" c', "js"), '<s>"a\\"b"</s> c');
  eq("py comment + keyword", h("def f(): # x", "py"), "<k>def</k> <f>f</f>(): <g># x</g>");
  eq("sh: # inside a word is not a comment", h("echo a#b", "sh"), "<k>echo</k> a#b");
  eq("sh: variables", h("echo $HOME ${X}", "sh"), "<k>echo</k> <f>$HOME</f> <f>${X}</f>");
  eq("sql keywords are case-insensitive", h("SELECT id FROM t", "sql"), "<k>SELECT</k> id <k>FROM</k> t");
  eq("json keys vs values", h('{"a": "b", "n": true}', "json"), '{<f>"a"</f>: <s>"b"</s>, <f>"n"</f>: <k>true</k>}');
  eq("yaml keys", h("name: web", "yaml"), "<f>name</f>: web");
  eq("identifiers with digits are not numbers", h("x1 = 2", "py"), "x1 = <n>2</n>");
  const st = {};
  eq("block comment opens", highlight("a /* b", "js", T, st), "a <g>/* b</g>");
  eq("block comment continues on the next line", highlight("c */ d", "js", T, st), "<g>c */</g> d");
  const st2 = {};
  highlight('x = """doc', "py", T, st2);
  eq("python triple-quote spans lines", highlight('end""" + y', "py", T, st2), '<s>end"""</s> + y');
  eq("unknown language: generic strings/numbers/comments", highlight('foo "s" 3 # c', null, T, {}), 'foo <s>"s"</s> <n>3</n> <g># c</g>');
  ok("escape sequences in code are neutralised", !highlight("a\x1b]0;pwn\x07b", "js", T, {}).includes("\x1b]"));
  eq("aliases resolve", ["typescript", "bash", "yml", "c++", "Dockerfile", "weird"].map(langOf), ["js", "sh", "yaml", "c", "docker", null]);
}

group("diff fences");
{
  const G = Object.assign({}, T, { green: tag("add"), red: tag("del") });
  const d = renderMd("```diff\n+add\n-del\n```", 80, G);
  ok("added line painted as an addition", d[1].includes("<add>+add</add>"));
  ok("removed line painted as a removal", d[2].includes("<del>-del</del>"));
}

group("tables");
{
  const t = plain("| Name | Port |\n|---|--:|\n| ssh | 22 |\n| http | 8080 |");
  eq("boxed, aligned, right-aligned numbers", t, [
    "┌──────┬──────┐",
    "│ Name │ Port │",
    "├──────┼──────┤",
    "│ ssh  │   22 │",
    "│ http │ 8080 │",
    "└──────┴──────┘",
  ]);
  eq("centre alignment", plain("| a |\n|:-:|\n| xyz |")[1], "│  a  │");
  eq("escaped pipe and pipes inside code stay in the cell", cells("| a \\| b | `x|y` |"), ["a | b", "`x|y`"]);
  const narrow = plain("| Header | Value |\n|---|---|\n| one | a much longer value than fits |", 24);
  ok("too wide: falls back to stacked records", narrow[0] === "Header: one" && narrow.some((l) => l.startsWith("Value: ")));
  ok("header-only table (separator not streamed yet) stays text", plain("| a | b |")[0] === "| a | b |");
  eq("a table ends at the first non-row line", plain("| a |\n|---|\n| 1 |\nafter").slice(-1), ["after"]);
  const wide = plain("| 日本 | b |\n|---|---|\n| x | y |");
  ok("wide (CJK) cells keep the borders aligned", new Set(wide.map((l) => strWidth(l))).size === 1);
}

group("prose");
{
  eq("block quote", plain("> careful"), ["▎ careful"]);
  eq("inline code in a quote drops its backticks", plain("> bind to `127.0.0.1`"), ["▎ bind to 127.0.0.1"]);
  eq("horizontal rule", plain("---", 10), ["──────────"]);
  eq("link keeps its url", renderMd("see [docs](https://x.io)", 80, T), ["see <u>docs</u><g> (https://x.io)</g>"]);
  eq("bare-url link is not doubled", renderMd("[https://x.io](https://x.io)", 80, T), ["<u>https://x.io</u>"]);
  eq("italic", renderMd("an *emphasis* here", 80, T), ["an <i>emphasis</i> here"]);
  eq("bold markers are not italicised", renderMd("a **b** c", 80, T), ["a **b** c"]);
  eq("inline code is left alone", renderMd("run `a *b* [c](d.io)`", 80, T), ["run `a *b* [c](d.io)`"]);
  eq("snake_case is not italicised", renderMd("use my_var_name", 80, T), ["use my_var_name"]);
  eq("inline painter runs on prose rows", renderMd("hi", 80, { inline: (l) => "[" + l + "]" }), ["[hi]"]);
  eq("blank lines kept", plain("a\n\nb"), ["a", "", "b"]);
}

group("width contract");
{
  const doc = "# Heading that is quite long indeed\n" + "word ".repeat(60) + "\n```js\n" + "const x = \"" + "y".repeat(120) + "\";\n```\n| a | b |\n|---|---|\n| " + "z".repeat(90) + " | q |\n> " + "quote ".repeat(30);
  for (const w of [20, 40, 79]) {
    const lines = renderMd(doc, w, { gray: (s) => "\x1b[90m" + s + "\x1b[0m", green: (s) => "\x1b[32m" + s + "\x1b[0m" });
    ok("no row exceeds width " + w, lines.every((l) => strWidth(l) <= w));
  }
  ok("stripAnsi of a coloured row equals the plain row", stripAnsi(renderMd("```js\nconst a=1\n```", 40, { mag: (s) => "\x1b[35m" + s + "\x1b[0m" })[1]) === plain("```js\nconst a=1\n```", 40)[1]);
}

console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (answer renderer)");
process.exit(fail ? 1 : 0);

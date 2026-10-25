"use strict";
// Transcript link suite (lib/cli/links.js): detection, wrapped URLs, display
// columns, and the shell-free opener.
const { findLinks, openLink, trimUrl } = require("../lib/cli/links");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const eq = (name, a, b) => ok(name + "  (" + JSON.stringify(a) + " === " + JSON.stringify(b) + ")", JSON.stringify(a) === JSON.stringify(b));
const group = (t) => console.log("\n\x1b[1m" + t + "\x1b[0m");
const urls = (rows, w) => findLinks(rows, w || 200).map((z) => z.url);

group("detection");
{
  eq("CVE -> NVD", urls(["patch CVE-2024-3094 now"]), ["https://nvd.nist.gov/vuln/detail/CVE-2024-3094"]);
  eq("GHSA -> GitHub advisory", urls(["GHSA-jfh8-c2jp-5v3q"]), ["https://github.com/advisories/GHSA-jfh8-c2jp-5v3q"]);
  eq("CWE -> MITRE", urls(["CWE-79"]), ["https://cwe.mitre.org/data/definitions/79.html"]);
  eq("http(s) URL", urls(["go to https://example.com/x?a=1&b=2 today"]), ["https://example.com/x?a=1&b=2"]);
  eq("trailing punctuation is not part of the URL", urls(["see https://example.com/a."]), ["https://example.com/a"]);
  eq("wrapping parens are not part of the URL", urls(["(https://example.com/a)"]), ["https://example.com/a"]);
  eq("parens inside a URL are kept", trimUrl("https://en.wikipedia.org/wiki/Rust_(language)"), "https://en.wikipedia.org/wiki/Rust_(language)");
  eq("a CVE inside a URL is not linked twice", urls(["https://nvd.nist.gov/vuln/detail/CVE-2024-3094"]), ["https://nvd.nist.gov/vuln/detail/CVE-2024-3094"]);
  eq("non-http schemes are ignored", urls(["javascript:alert(1) file:///etc/passwd ftp://x.io"]), []);
  eq("lowercase look-alikes are not ids", urls(["cve-2024-3094 xCVE-2024-3094"]), []);
}

group("columns");
{
  const z = findLinks(["ab CVE-2021-44228"], 80)[0];
  eq("start / end columns", [z.c0, z.c1, z.row], [3, 16, 0]);
  const w = findLinks(["日本 CVE-2021-44228"], 80)[0];
  eq("wide glyphs count as two columns", [w.c0, w.c1], [5, 18]);
}

group("wrapped URLs");
{
  const W = 30;
  const rows = ["  ● go to https://example.com/ve", "    ry/long/path for more", "next CVE-2021-44228"];
  const z = findLinks(rows, W);
  eq("both halves open the whole URL", z.filter((x) => x.kind === "url").map((x) => [x.row, x.url]), [[0, "https://example.com/very/long/path"], [1, "https://example.com/very/long/path"]]);
  eq("continuation zone covers only the URL part", [z[1].c0, z[1].c1], [4, 15]);
  ok("links later in the document still found", z.some((x) => x.kind === "cve" && x.row === 2));
  eq("a short row ending in a URL is not joined to the next row", urls(["see https://example.com", "next"], 80), ["https://example.com"]);
  eq("code gutter is skipped on the continuation row", urls(["│ curl https://example.com/aaaaa", "│ bbbb/c"], 32), ["https://example.com/aaaaabbbb/c", "https://example.com/aaaaabbbb/c"]);
}

group("openLink");
{
  const calls = []; const spawn = (cmd, args, o) => { calls.push([cmd, args, o.detached]); return { on() {}, unref() {} }; };
  ok("linux uses xdg-open", openLink("https://x.io/a", { platform: "linux", spawn }) && calls[0][0] === "xdg-open");
  openLink("https://x.io/?a=1&b=2|c", { platform: "win32", spawn });
  eq("windows avoids cmd.exe (& and | stay literal)", calls[1].slice(0, 2), ["rundll32", ["url.dll,FileProtocolHandler", "https://x.io/?a=1&b=2|c"]]);
  openLink("https://x.io", { platform: "darwin", spawn });
  eq("mac uses open", calls[2][0], "open");
  ok("javascript: refused", !openLink("javascript:alert(1)", { spawn }));
  ok("file: refused", !openLink("file:///etc/passwd", { spawn }));
  ok("control characters refused", !openLink("https://x.io/\x1b]0;x", { spawn }));
  ok("spawn failure is reported, not thrown", openLink("https://x.io", { platform: "linux", spawn: () => { throw new Error("ENOENT"); } }) === false);
  eq("nothing else was launched", calls.length, 3);
}

console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (transcript links)");
process.exit(fail ? 1 : 0);

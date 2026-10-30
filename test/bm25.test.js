"use strict";
// Chunk-level BM25 code search (lib/nexus/bm25.js): identifier splitting, chunk windows, data
// chunks left out, ranking that finds the right part of the right file, and safety of a stored
// (JSON round-tripped) index.
const { tokenize, chunkText, stringShare, buildIndex, search, VERSION } = require("../lib/nexus/bm25");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const eq = (name, a, b) => ok(name + "  (" + JSON.stringify(a) + " === " + JSON.stringify(b) + ")", JSON.stringify(a) === JSON.stringify(b));
const group = (t) => console.log("\n\x1b[1m" + t + "\x1b[0m");

group("tokens and chunks");
{
  const t = tokenize("retryUpload(HTTPServer, max_attempts) // where we retry");
  ok("camelCase splits into words and keeps the whole name", ["retryupload", "retry", "upload"].every((w) => t.includes(w)));
  ok("acronyms split (HTTPServer -> http, server)", t.includes("http") && t.includes("server"));
  ok("snake_case splits", t.includes("max_attempts") && t.includes("attempt"));
  ok("prose forms meet code forms (uploads/retried -> upload/retry)", ["upload", "retry"].every((w) => tokenize("uploads retried").includes(w)) && tokenize("uploading").includes("upload") && tokenize("retries").includes("retry"));
  ok("short words and -ss/-us/-is endings are not stemmed", ["class", "status", "analysis", "uses"].every((w) => tokenize(w).includes(w)));
  ok("stop words are dropped", !t.includes("where") && !t.includes("we"));
  const lines = Array.from({ length: 130 }, (_, i) => "line" + (i + 1)).join("\n") + "\n";
  const c = chunkText(lines);
  eq("130 lines -> windows 1-60, 51-110, 101-130", c.map((x) => [x.start, x.end]), [[1, 60], [51, 110], [101, 130]]);
  ok("windows overlap so a cut function is whole in one of them", c[1].start < c[0].end);
  eq("a short file is one chunk", chunkText("a\nb\n").map((x) => [x.start, x.end]), [[1, 2]]);
  eq("an empty file has no chunks", chunkText(""), []);
  ok("code is mostly not string literals", stringShare("function f(a) {\n  return a + 1;\n}") < 0.2);
  ok("a payload list is mostly string literals", stringShare('["<script>alert(1)</script>", "\' OR 1=1 --", "../../etc/passwd"],') > 0.7);
}

const FILES = [
  { path: "src/upload/retry.js", content: "// Retry failed uploads with exponential backoff.\nfunction retryUpload(file, attempts) {\n  for (let i = 0; i < attempts; i++) {\n    if (sendChunk(file)) return true;\n    sleep(backoffDelay(i));\n  }\n  return false;\n}\nfunction backoffDelay(n) { return 2 ** n * 100; }\n" },
  { path: "src/auth/session.js", content: "function createSessionToken(user) { return sign(user.id); }\nfunction sessionExpired(token, now) { return token.exp < now; }\n" },
  { path: "src/ui/theme.js", content: "export const colors = { primary: '#123', upload: '#456' };\nfunction applyTheme(el) { el.style.color = colors.primary; }\n" },
  // a big file where the relevant code is far down
  { path: "src/server.js", content: Array.from({ length: 200 }, (_, i) => "function handler" + i + "(req) { return req.body; }").join("\n") + "\nfunction rateLimitRequests(ip) { return bucket(ip).take(); }\n" },
  // a data file that mentions every word under the sun
  { path: "src/data/payloads.js", content: "module.exports = [" + Array.from({ length: 80 }, () => '"retry upload session token theme rate limit requests backoff"').join(",\n") + "];\n" },
  { path: "docs/uploads.md", content: "# Uploads\n\nFailed uploads are retried with backoff.\n" },
];
const IX = buildIndex(FILES);

group("ranking");
{
  ok("index records its version and chunk count", IX.version === VERSION && IX.N > 0);
  ok("data chunks are left out of the index", !IX.docs.some((d) => d.path === "src/data/payloads.js"));
  ok("markdown is kept even when it is mostly prose", IX.docs.some((d) => d.path === "docs/uploads.md"));
  const r = search(IX, "where do we retry failed uploads with backoff");
  eq("a prose question finds the code it is about", r[0] && r[0].path, "src/upload/retry.js");
  const r2 = search(IX, "rate limiting of incoming requests");
  ok("the right chunk of a long file, not its start", r2[0] && r2[0].path === "src/server.js" && r2[0].start > 100);
  eq("path words count (a question about sessions finds session.js)", search(IX, "session expiry")[0].path, "src/auth/session.js");
  eq("no match -> nothing", search(IX, "kubernetes helm chart"), []);
  eq("only stop words -> nothing", search(IX, "where is the"), []);
  ok("k limits the result count", search(IX, "function", { k: 2 }).length <= 2);
  const many = buildIndex([{ path: "big.js", content: Array.from({ length: 600 }, (_, i) => "function upload" + i + "() { retryUpload(); }").join("\n") }].concat(FILES));
  ok("at most 2 chunks from one file by default", search(many, "retry upload", { k: 10 }).filter((h) => h.path === "big.js").length <= 2);
  const hits = search(many, "retry upload", { k: 10 });
  ok("results from the same file never overlap", hits.every((a, i) => hits.every((b, j) => i === j || a.path !== b.path || a.end < b.start || b.end < a.start)));
}

group("stored index");
{
  const stored = JSON.parse(JSON.stringify(IX));
  eq("a JSON round-trip ranks the same", search(stored, "retry failed uploads").map((h) => h.path + ":" + h.start), search(IX, "retry failed uploads").map((h) => h.path + ":" + h.start));
  eq("Object.prototype names are not terms (constructor, toString)", search(stored, "constructor toString hasOwnProperty"), []);
  eq("a query that also says constructor still ranks its real words", (search(stored, "constructor for retry uploads")[0] || {}).path, "src/upload/retry.js");
  eq("an index from another version is not searched", search(Object.assign({}, stored, { version: 1 }), "retry"), []);
  eq("no index -> nothing", search(null, "retry"), []);
}

group("code_search tool");
{
  const fs = require("fs"), os = require("os"), path = require("path");
  const { codeSearchTool } = require("../lib/nexus/code-search");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nx-cs-"));
  for (const f of FILES) { fs.mkdirSync(path.join(dir, path.dirname(f.path)), { recursive: true }); fs.writeFileSync(path.join(dir, f.path), f.content); }
  fs.mkdirSync(path.join(dir, "node_modules", "dep"), { recursive: true });
  fs.writeFileSync(path.join(dir, "node_modules", "dep", "retry.js"), "function retryUploadAgain() { retry(); upload(); }\n");
  ok("no query -> an error, not a throw", !!codeSearchTool({}, dir).error);
  const r = codeSearchTool({ query: "where do we retry failed uploads with backoff" }, dir);
  eq("first use builds the index and finds the code", [r.results[0] && r.results[0].path, !!r.note], ["src/upload/retry.js", true]);
  ok("the index is stored for later searches", fs.existsSync(path.join(dir, ".nexus", "index.json")) && !codeSearchTool({ query: "retry" }, dir).note);
  ok("hits carry a line range and the matching lines, numbered", r.results[0].lines === "1-9" && r.results[0].matches.some((m) => /^2: function retryUpload/.test(m)));
  ok("vendored code is not indexed", !r.results.some((h) => h.path.startsWith("node_modules")));
  ok("path limits results to a directory", codeSearchTool({ query: "retry upload backoff", path: "docs" }, dir).results.every((h) => h.path.startsWith("docs/")));
  // a file edited after indexing: the stale range is rebuilt before it is returned
  const later = Date.now() + 5000;
  fs.writeFileSync(path.join(dir, "src/upload/retry.js"), "// moved\n\n\n\n" + FILES[0].content);
  fs.utimesSync(path.join(dir, "src/upload/retry.js"), later / 1000, later / 1000);
  const r2 = codeSearchTool({ query: "retry failed uploads backoff" }, dir);
  ok("an edited hit file triggers a rebuild with fresh line numbers", r2.results[0].matches.some((m) => /^6: function retryUpload/.test(m)));
  eq("nothing matching -> empty results with a hint", [codeSearchTool({ query: "kubernetes helm chart" }, dir).results.length, !!codeSearchTool({ query: "kubernetes helm chart" }, dir).hint], [0, true]);
  fs.rmSync(dir, { recursive: true, force: true });
}

console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (bm25 code search)");
process.exit(fail ? 1 : 0);

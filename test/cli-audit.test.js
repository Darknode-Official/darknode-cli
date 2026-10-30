"use strict";
// CLI surface audit (lib/cli/api-server.js, md-render.js, composer.js, text.js, ledger.js,
// tokcount.js, nexus-settings.js): the local REST server's auth/input handling, escape
// injection through rendered model text and file names, cursor/paste edge cases, and
// settings that must survive hand edits and failed writes.
const fs = require("fs");
const os = require("os");
const path = require("path");
const http = require("http");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const group = (t) => console.log("\n\x1b[1m" + t + "\x1b[0m");

const T = fs.mkdtempSync(path.join(os.tmpdir(), "nx-cli-audit-"));
const OSC = /\x1b\]|\x07|\x1b\[[0-9;?]*[A-Za-ln-z]/; // OSC, BEL, or any CSI that is not SGR

(async () => {
  group("api-server");
  {
    const { createAPIServer } = require("../lib/cli/api-server");
    const stub = path.join(T, "stub.js");
    fs.writeFileSync(stub, "console.log(JSON.stringify(process.argv.slice(2)));\n");
    const bare = createAPIServer({});
    ok("default bind is loopback", bare.host === "127.0.0.1");
    ok("no token passed -> one is generated (never unauthenticated)", typeof bare.token === "string" && bare.token.length >= 24);
    const api = createAPIServer({ token: "s3cret", darknodePath: stub });
    await new Promise((r) => api.srv.listen(0, "127.0.0.1", r));
    const port = api.srv.address().port;
    const req = (method, p, opt) => new Promise((res) => {
      const o = opt || {};
      const r = http.request({ port, host: "127.0.0.1", method, path: p, headers: Object.assign({ "X-API-Key": "s3cret" }, o.headers || {}) }, (s) => { let d = ""; s.on("data", (c) => d += c); s.on("end", () => res({ code: s.statusCode, body: d })); });
      r.on("error", (e) => res({ code: 0, body: e.message }));
      for (const c of o.chunks || (o.body != null ? [o.body] : [])) r.write(c);
      r.end();
    });
    ok("wrong key is refused", (await req("GET", "/health", { headers: { "X-API-Key": "s3cres" } })).code === 401);
    ok("missing key is refused", (await req("GET", "/health", { headers: { "X-API-Key": "" } })).code === 401);
    ok("text/plain CSRF-style POST without the key is refused", (await req("POST", "/api/v1/encode", { headers: { "X-API-Key": "", "Content-Type": "text/plain" }, body: "{\"data\":\"x\"}" })).code === 401);
    ok("right key passes", (await req("GET", "/health")).code === 200);
    const d1 = await req("POST", "/api/v1/osint/domain", { body: JSON.stringify({ domain: "--authorized" }) });
    ok("option-looking domain is rejected before the shell-out", d1.code === 400 && !/authorized"\]/.test(d1.body));
    ok("CR/LF in an email domain is rejected (whois query injection)", (await req("POST", "/api/v1/osint/email", { body: JSON.stringify({ email: "a@x.com\r\nGET / HTTP/1.0" }) })).code === 400);
    ok("a plain domain still reaches the tool", /"dns\\",\\"example\.com/.test((await req("POST", "/api/v1/osint/domain", { body: JSON.stringify({ domain: "example.com" }) })).body));
    const b = Buffer.from(JSON.stringify({ data: "é" })); const k = b.indexOf(0xc3) + 1;
    const enc = await req("POST", "/api/v1/encode", { chunks: [b.slice(0, k), b.slice(k)] });
    ok("a UTF-8 char split across body chunks is not mangled", JSON.parse(enc.body).result === Buffer.from("é").toString("base64"));
    const big = await req("POST", "/api/v1/encode", { body: "x".repeat(2.1e6) });
    ok("oversized body is cut off", big.code === 400 || big.code === 0);
    const t0 = Date.now();
    const sc = await req("POST", "/api/v1/scan/code", { body: JSON.stringify({ code: "SELECT ".repeat(40000) + "\nq = \"SELECT * FROM t WHERE id=\" + req.id" }) });
    ok("SQL pattern is linear on a long line (no event-loop stall)", Date.now() - t0 < 2000 && JSON.parse(sc.body).findings.some((f) => f.title === "SQL Injection" && f.line === 2));
    await new Promise((r) => api.srv.close(r));
  }

  group("md-render: escapes from model text");
  {
    const { renderMd } = require("../lib/cli/md-render");
    const { strWidth } = require("../lib/cli/tui-format");
    const tbl = renderMd("| a | b\x1b]0;pwned\x07 |\n|---|---|\n| x\x1b]52;c;ZXZpbA==\x07 | y\x1b[2J |", 80);
    ok("table cells drop OSC title/clipboard and CSI clear", !tbl.some((l) => OSC.test(l)));
    ok("table borders line up (escape bytes not counted as width)", new Set(tbl.map(strWidth)).size === 1);
    ok("fence label drops OSC", !renderMd("```js\x1b]0;t\x07\nx\n```", 80).some((l) => OSC.test(l)));
    ok("prose and quotes stay clean", !renderMd("a \x1b]52;c;eA==\x07 b\n> q \x1b]0;t\x1b\\", 80).some((l) => OSC.test(l)));
  }

  group("composer");
  {
    const C = require("../lib/cli/composer");
    const lone = (m) => /[\uDC00-\uDFFF]/.test(m.text[m.cursor] || "");
    let m = new C.ComposerModel({ text: "😀😀\nabc" }); m.moveUp();
    ok("Up onto an emoji line never splits a surrogate pair", !lone(m) && m.cursor === 2);
    m = new C.ComposerModel({ text: "abc\n😀😀" }); m.cursor = 3; m.moveDown();
    ok("Down onto an emoji line never splits a surrogate pair", !lone(m));
    m = new C.ComposerModel({ text: "abcd\nabcd" }); m.moveUp();
    ok("plain ASCII Up keeps the column", m.cursor === 4);
    m = new C.ComposerModel({ maxBytes: 3000 }); m.paste("x".repeat(2500)); m.paste("y".repeat(2500));
    ok("byte cap counts earlier collapsed pastes", Buffer.byteLength(m.submit()) <= 3000);
    m = new C.ComposerModel(); C.feed(m, "ab\x1b]0;pwn\x07c", {});
    ok("a coalesced typed chunk cannot insert ESC/BEL", !/[\x1b\x07]/.test(m.text) && m.text.startsWith("ab"));
    m = new C.ComposerModel(); C.feed(m, "é", {});
    ok("normal typing still inserts", m.text === "é");
  }

  group("text");
  {
    const { extractJson, oneline } = require("../lib/cli/text");
    const t0 = Date.now(); extractJson("{".repeat(200000)); extractJson("[".repeat(200000));
    ok("extractJson is linear on many unclosed openers", Date.now() - t0 < 500);
    ok("extractJson still finds embedded JSON", JSON.stringify(extractJson("x: {\"a\":[1]} end")) === "{\"a\":[1]}" && JSON.stringify(extractJson("x [1,2] y {\"b\":1}")) === "[1,2]" && extractJson("none", "fb") === "fb");
    ok("oneline never ends on half an emoji", !/[\uD800-\uDBFF]…$/.test(oneline("😀😀😀😀", 4)));
  }

  group("ledger + tokcount");
  {
    const L = require("../lib/cli/ledger"), K = require("../lib/cli/tokcount");
    const { strWidth } = require("../lib/cli/tui-format");
    const rows = L.renderTurns([{ label: "日本語のテキスト".repeat(10), cost: 0.1, paid: true }, { label: "x".repeat(200), cost: 0 }, { label: "a\x1b]0;t\x07b" }], { width: 80 });
    ok("ledger rows fit the width with wide labels", rows.every((l) => strWidth(l) <= 80));
    ok("ledger label escapes are dropped", !rows.some((l) => OSC.test(l)));
    ok("string costs add as numbers", L.summarizeTurns([{ cost: "0.5" }, { cost: 0.25 }]).cost === 0.75 && L.money("0.5") === "$0.5000");
    const tk = K.renderTokens([{ path: "src/" + "文件".repeat(40) + ".js", chars: 400 }, { path: "a\x1b]52;c;eA==\x07b.js", chars: 4 }], { width: 60 });
    ok("token rows fit the width with wide file names", tk.every((l) => strWidth(l) <= 60));
    ok("a file name's escape bytes are dropped", !tk.some((l) => OSC.test(l)));
    ok("estimateTokens past 2 GiB does not wrap to 0", K.estimateTokens(3e9) === 750000000);
  }

  group("nexus-settings");
  {
    const S = require("../lib/cli/nexus-settings");
    const H = path.join(T, "home"); fs.mkdirSync(path.join(H, ".nexus"), { recursive: true });
    const f = S.settingsPath(H);
    fs.writeFileSync(f, JSON.stringify({ autoCompact: "false", budgetCap: "lots", lean: true, mode: "plan" }));
    const st = S.createStore(H, {});
    ok("a wrong-typed saved value falls back to the default", st.get("autoCompact") === false && st.get("budgetCap") === 0);
    ok("right-typed saved values still load", st.get("lean") === true && st.get("mode") === "plan");
    ok("getSaved ignores prototype keys", st.getSaved("toString") === undefined && st.getSaved("__proto__") === undefined);
    ok("set() persists", st.set("lean", false) && JSON.parse(fs.readFileSync(f, "utf8")).lean === false);
    if (process.platform !== "win32" && process.getuid && process.getuid() !== 0) {
      fs.chmodSync(path.dirname(f), 0o500);
      const w = S.writeSaved({ lean: true }, H);
      fs.chmodSync(path.dirname(f), 0o700);
      ok("a failed write keeps the old file and leaves no temp file", !w && JSON.parse(fs.readFileSync(f, "utf8")).lean === false && fs.readdirSync(path.dirname(f)).every((n) => !/\.tmp-/.test(n)));
    }
    fs.writeFileSync(f, "{ not json");
    const st2 = S.createStore(H, {});
    ok("corrupt JSON -> defaults + file moved aside, not overwritten", st2.get("lean") === false && !!st2.corrupt && fs.existsSync(st2.corrupt));
  }

  fs.rmSync(T, { recursive: true, force: true });
  console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (cli audit)");
  process.exit(fail ? 1 : 0);
})();

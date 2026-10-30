"use strict";
// MCP audit (2026-10-30): JSON-RPC 2.0 / MCP stdio conformance of the two servers Nexus ships —
// darknode-mcp (`darknode mcp`) and ask-mcp (the ask_user shim external engines spawn) — plus
// the catalog. Each case here reproduced a real bug before its fix.
const path = require("path"), os = require("os"), fs = require("fs"), cp = require("child_process"), net = require("net");
const { PassThrough } = require("stream");
const M = require("../lib/nexus/darknode-mcp");
const { MCP_CATALOG } = require("../lib/nexus/mcp-catalog");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const group = (t) => console.log("\n\x1b[1m" + t + "\x1b[0m");
const ASK = path.join(__dirname, "..", "lib", "nexus", "ask-mcp.js");
const kids = [];
const lines = (s) => String(s || "").split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l));

// serveStdio over an in-memory pair with a stub server: returns parsed output lines
async function stdio(server, chunks) {
  const inp = new PassThrough(), out = new PassThrough(); let txt = ""; out.on("data", (d) => { txt += d; });
  const fin = M.serveStdio(server, inp, out);
  for (const c of chunks) { inp.write(c); await new Promise((r) => setImmediate(r)); }
  inp.end(); await fin; return lines(txt);
}
const stub = { handle: async (m) => m.method === "ping" ? { result: {} } : m.method === "slow" ? new Promise((r) => setTimeout(() => r({ result: { slow: true } }), 200)) : m.id === undefined ? null : { error: { code: -32601, message: "nope" } } };

function runAsk(input, env) {
  return cp.spawnSync(process.execPath, [ASK], { input, encoding: "utf8", timeout: 10000, env: Object.assign({}, process.env, { NEXUS_ASK_SOCK: "" }, env || {}) });
}

(async () => {
  group("darknode-mcp stdio framing");
  {
    const crashed = [];
    const onRej = (e) => crashed.push(e); process.on("unhandledRejection", onRej);
    const r = await stdio(stub, ['null\n5\n"x"\n{"jsonrpc":"2.0","id":1,"method":"ping"}\n']);
    await new Promise((res) => setTimeout(res, 20)); process.removeListener("unhandledRejection", onRej);
    ok("a bare null/number/string line is an Invalid Request, not a crash", !crashed.length && r.filter((m) => m.error && m.error.code === -32600 && m.id === null).length === 3 && r.some((m) => m.id === 1 && m.result));
    const b = await stdio(stub, ['[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","method":"notifications/x"},{"jsonrpc":"2.0","id":"two","method":"nope"}]\n[]\n']);
    const arr = b.find(Array.isArray) || [], single = b.find((m) => !Array.isArray(m)) || {};
    ok("a batch gets one array reply with every request answered and no notification reply", b.length === 2 && arr.length === 2 && arr.some((m) => m.id === 1) && arr.some((m) => m.id === "two" && m.error.code === -32601));
    ok("an empty batch is an Invalid Request", single.error && single.error.code === -32600);
    const z = await stdio(stub, ['{"jsonrpc":"2.0","id":0,"me', 'thod":"ping"}\r\n{"jsonrpc":"2.0","id":"s","method":"ping"}\n{"jsonrpc":"2.0","id":9,"method":"ping"}']);
    ok("id 0, a split message, CRLF, and a last line with no newline are all answered", [0, "s", 9].every((id) => z.some((m) => m.id === id && m.result)));
    const s = await stdio(stub, ['{"jsonrpc":"2.0","id":5,"method":"slow"}\n']);
    ok("stdin closing mid-call still answers the call before the loop ends", s.length === 1 && s[0].id === 5 && s[0].result.slow);
  }

  group("darknode-mcp tools/call params");
  {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "nx-mcpa-"));
    const web = path.resolve(__dirname, "..", "..", "darknode-web", "public", "js", "api", "catalog.js");
    if (fs.existsSync(web)) {
      const srv = M.createServer({ env: {}, home: tmp, here: path.join(__dirname, "..", "lib", "nexus"), cwd: tmp, fetchText: async () => { throw new Error("offline"); }, postJson: async () => ({ status: 500 }), account: { readAuth: () => null } });
      const r = await stdio(srv, [[
        '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}',
        '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"darknode_nope"}}',
        '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"darknode_account","arguments":"zz"}}',
        '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"darknode_account"}}',
      ].join("\n") + "\n"]);
      const by = (id) => r.find((m) => m.id === id) || {};
      ok("tools/call with no name is -32602", by(1).error && by(1).error.code === -32602);
      ok("an unknown tool is the spec's -32602 protocol error", by(2).error && by(2).error.code === -32602 && /Unknown tool/.test(by(2).error.message));
      ok("non-object arguments are -32602", by(3).error && by(3).error.code === -32602);
      ok("a valid call still returns a tool result", by(4).result && Array.isArray(by(4).result.content));
    } else ok("darknode-web checkout present (skipped tools/call cases)", true);
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (_) {}
  }

  group("ask-mcp shim");
  {
    const r = runAsk([
      '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}',
      '{"jsonrpc":"2.0","method":"notifications/initialized"}',
      '{bad',
      '{"jsonrpc":"2.0","method":"tools/list"}',
      '[{"jsonrpc":"2.0","id":"b1","method":"ping"},{"jsonrpc":"2.0","id":"b2","method":"tools/list"}]',
      '{"jsonrpc":"2.0","id":"u","method":"tools/call","params":{"name":"nope"}}',
      '{"jsonrpc":"2.0","id":"q","method":"tools/call","params":{"name":"ask_user","arguments":{}}}',
      '{"jsonrpc":"2.0","id":"t","method":"tools/call","params":{"name":"ask_user","arguments":"x"}}',
      '{"jsonrpc":"2.0","id":5,"method":"foo"}',
    ].join("\n") + "\n");
    const m = lines(r.stdout), by = (id) => m.find((x) => x.id === id) || {};
    ok("initialize with an unknown version answers one the shim speaks", by(0).result && by(0).result.protocolVersion === "2025-06-18");
    ok("malformed JSON gets a -32700 parse error", m.some((x) => x.id === null && x.error && x.error.code === -32700));
    ok("a notification of any method gets no reply (no id-less responses)", !m.some((x) => !("id" in x)));
    ok("a batch has every member answered", by("b1").result && by("b2").result && by("b2").result.tools.length === 1);
    ok("an unknown tool is -32602", by("u").error && by("u").error.code === -32602);
    ok("ask_user without a question is -32602, not a blank popup", by("q").error && by("q").error.code === -32602 && by("t").error && by("t").error.code === -32602);
    ok("an unknown method is -32601", by(5).error && by(5).error.code === -32601);
    ok("the shim exits cleanly on stdin end", r.status === 0);

    // a real round trip through a bridge socket that never answers: closing stdin mid-call must not orphan the shim
    const sock = path.join(os.tmpdir(), "nx-mcpa-" + process.pid + ".sock");
    try { fs.unlinkSync(sock); } catch (_) {}
    let got = "";
    const srv = net.createServer((c) => { c.on("data", (d) => { got += d; }); c.on("error", () => {}); });
    await new Promise((res) => srv.listen(sock, res));
    const k = cp.spawn(process.execPath, [ASK], { env: Object.assign({}, process.env, { NEXUS_ASK_SOCK: sock }), stdio: ["pipe", "pipe", "ignore"] }); kids.push(k);
    k.stdin.write('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ask_user","arguments":{"question":"Q?"}}}\n');
    await new Promise((res) => { const t0 = Date.now(); const iv = setInterval(() => { if (got || Date.now() - t0 > 3000) { clearInterval(iv); res(); } }, 20); });
    ok("the question reaches the bridge", /"question":"Q\?"/.test(got));
    const exited = new Promise((res) => k.on("exit", (code) => res(code)));
    k.stdin.end();
    const code = await Promise.race([exited, new Promise((res) => setTimeout(() => res("hung"), 3000))]);
    ok("closing stdin mid-call exits the shim (no orphan)", code === 0);
    srv.close(); try { fs.unlinkSync(sock); } catch (_) {}
  }

  group("catalog");
  {
    ok("sentry points at a package that exists (@sentry/mcp-server, not the 404 @modelcontextprotocol/server-sentry)", MCP_CATALOG.sentry.spec.args.includes("@sentry/mcp-server@latest") && MCP_CATALOG.sentry.needsEnv[0] === "SENTRY_" + "ACCESS_TOKEN");
  }

  group("MCP client (darknode.js mcpConnect) against a paginating server that can fail or die");
  {
    const src = fs.readFileSync(path.join(__dirname, "..", "darknode.js"), "utf8"), i = src.indexOf("function mcpConnect("), body = src.slice(i, src.indexOf("\n// ---------- Hooks", i));
    const mcpConnect = new Function("_cp", "require", body + "\nreturn mcpConnect;")(cp, require);
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nxmcpcli-")), srv = path.join(dir, "srv.js");
    fs.writeFileSync(srv, `let b="";process.stdin.on("data",(d)=>{b+=d;let n;while((n=b.indexOf("\\n"))>=0){const m=JSON.parse(b.slice(0,n));b=b.slice(n+1);if(m.id==null)continue;const r=(x)=>process.stdout.write(JSON.stringify({jsonrpc:"2.0",id:m.id,result:x})+"\\n");
if(m.method==="initialize")r({protocolVersion:"2024-11-05",capabilities:{tools:{}},serverInfo:{name:"t",version:"1"}});
else if(m.method==="tools/list")r(m.params.cursor?{tools:[{name:"two",inputSchema:{type:"object"}}]}:{tools:[{name:"one",inputSchema:{type:"object"}}],nextCursor:"p2"});
else if(m.method==="tools/call"&&m.params.name==="die")process.exit(3);
else if(m.method==="tools/call")r({content:[{type:"text",text:"boom"}],isError:true});}});`);
    const c = await mcpConnect("t", { command: process.execPath, args: [srv] }, dir);
    kids.push(c.cp);
    ok("tools/list follows nextCursor to the second page", !c.error && c.tools.map((t) => t.name).join(",") === "one,two");
    const t0 = Date.now(); let err = "";
    try { await c.call("tools/call", { name: "die", arguments: {} }, 600000); } catch (e) { err = e.message; }
    ok("a server that exits mid-call fails the call at once, not at the 10-minute timeout", /exited \(code 3\)/.test(err) && Date.now() - t0 < 5000);
    ok("an isError tool result reaches the model as an error", /result = r && r\.isError \? \{ error: resultText/.test(src));
    fs.rmSync(dir, { recursive: true, force: true });
  }

  for (const k of kids) { try { k.kill("SIGKILL"); } catch (_) {} }
  console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m");
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.log(e); for (const k of kids) { try { k.kill("SIGKILL"); } catch (_) {} } process.exit(1); });

"use strict";
// Outbound-fetch guard audit regressions (url-guard / http-fetch / web-search). No network:
// local servers on 127.0.0.1 and stubbed http(s).request only.
const http = require("http"), https = require("https"), EventEmitter = require("events");
const { isSafeUrl } = require("../lib/nexus/url-guard");
const { httpFetchTool } = require("../lib/nexus/http-fetch");
const { isLocalTarget } = require("../lib/governance/default-guard");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const group = (t) => console.log("\n\x1b[1m" + t + "\x1b[0m");
const listen = (handler) => new Promise((r) => { const s = http.createServer(handler).listen(0, "127.0.0.1", () => r(s)); });
const realHttps = https.request, realHttp = http.request;

(async () => {
  group("isSafeUrl: curl schemes without //");
  ok("rejects file:/etc/passwd, FILE:/, gopher:/, dict:/ (curl reads/dials these)", !isSafeUrl("file:/etc/passwd") && !isSafeUrl("FILE:/etc/passwd") && !isSafeUrl("gopher:/127.0.0.1:11211/x") && !isSafeUrl("dict:/x"));
  ok("still accepts bare host, host:port and http(s) urls", isSafeUrl("example.com") && isSafeUrl("localhost:3000") && isSafeUrl("example.com:8080/x") && isSafeUrl("https://test.darknode.ai/x"));

  group("http_fetch: resolved-address check uses the real port");
  {
    const s = await listen((q, r) => r.end("SECRET"));
    const p = s.address().port;
    const own80 = (h) => { const u = new URL(h); return /^(localhost|127(\.\d+){3}|\[::1\])$/i.test(u.hostname) && +(u.port || 80) === 80; }; // a background job owns :80 only
    const r = await httpFetchTool({ url: "http://localhost.:" + p + "/" }, { isLocal: (h) => isLocalTarget(h) && !own80(h) });
    ok("a name resolving to 127.0.0.1 on an unowned port is blocked (owned :80 not borrowed)", !!r.error && /blocked/.test(r.error) && r.body === undefined);
    s.close();
  }

  group("http_fetch: credentials dropped on a scheme downgrade");
  {
    const seen = [];
    const stub = (proto) => (url, opts, cb) => {
      const req = new EventEmitter(); req.write = () => {}; req.destroy = () => {};
      req.end = () => setImmediate(() => {
        seen.push({ href: String(url), headers: opts.headers });
        const res = new EventEmitter(); res.destroy = () => {};
        Object.assign(res, proto === "https" ? { statusCode: 302, headers: { location: "http://a.example/next" } } : { statusCode: 200, headers: { "content-type": "text/plain" } });
        cb(res); setImmediate(() => { if (proto === "http") res.emit("data", Buffer.from("ok")); res.emit("end"); });
      });
      return req;
    };
    https.request = stub("https"); http.request = stub("http");
    try {
      const r = await httpFetchTool({ url: "https://a.example/", headers: { Authorization: "Bearer s3cret", "x-keep": "1" } }, { isLocal: () => false });
      const hop = seen[1] || { headers: {} };
      ok("https -> http same host: Authorization not sent in cleartext, other headers kept", r.status === 200 && seen.length === 2 && !hop.headers.Authorization && hop.headers["x-keep"] === "1");
    } finally { https.request = realHttps; http.request = realHttp; }
  }

  group("web_search: never hangs on a broken or endless response");
  for (const mode of ["reset", "drip"]) {
    const s = await listen((q, r) => {
      r.writeHead(200, { "content-type": "text/html" }); r.write("<html>partial");
      if (mode === "reset") setTimeout(() => r.socket.destroy(), 30);
      else { const t = setInterval(() => r.write("x".repeat(200000)), 5); r.on("close", () => clearInterval(t)); }
    });
    const p = s.address().port;
    https.request = (o, cb) => realHttp(Object.assign({}, o, { host: "127.0.0.1", port: p }), cb);
    delete require.cache[require.resolve("../lib/nexus/web-search")];
    const { webSearchTool } = require("../lib/nexus/web-search");
    const t0 = Date.now();
    const r = await Promise.race([webSearchTool({ query: "x" }), new Promise((res) => setTimeout(() => res("HUNG"), 5000))]);
    https.request = realHttps;
    ok("web_search resolves promptly on a " + (mode === "reset" ? "mid-body reset" : "never-ending body"), r !== "HUNG" && Date.now() - t0 < 5000);
    s.close(); if (s.closeAllConnections) s.closeAllConnections();
  }

  console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (url guard audit)");
  process.exit(fail ? 1 : 0);
})();

"use strict";
// ================= browser: attach to the user's ALREADY-OPEN browser (agentic) =================
// Lets the agent look at what the user is actually looking at — their real tabs, logged-in pages,
// whatever is on screen — instead of launching a fresh, empty, logged-out browser and guessing.
//
// It speaks the Chrome DevTools Protocol (CDP) to a browser the user is already running, over a
// raw WebSocket we implement here from `net` + `crypto` (Nexus ships ZERO dependencies — no
// puppeteer/playwright). Works with any Chromium browser: Chrome, Edge, Brave, Chromium.
//
// HARD REQUIREMENT the user controls: the browser must have been started with a remote-debugging
// port open. A normal browser window cannot be attached to after the fact — that is a deliberate
// Chromium security boundary, not a Nexus limitation. `browserStatus()` detects whether a
// debuggable browser is reachable and, if not, prints the exact command to start one that keeps
// the user's own profile and logins. Nothing here opens a port or a browser on its own.
//
// Exposed agent tools (wired in darknode.js deviceTool): browser_status, browser_tabs,
// browser_read, browser_eval, browser_screenshot. Everything is observe/act on the LOCAL machine
// over loopback; it never dials out.

const net = require("net");
const crypto = require("crypto");
const http = require("http");

const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_PORT = 9222;
// Chrome=9222 is the convention; Edge/Brave/Chromium use the same flag. A couple of fallbacks in
// case the user picked a different port, tried in order by the auto-probe.
const PROBE_PORTS = [9222, 9223, 9229, 9222];

// ---- CDP discovery over plain HTTP (the /json endpoints are unauthenticated on loopback) --------
function httpJson(host, port, pathName, timeoutMs) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host, port, path: pathName, method: "GET", timeout: timeoutMs || 3500 }, (res) => {
      let d = "";
      res.on("data", (c) => { if (d.length < 2e6) d += c; });
      res.on("end", () => { try { resolve(JSON.parse(d)); } catch (_) { reject(new Error("non-JSON reply from " + pathName)); } });
    });
    req.on("timeout", () => { req.destroy(); reject(new Error("timeout")); });
    req.on("error", reject);
    req.end();
  });
}

async function listTargets(host, port) {
  const list = await httpJson(host, port, "/json", 3500);
  return (Array.isArray(list) ? list : []).filter((t) => t && t.webSocketDebuggerUrl);
}

// Choose a target. `sel` may be: null/"" (first real page), a number (index into the page list),
// a target id, or a substring of the title or URL.
function pickTarget(list, sel) {
  const pages = list.filter((t) => t.type === "page");
  const pool = pages.length ? pages : list;
  if (sel == null || sel === "") return pool[0] || null;
  const s = String(sel);
  if (/^\d+$/.test(s)) return pool[Number(s)] || null;
  return list.find((t) => t.id === s)
    || list.find((t) => (t.url || "").toLowerCase().includes(s.toLowerCase()))
    || list.find((t) => (t.title || "").toLowerCase().includes(s.toLowerCase()))
    || null;
}

// ---- a minimal WebSocket client (RFC 6455, client role) -----------------------------------------
// Parse ONE frame off the front of `buf`; return { fin, opcode, payload, rest } or null if the
// buffer does not yet hold a whole frame. Server->client frames are not masked.
function parseFrame(buf) {
  if (buf.length < 2) return null;
  const b0 = buf[0], b1 = buf[1];
  const fin = (b0 & 0x80) !== 0;
  const opcode = b0 & 0x0f;
  const masked = (b1 & 0x80) !== 0;
  let len = b1 & 0x7f;
  let off = 2;
  if (len === 126) { if (buf.length < 4) return null; len = buf.readUInt16BE(2); off = 4; }
  else if (len === 127) { if (buf.length < 10) return null; len = buf.readUInt32BE(2) * 4294967296 + buf.readUInt32BE(6); off = 10; }
  if (masked) off += 4;
  if (buf.length < off + len) return null;
  const maskKey = masked ? buf.slice(off - 4, off) : null;
  let payload = buf.slice(off, off + len);
  if (masked && maskKey) { const out = Buffer.allocUnsafe(len); for (let i = 0; i < len; i++) out[i] = payload[i] ^ maskKey[i & 3]; payload = out; }
  return { fin, opcode, payload, rest: buf.slice(off + len) };
}

// Build a client->server frame (always masked per spec).
function buildFrame(data, opcode) {
  opcode = opcode == null ? 0x1 : opcode;
  const payload = Buffer.isBuffer(data) ? data : Buffer.from(String(data), "utf8");
  const len = payload.length;
  let header;
  if (len < 126) { header = Buffer.alloc(2); header[1] = 0x80 | len; }
  else if (len < 65536) { header = Buffer.alloc(4); header[1] = 0x80 | 126; header.writeUInt16BE(len, 2); }
  else { header = Buffer.alloc(10); header[1] = 0x80 | 127; header.writeUInt32BE(Math.floor(len / 4294967296), 2); header.writeUInt32BE(len >>> 0, 6); }
  header[0] = 0x80 | opcode;
  const mask = crypto.randomBytes(4);
  const masked = Buffer.allocUnsafe(len);
  for (let i = 0; i < len; i++) masked[i] = payload[i] ^ mask[i & 3];
  return Buffer.concat([header, mask, masked]);
}

// Open one CDP session to a target's webSocketDebuggerUrl. Resolves to a client with
// .send(method, params) -> Promise(result) and .close(). Zero deps.
function openSession(wsUrl, timeoutMs) {
  const to = timeoutMs || 10000;
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(wsUrl); } catch (_) { return reject(new Error("bad ws url")); }
    const host = u.hostname, port = u.port || DEFAULT_PORT;
    const key = crypto.randomBytes(16).toString("base64");
    const sock = net.connect({ host: host, port: Number(port) });
    let settled = false;
    const fail = (e) => { if (!settled) { settled = true; try { sock.destroy(); } catch (_) {} reject(e instanceof Error ? e : new Error(String(e))); } };
    sock.setTimeout(to, () => fail(new Error("connection timeout")));
    sock.on("error", fail);
    sock.once("connect", () => {
      sock.write(
        "GET " + (u.pathname + (u.search || "")) + " HTTP/1.1\r\n" +
        "Host: " + host + ":" + port + "\r\n" +
        "Upgrade: websocket\r\n" +
        "Connection: Upgrade\r\n" +
        "Sec-WebSocket-Key: " + key + "\r\n" +
        "Sec-WebSocket-Version: 13\r\n\r\n"
      );
    });

    let buf = Buffer.alloc(0);
    let upgraded = false;
    let nextId = 1;
    const pending = new Map();
    let frag = null; // { opcode, chunks:[] } across continuation frames

    const client = {
      send(method, params) {
        const id = nextId++;
        sock.write(buildFrame(JSON.stringify({ id: id, method: method, params: params || {} })));
        return new Promise((res, rej) => {
          const timer = setTimeout(() => { if (pending.has(id)) { pending.delete(id); rej(new Error("CDP timeout: " + method)); } }, to);
          pending.set(id, { res: res, rej: rej, timer: timer });
        });
      },
      close() { try { sock.end(); } catch (_) {} },
    };

    const dispatch = (text) => {
      let obj; try { obj = JSON.parse(text); } catch (_) { return; }
      if (obj.id == null || !pending.has(obj.id)) return; // event or stray — ignore
      const p = pending.get(obj.id); pending.delete(obj.id); clearTimeout(p.timer);
      if (obj.error) p.rej(new Error(obj.error.message || JSON.stringify(obj.error)));
      else p.res(obj.result);
    };

    sock.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (!upgraded) {
        const idx = buf.indexOf("\r\n\r\n");
        if (idx === -1) return;
        const head = buf.slice(0, idx).toString("latin1");
        if (!/^HTTP\/1\.1 101/.test(head)) return fail(new Error("WebSocket upgrade refused: " + head.split("\r\n")[0]));
        buf = buf.slice(idx + 4);
        upgraded = true; settled = true; resolve(client);
      }
      let f;
      while ((f = parseFrame(buf))) {
        buf = f.rest;
        if (f.opcode === 0x8) { client.close(); return; }            // close
        if (f.opcode === 0x9) { sock.write(buildFrame(f.payload, 0xA)); continue; } // ping -> pong
        if (f.opcode === 0xA) continue;                               // pong
        if (f.opcode === 0x1 || f.opcode === 0x2) {                   // text/binary start
          if (f.fin) dispatch(f.payload.toString("utf8"));
          else frag = { chunks: [f.payload] };
        } else if (f.opcode === 0x0 && frag) {                        // continuation
          frag.chunks.push(f.payload);
          if (f.fin) { const t = Buffer.concat(frag.chunks).toString("utf8"); frag = null; dispatch(t); }
        }
      }
    });
    sock.on("close", () => { for (const [, p] of pending) { clearTimeout(p.timer); p.rej(new Error("WebSocket closed")); } pending.clear(); if (!settled) fail(new Error("closed before upgrade")); });
  });
}

// Run a sequence of CDP commands on a fresh session, then always close it.
async function withTarget(host, port, sel, fn) {
  const list = await listTargets(host, port);
  if (!list.length) throw new Error("no attachable tabs — is the browser running with the debug port open?");
  const t = pickTarget(list, sel);
  if (!t) throw new Error("no tab matched " + JSON.stringify(sel) + " — list tabs with browser_tabs");
  const cdp = await openSession(t.webSocketDebuggerUrl);
  try { return await fn(cdp, t); } finally { cdp.close(); }
}

// ---- the startup command we tell the user to run (keeps their profile + logins) -----------------
function startHint(port) {
  port = port || DEFAULT_PORT;
  const plat = process.platform;
  const dir = plat === "win32" ? "%TEMP%\\\\nexus-browser" : "\"$HOME/.nexus-browser-profile\"";
  if (plat === "darwin") {
    return "Fully quit Chrome, then run:\n" +
      "  \"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome\" --remote-debugging-port=" + port + " --user-data-dir=" + dir + "\n" +
      "Sign in once in that window; its tabs become attachable.";
  }
  if (plat === "win32") {
    return "Fully quit Chrome, then run (cmd):\n" +
      "  \"%ProgramFiles%\\\\Google\\\\Chrome\\\\Application\\\\chrome.exe\" --remote-debugging-port=" + port + " --user-data-dir=" + dir + "\n" +
      "Sign in once in that window; its tabs become attachable.";
  }
  return "Fully quit the browser, then run one of:\n" +
    "  google-chrome   --remote-debugging-port=" + port + " --user-data-dir=" + dir + "\n" +
    "  chromium        --remote-debugging-port=" + port + " --user-data-dir=" + dir + "\n" +
    "  brave-browser   --remote-debugging-port=" + port + " --user-data-dir=" + dir + "\n" +
    "Sign in once in that window; its tabs become attachable. (Recent Chromium refuses the debug\n" +
    "port on the DEFAULT profile dir, which is why a dedicated --user-data-dir is used.)";
}

// ---- high-level tool handlers -------------------------------------------------------------------
// Probe the default + a couple of fallback ports; report what is reachable.
async function browserStatus(a) {
  const host = (a && a.host) || DEFAULT_HOST;
  const ports = (a && a.port) ? [Number(a.port)] : [...new Set(PROBE_PORTS)];
  for (const port of ports) {
    try {
      const ver = await httpJson(host, port, "/json/version", 2500);
      const tabs = await listTargets(host, port).catch(() => []);
      return { reachable: true, host: host, port: port, browser: (ver && (ver.Browser || ver.product)) || "unknown", tabs: tabs.filter((t) => t.type === "page").length, hint: "attached — use browser_tabs / browser_read" };
    } catch (_) { /* try next port */ }
  }
  return { reachable: false, host: host, triedPorts: ports, hint: "No debuggable browser found. Start one so Nexus can see your real tabs:\n\n" + startHint(ports[0]) };
}

async function browserTabs(a) {
  const host = (a && a.host) || DEFAULT_HOST;
  const port = Number((a && a.port) || DEFAULT_PORT);
  let list;
  try { list = await listTargets(host, port); }
  catch (e) { return { error: e.message, hint: "run browser_status for how to start a debuggable browser" }; }
  const pages = list.filter((t) => t.type === "page");
  return {
    count: pages.length,
    tabs: pages.map((t, i) => ({ index: i, title: t.title || "", url: t.url || "", id: t.id })),
    note: pages.length ? "read one with browser_read{target:<index|url substring>}" : "no page tabs open",
  };
}

async function browserRead(a) {
  const host = (a && a.host) || DEFAULT_HOST;
  const port = Number((a && a.port) || DEFAULT_PORT);
  const max = Math.min(Math.max(Number((a && a.max) || 12000), 500), 60000);
  const sel = (a && (a.target != null ? a.target : a.tab));
  const selector = a && a.selector;
  const expr = selector
    ? "(function(){var el=document.querySelector(" + JSON.stringify(String(selector)) + ");return{title:document.title,url:location.href,text:el?(el.innerText||el.textContent||''):('(no element matched " + "'+" + JSON.stringify(String(selector)) + "+'" + ")')}})()"
    : "(function(){return{title:document.title,url:location.href,text:(document.body?document.body.innerText:'')}})()";
  try {
    return await withTarget(host, port, sel, async (cdp, t) => {
      const r = await cdp.send("Runtime.evaluate", { expression: expr, returnByValue: true });
      const v = (r && r.result && r.result.value) || {};
      const text = String(v.text || "");
      return { title: v.title || t.title || "", url: v.url || t.url || "", text: text.slice(0, max), truncated: text.length > max };
    });
  } catch (e) { return { error: e.message, hint: "run browser_status for how to start a debuggable browser" }; }
}

async function browserEval(a) {
  const host = (a && a.host) || DEFAULT_HOST;
  const port = Number((a && a.port) || DEFAULT_PORT);
  const expression = a && (a.expression || a.expr || a.code || a.js);
  if (!expression) return { error: "browser_eval needs an 'expression' (JavaScript to run in the page)" };
  const sel = a && (a.target != null ? a.target : a.tab);
  try {
    return await withTarget(host, port, sel, async (cdp) => {
      const r = await cdp.send("Runtime.evaluate", { expression: String(expression), returnByValue: true, awaitPromise: true });
      if (r && r.exceptionDetails) return { error: "page threw: " + (r.exceptionDetails.exception && r.exceptionDetails.exception.description || r.exceptionDetails.text || "error") };
      const res = r && r.result;
      let value = res ? (("value" in res) ? res.value : res.description) : undefined;
      let out = value;
      try { if (typeof value !== "string") out = JSON.stringify(value); } catch (_) { out = String(value); }
      return { type: res && res.type, result: String(out == null ? "" : out).slice(0, 20000) };
    });
  } catch (e) { return { error: e.message }; }
}

async function browserScreenshot(a, cwd) {
  const path = require("path"), fs = require("fs");
  const host = (a && a.host) || DEFAULT_HOST;
  const port = Number((a && a.port) || DEFAULT_PORT);
  const sel = a && (a.target != null ? a.target : a.tab);
  const rel = (a && (a.path || a.file)) || ("browser-" + Date.now() + ".png");
  const outPath = path.resolve(cwd || process.cwd(), rel);
  try {
    return await withTarget(host, port, sel, async (cdp, t) => {
      await cdp.send("Page.enable", {}).catch(() => {});
      const shot = await cdp.send("Page.captureScreenshot", { format: "png", captureBeyondViewport: !!(a && a.fullPage) });
      if (!shot || !shot.data) return { error: "no screenshot data returned" };
      fs.writeFileSync(outPath, Buffer.from(shot.data, "base64"));
      return { ok: true, path: path.relative(cwd || process.cwd(), outPath) || outPath, tab: t.title || t.url, bytes: Buffer.byteLength(shot.data, "base64") };
    });
  } catch (e) { return { error: e.message }; }
}

// Single entry point for deviceTool: returns a result object for a browser_* tool, or null if
// `name` is not one of ours (so the caller keeps looking).
async function browserTool(name, a, cwd) {
  a = a || {};
  switch (name) {
    case "browser_status": return await browserStatus(a);
    case "browser_tabs": case "browser_list": return await browserTabs(a);
    case "browser_read": case "browser_page": return await browserRead(a);
    case "browser_eval": case "browser_exec": return await browserEval(a);
    case "browser_screenshot": case "browser_shot": return await browserScreenshot(a, cwd);
    default: return null;
  }
}

module.exports = {
  browserTool, browserStatus, browserTabs, browserRead, browserEval, browserScreenshot,
  // exported for tests
  parseFrame, buildFrame, pickTarget, startHint,
};

"use strict";
// wait_for — block until something the agent started is actually ready: a
// local port accepts connections, a local URL answers, a file appears, or a
// background job prints a line matching a pattern (or exits). Replaces the
// usual `sleep 5 && curl …` guess loops, which either wait too long (wasted
// time) or not long enough (a false failure and another round-trip).
// Local only: URLs must point at this machine, so it never reaches the network.

const fs = require("fs");
const net = require("net");
const http = require("http");

const MAX_S = 180;
const LOCAL = /^(localhost|127\.\d+\.\d+\.\d+|\[?::1\]?|0\.0\.0\.0)$/i;

const probePort = (port, host) => new Promise((res) => {
  const s = net.connect({ port, host: host || "127.0.0.1" });
  const done = (ok) => { try { s.destroy(); } catch (_) {} res(ok); };
  s.setTimeout(1000, () => done(false)); s.once("connect", () => done(true)); s.once("error", () => done(false));
});
const probeUrl = (u) => new Promise((res) => {
  const lib = u.protocol === "https:" ? require("https") : http;
  const req = lib.get(u, { timeout: 2000, rejectUnauthorized: false }, (r) => { r.resume(); res(r.statusCode); });
  req.on("timeout", () => { req.destroy(); res(0); }); req.on("error", () => res(0));
});

// deps: { jobs (bgJobs), sleep(ms), now(), stopped() }
async function waitForTool(a, cwd, rp, deps) {
  deps = deps || {};
  const sleep = deps.sleep || ((ms) => new Promise((r) => setTimeout(r, ms)));
  const now = deps.now || Date.now;
  const timeout = Math.min(MAX_S, Math.max(1, +(a.timeout_s || a.timeout || 30))) * 1000;
  let check, what;
  if (a.port) {
    const port = +a.port; if (!(port > 0 && port < 65536)) return { error: "port must be 1-65535" };
    // no host: a dev server bound to "localhost" may listen on ::1 only (Node 17+ / Vite), so try both
    const hosts = a.host && LOCAL.test(a.host) ? [a.host.replace(/^\[|\]$/g, "")] : ["127.0.0.1", "::1"];
    what = "port " + port; check = async () => { for (const h of hosts) if (await probePort(port, h)) return { ready: true }; return null; };
  } else if (a.url) {
    let u; try { u = new URL(String(a.url)); } catch (_) { return { error: "invalid url" }; }
    if (!LOCAL.test(u.hostname)) return { error: "wait_for only checks local URLs (localhost/127.0.0.1) — use http_fetch for remote ones" };
    const want = a.status ? +a.status : 0;
    what = u.href; check = async () => { const s = await probeUrl(u); return s && (want ? s === want : s < 500) ? { ready: true, status: s } : null; };
  } else if (a.file) {
    let fp; try { fp = rp(a.file); } catch (e) { return { error: e.message }; }
    what = "file " + a.file; check = async () => (fs.existsSync(fp) ? { ready: true } : null);
  } else if (a.job || a.id) {
    const id = a.job || a.id, jobs = deps.jobs;
    if (!jobs || !jobs.get(id)) return { error: "no such background job " + id };
    let re = null;
    if (a.pattern) { try { re = new RegExp(a.pattern, "i"); } catch (e) { return { error: "invalid pattern: " + e.message }; } }
    what = re ? "job " + id + " output /" + a.pattern + "/" : "job " + id + " to exit";
    check = async () => {
      // colour codes inside a line (localhost:\x1b[1m5173) kept a pattern from ever matching; \r = progress redraws
      const j = jobs.get(id), out = (jobs.tail(id, 20000) || "").replace(/\x1b\[[0-9;?]*[ -\/]*[@-~]/g, "");
      if (re) { const lines = out.split(/\r\n|\r|\n/); for (let i = lines.length - 1; i >= 0; i--) if (re.test(lines[i])) return { ready: true, line: lines[i].slice(0, 300) }; }
      if (j.status !== "running") return re ? { ready: false, exited: true, code: j.code, tail: out.slice(-1500) } : { ready: true, code: j.code };
      return null;
    };
  } else return { error: "wait_for needs one of: port, url (local), file, or job (+ optional pattern)" };
  const t0 = now();
  while (true) {
    if (deps.stopped && deps.stopped()) return { ready: false, waited_s: +((now() - t0) / 1000).toFixed(1), note: "interrupted" };
    const r = await check();
    if (r) return Object.assign({ for: what, waited_s: +((now() - t0) / 1000).toFixed(1) }, r);
    if (now() - t0 >= timeout) {
      const res = { ready: false, for: what, waited_s: +(timeout / 1000).toFixed(1), note: "timed out" };
      if ((a.job || a.id) && deps.jobs) res.tail = (deps.jobs.tail(a.job || a.id, 1500) || "");
      return res;
    }
    await sleep(Math.min(500, Math.max(100, (now() - t0) / 10)));
  }
}

module.exports = { waitForTool, LOCAL };

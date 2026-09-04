"use strict";
const http = require("http");
const crypto = require("crypto");
const { execFile, spawn } = require("child_process");
const dns = require("dns").promises;
const os = require("os");
const { ENC } = require("../toolkit/encoders");

function createAPIServer(opts) {
  const port = opts.port || 8080;
  const host = opts.host || "0.0.0.0";
  const token = opts.token || null;
  const sentinelPath = opts.sentinelPath || require("path").join(__dirname, "..", "..", "sentinel.js");

  function sendJSON(res, code, obj) {
    const b = JSON.stringify(obj);
    res.writeHead(code, {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Headers": "Content-Type, X-API-Key",
      "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
      "Content-Length": Buffer.byteLength(b),
    });
    res.end(b);
  }

  function readBody(req) {
    return new Promise((resolve, reject) => {
      let data = "";
      req.on("data", (c) => { data += c; if (data.length > 2e6) { req.destroy(); reject(new Error("body too large")); } });
      req.on("end", () => {
        try { resolve(JSON.parse(data || "{}")); }
        catch (_) { reject(new Error("invalid JSON")); }
      });
      req.on("error", reject);
    });
  }

  function runSentinel(args, timeout) {
    return new Promise((resolve) => {
      const child = execFile(process.execPath, [sentinelPath, ...args], {
        timeout: timeout || 60000,
        env: Object.assign({}, process.env, { NO_COLOR: "1" }),
        maxBuffer: 10 * 1024 * 1024,
      }, (err, stdout, stderr) => {
        resolve({ ok: !err, output: (stdout || "").trim(), error: err ? (stderr || err.message || "").trim() : undefined });
      });
    });
  }

  const ENDPOINTS = {
    "/api/v1/scan/url": async (body) => {
      const url = body.url;
      if (!url) return { code: 400, body: { error: "missing 'url'" } };
      let host;
      try { host = new URL(url).hostname; } catch (_) { return { code: 400, body: { error: "invalid URL" } }; }
      const depth = body.depth || 1;
      const results = [];

      const headerRes = await runSentinel(["headers", host]);
      const dnsRes = await runSentinel(["dns", host]);
      const certRes = await runSentinel(["cert", host]);
      const subsRes = await runSentinel(["subs", host]);

      return {
        code: 200,
        body: {
          status: "complete",
          url,
          host,
          headers: headerRes.ok ? headerRes.output : null,
          dns: dnsRes.ok ? dnsRes.output : null,
          certificate: certRes.ok ? certRes.output : null,
          subdomains: subsRes.ok ? subsRes.output.split("\n").filter(Boolean) : [],
        },
      };
    },

    "/api/v1/scan/code": async (body) => {
      const code = body.code;
      if (!code) return { code: 400, body: { error: "missing 'code'" } };
      const lang = body.language || "unknown";
      const patterns = [
        { re: /eval\s*\(/g, title: "Dangerous eval()", severity: "critical" },
        { re: /exec\s*\(/g, title: "Command execution", severity: "critical" },
        { re: /\bSELECT\b.*\+\s*req\b/gi, title: "SQL Injection", severity: "critical" },
        { re: /innerHTML\s*=/g, title: "XSS via innerHTML", severity: "high" },
        { re: /document\.write\s*\(/g, title: "XSS via document.write", severity: "high" },
        { re: /password\s*[:=]\s*["'][^"']+["']/gi, title: "Hardcoded password", severity: "high" },
        { re: /api[_-]?key\s*[:=]\s*["'][^"']+["']/gi, title: "Hardcoded API key", severity: "high" },
        { re: /Math\.random\s*\(/g, title: "Weak randomness", severity: "medium" },
        { re: /http:\/\//g, title: "Insecure HTTP URL", severity: "low" },
        { re: /console\.log\s*\(/g, title: "Debug logging", severity: "info" },
      ];
      const findings = [];
      const lines = code.split("\n");
      for (const p of patterns) {
        for (let i = 0; i < lines.length; i++) {
          if (p.re.test(lines[i])) {
            findings.push({ severity: p.severity, title: p.title, line: i + 1, detail: lines[i].trim().slice(0, 120) });
          }
          p.re.lastIndex = 0;
        }
      }
      return { code: 200, body: { status: "complete", language: lang, findings } };
    },

    "/api/v1/osint/domain": async (body) => {
      const domain = body.domain;
      if (!domain) return { code: 400, body: { error: "missing 'domain'" } };
      const [dnsRes, whoisRes, subsRes, headerRes] = await Promise.all([
        runSentinel(["dns", domain]),
        runSentinel(["whois", domain]),
        runSentinel(["subs", domain]),
        runSentinel(["headers", domain]),
      ]);
      return {
        code: 200,
        body: {
          domain,
          dns: dnsRes.ok ? dnsRes.output : null,
          whois: whoisRes.ok ? whoisRes.output : null,
          subdomains: subsRes.ok ? subsRes.output.split("\n").filter(Boolean) : [],
          headers: headerRes.ok ? headerRes.output : null,
        },
      };
    },

    "/api/v1/osint/email": async (body) => {
      const email = body.email;
      if (!email) return { code: 400, body: { error: "missing 'email'" } };
      const domain = email.split("@")[1];
      if (!domain) return { code: 400, body: { error: "invalid email" } };
      const mxRes = await runSentinel(["dns", domain]);
      return {
        code: 200,
        body: {
          email,
          domain,
          dns: mxRes.ok ? mxRes.output : null,
          note: "Use haveibeenpwned.com or dehashed.com for breach lookups",
        },
      };
    },

    "/api/v1/hash/crack": async (body) => {
      const hash = body.hash;
      if (!hash) return { code: 400, body: { error: "missing 'hash'" } };
      const res = await runSentinel(["hash", hash]);
      return { code: 200, body: { hash, output: res.ok ? res.output : res.error } };
    },

    "/api/v1/encode": async (body) => {
      const data = body.data;
      if (!data) return { code: 400, body: { error: "missing 'data'" } };
      const op = body.operation || "encode";
      // Accept legacy short names and map to the shared ENC table's keys so the API
      // and CLI stay in lockstep (base64/hex/url/base32/base58/rot13).
      const alias = { base64: "b64", b64: "b64", hex: "hex", url: "url", base32: "base32", base58: "base58", rot13: "rot13" };
      const fmt = body.format || "base64";
      const key = alias[fmt];
      const fn = key && ENC[key + (op === "decode" ? "d" : "e")];
      if (!fn) return { code: 400, body: { error: "unsupported format — use base64, hex, url, base32, base58, or rot13" } };
      let result;
      try { result = fn(String(data)); } catch (e) { return { code: 400, body: { error: "encode failed: " + e.message } }; }
      return { code: 200, body: { result, format: fmt, operation: op } };
    },

    "/api/v1/generate/payload": async (body) => {
      const type = body.type || "reverse-shell";
      const lang = body.language || "bash";
      const lhost = body.lhost || "127.0.0.1";
      const lport = body.lport || 4444;
      const res = await runSentinel(["payloads", lang]);
      return {
        code: 200,
        body: {
          type,
          language: lang,
          lhost,
          lport,
          output: res.ok ? res.output.replace(/LHOST/g, lhost).replace(/LPORT/g, String(lport)) : res.error,
        },
      };
    },

    "/api/v1/ai/ask": async (body) => {
      const question = body.question;
      if (!question) return { code: 400, body: { error: "missing 'question'" } };
      const res = await runSentinel(["nexus", "--print", question], 120000);
      return {
        code: 200,
        body: { answer: res.ok ? res.output : (res.error || "AI engine unavailable"), engine: "nexus" },
      };
    },
  };

  const srv = http.createServer(async (req, res) => {
    if (req.method === "OPTIONS") return sendJSON(res, 200, { ok: true });

    if (token) {
      const got = req.headers["x-api-key"] || "";
      if (got !== token) return sendJSON(res, 401, { error: "unauthorized — include X-API-Key header" });
    }

    const url = req.url.split("?")[0];

    if (req.method === "GET" && url === "/health") {
      return sendJSON(res, 200, { ok: true, version: "1.0.0", endpoints: Object.keys(ENDPOINTS) });
    }

    if (req.method === "POST" && ENDPOINTS[url]) {
      try {
        const body = await readBody(req);
        const result = await ENDPOINTS[url](body);
        return sendJSON(res, result.code, result.body);
      } catch (e) {
        return sendJSON(res, 400, { error: e.message });
      }
    }

    sendJSON(res, 404, { error: "not found", endpoints: Object.keys(ENDPOINTS) });
  });

  return { srv, port, host, token, ENDPOINTS };
}

module.exports = { createAPIServer };

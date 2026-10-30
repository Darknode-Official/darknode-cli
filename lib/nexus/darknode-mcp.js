"use strict";
// ============================================================================
// darknode-mcp: the Darknode Deck's analysis tools as an MCP server, so any AI
// client (Claude Code, Claude Desktop, Cursor, Codex, Gemini CLI, Nexus, ...) can
// run them. Start it with `darknode mcp` (stdio, JSON-RPC 2.0, no dependencies).
//
// The tools are the Deck's own engines (darknode-web public/js), not copies:
//   - from a local darknode-web checkout when one is found (DARKNODE_WEB_DIR, or a
//     sibling ../darknode-web), else
//   - downloaded from the live site (https://darknode.ai/js/...) into
//     ~/.darknode/engines, refreshed every 12 hours, the cached copy used offline.
// The engines run on this machine, so the files an AI hands them never leave it.
// Only "send to Deck" uploads anything, and only the findings, with the user's own
// workspace API key.
//
// Plans match the Deck: the signed-in Darknode account's plan (users/{uid}.tier, or
// the owner's admin claim) decides which tools are listed, using the same table the
// Deck sidebar uses (core/entitlements.js). Not signed in = Free.
// ============================================================================
const fs = require("fs");
const os = require("os");
const path = require("path");
const { pathToFileURL } = require("url");

const PROTOCOLS = ["2025-06-18", "2025-03-26", "2024-11-05"];
const DEFAULT_ORIGIN = "https://darknode.ai";
const DEFAULT_API = "https://darknode-proxy.darknode-ai.workers.dev";
const REFRESH_MS = 12 * 3600 * 1000;
const FILE_CAP = 20 * 1024 * 1024, TOTAL_CAP = 60 * 1024 * 1024, MAX_FILES = 500;
const SKIP_DIRS = new Set([".git", "node_modules", ".nexus", "dist", "build", ".cache", "__pycache__", ".venv", "venv", "target"]);
const SEV = ["critical", "high", "medium", "low", "info"];

// ---------------------------------------------------------------- engine source
// Module specifiers an ES module pulls in: static import/export-from, bare import, import().
function importSpecifiers(src) {
  const out = new Set(); let m;
  const re = /(?:^|[;\s])(?:import|export)\s+(?:[\w*{}\s,$]+?\s+from\s+)?["']([^"']+)["']|\bimport\(\s*["']([^"']+)["']\s*\)/g;
  while ((m = re.exec(String(src)))) out.add(m[1] || m[2]);
  return [...out];
}

// "/js/a/b.js?v=1" or "../b.js" seen from js-relative file `from` -> js-relative path, or null if off-site.
function resolveSpec(spec, from) {
  const s = String(spec).split(/[?#]/)[0];
  if (/^[a-z][a-z0-9+.-]*:/i.test(s)) return null;               // http:, data:, node: ...
  if (s.startsWith("/js/")) return path.posix.normalize(s.slice(4));
  if (s.startsWith("./") || s.startsWith("../")) { const r = path.posix.normalize(path.posix.join(path.posix.dirname(from), s)); return r.startsWith("../") ? null : r; }
  return null;                                                    // bare package name: not ours
}

// Rewrite site-absolute "/js/x.js?v=.." imports to relative ones so the copy loads from disk.
function relativize(src, from) {
  return String(src).replace(/(["'])\/js\/([^"'?#]+)(?:\?[^"']*)?\1/g, (all, q, p) => {
    let rel = path.posix.relative(path.posix.dirname(from), p); if (!rel.startsWith(".")) rel = "./" + rel; return q + rel + q;
  });
}

// Download `entries` (js-relative paths) and everything they import into dir, atomically.
// fetchText(url) -> Promise<string>. Returns the list of files written.
async function syncEngines(dir, entries, fetchText, origin) {
  const tmp = dir + ".tmp-" + process.pid;
  fs.rmSync(tmp, { recursive: true, force: true });
  const seen = new Set(), queue = entries.slice(), files = [];
  while (queue.length) {
    const rel = queue.shift(); if (seen.has(rel)) continue; seen.add(rel);
    const src = await fetchText(origin + "/js/" + rel);
    if (/^\s*</.test(src)) throw new Error(rel + ": the site returned a web page, not a script");
    for (const sp of importSpecifiers(src)) { const r = resolveSpec(sp, rel); if (r && !seen.has(r)) queue.push(r); }
    const out = path.join(tmp, rel); fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, relativize(src, rel)); files.push(rel);
  }
  fs.writeFileSync(path.join(tmp, "package.json"), JSON.stringify({ type: "module" }) + "\n");
  fs.writeFileSync(path.join(tmp, ".synced.json"), JSON.stringify({ origin, at: Date.now(), files }) + "\n");
  fs.rmSync(dir, { recursive: true, force: true }); fs.renameSync(tmp, dir);
  return files;
}

function findWebDir(env, here) {
  const cands = [env.DARKNODE_WEB_DIR, path.resolve(here, "..", "..", "..", "darknode-web")].filter(Boolean);
  for (const c of cands) { const js = fs.existsSync(path.join(c, "public", "js", "api", "catalog.js")) ? path.join(c, "public", "js") : fs.existsSync(path.join(c, "api", "catalog.js")) ? c : null; if (js) return js; }
  return null;
}

// -> { root, source, note }. A local checkout wins; else the cache, refreshed when stale.
async function engineRoot(o) {
  const local = findWebDir(o.env, o.here);
  if (local) return { root: local, source: "local checkout " + local };
  const dir = path.join(o.home, ".darknode", "engines", "js");
  let meta = null; try { meta = JSON.parse(fs.readFileSync(path.join(dir, ".synced.json"), "utf8")); } catch (_) {}
  const fresh = meta && meta.origin === o.origin && Date.now() - meta.at < REFRESH_MS;
  if (!fresh) {
    try {
      const cat = await o.fetchText(o.origin + "/js/api/catalog.js");
      const engines = [...cat.matchAll(/T\("[\w-]+",\s*"[^"]*",\s*"[\w-]+",\s*"([\w/.-]+\.js)"/g)].map((m) => m[1]);
      await syncEngines(dir, ["api/catalog.js"].concat(engines), o.fetchText, o.origin);
      return { root: dir, source: o.origin };
    } catch (e) {
      if (!meta) throw new Error("could not download the Darknode tools from " + o.origin + " (" + e.message + "), and there is no cached copy yet");
      return { root: dir, source: "cached copy from " + new Date(meta.at).toISOString().slice(0, 16).replace("T", " "), note: "Using the cached tools: " + e.message };
    }
  }
  return { root: dir, source: "cached copy from " + meta.origin };
}

// ---------------------------------------------------------------- account & plan
const b64json = (s) => { try { return JSON.parse(Buffer.from(String(s).replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")); } catch (_) { return null; } };
const jwtClaims = (t) => b64json(String(t || "").split(".")[1] || "");

// deps: { readAuth(), saveAuth(a), refresh(refreshToken) -> {id_token, refresh_token}, getJson(url, headers) -> {status, json}, projectId }
async function resolveAccount(deps) {
  const a = deps.readAuth();
  if (!a || !a.idToken || !a.uid) return { signedIn: false, tier: "free" };
  let tok = a.idToken, c = jwtClaims(tok);
  if (!c || !c.exp || c.exp * 1000 - Date.now() < 120000) {
    try { const r = await deps.refresh(a.refreshToken); if (r && r.id_token) { tok = r.id_token; c = jwtClaims(tok); deps.saveAuth(Object.assign({}, a, { idToken: tok, refreshToken: r.refresh_token || a.refreshToken, ts: Date.now() })); } }
    catch (_) {}
  }
  const who = { signedIn: true, uid: a.uid, email: a.email || "", name: a.name || "" };
  if (!c || c.exp * 1000 < Date.now()) return Object.assign(who, { tier: "free", note: "Your Darknode sign-in has expired. Sign in again with `darknode nexus` then /login." });
  if (c.admin === true) return Object.assign(who, { tier: "enterprise", owner: true });
  try {
    const r = await deps.getJson("https://firestore.googleapis.com/v1/projects/" + deps.projectId + "/databases/(default)/documents/users/" + encodeURIComponent(a.uid), { Authorization: "Bearer " + tok });
    const f = r && r.json && r.json.fields;
    return Object.assign(who, { tier: (f && f.tier && f.tier.stringValue) || "free" });
  } catch (e) { return Object.assign(who, { tier: "free", note: "Could not read your plan (" + e.message + "); showing Free tools." }); }
}

// ---------------------------------------------------------------- inputs
// paths (files or folders on this machine) + inline files -> [{ name, text }].
function gatherFiles(args, cwd) {
  const out = [], skipped = []; let total = 0;
  const add = (name, text) => { if (out.length >= MAX_FILES) { skipped.push(name + " (file limit)"); return; } total += text.length; if (total > TOTAL_CAP) { skipped.push(name + " (size limit)"); return; } out.push({ name, text }); };
  for (const f of Array.isArray(args.files) ? args.files : []) if (f && typeof f.text === "string") add(String(f.name || "input.txt"), f.text);
  if (typeof args.text === "string" && args.text) add(String(args.name || "input.txt"), args.text);
  const walk = (abs, shown) => {
    let st; try { st = fs.statSync(abs); } catch (e) { skipped.push(shown + " (" + (e.code === "ENOENT" ? "not found" : e.code || e.message) + ")"); return; }
    if (st.isDirectory()) { let ents = []; try { ents = fs.readdirSync(abs).sort(); } catch (e) { skipped.push(shown + " (" + e.code + ")"); return; } for (const n of ents) if (!SKIP_DIRS.has(n)) walk(path.join(abs, n), path.join(shown, n)); return; }
    if (!st.isFile()) return;
    if (st.size > FILE_CAP) { skipped.push(shown + " (over 20 MB)"); return; }
    const buf = fs.readFileSync(abs);
    if (buf.subarray(0, 8000).includes(0)) { skipped.push(shown + " (binary)"); return; }
    add(shown, buf.toString("utf8"));
  };
  for (const p of Array.isArray(args.paths) ? args.paths : typeof args.paths === "string" ? [args.paths] : []) {
    const abs = path.resolve(cwd, String(p).replace(/^~(?=$|\/)/, os.homedir()));
    walk(abs, path.isAbsolute(String(p)) ? abs : String(p));
  }
  return { files: out, skipped };
}

// ---------------------------------------------------------------- outputs
const normSev = (s) => { s = String(s || "").toLowerCase(); return SEV.includes(s) ? s : s === "none" || s === "ok" ? "info" : "medium"; };
function findingsOf(r) {
  if (Array.isArray(r && r.findings)) return r.findings;
  if (Array.isArray(r && r.urls)) return r.urls.filter((u) => u.severity && u.severity !== "none" && u.severity !== "low").map((u) => ({ severity: u.severity, title: u.input, detail: (u.reasons || []).map((x) => x.t).join(" ") }));
  return [];
}
const pick = (f, ...ks) => { for (const k of ks) if (f[k] != null && f[k] !== "") return typeof f[k] === "string" ? f[k] : JSON.stringify(f[k]); return ""; };

function shapeResult(tool, r, max) {
  const all = findingsOf(r).slice().sort((a, b) => SEV.indexOf(normSev(a.severity)) - SEV.indexOf(normSev(b.severity)));
  const by = {}; for (const f of all) { const s = normSev(f.severity); by[s] = (by[s] || 0) + 1; }
  const summary = r.summary || { score: r.score, grade: r.grade, stats: r.stats || r.counts, kpis: r.kpis };
  return { tool: tool.id, name: tool.name, summary, bySeverity: by, total: all.length, findings: all.slice(0, max), truncated: Math.max(0, all.length - max), skipped: r.skipped || [], parse: r.parse || undefined };
}

function resultText(s, extraSkipped) {
  const L = [s.name + ": " + s.total + " finding" + (s.total === 1 ? "" : "s") + (s.total ? " (" + SEV.filter((k) => s.bySeverity[k]).map((k) => s.bySeverity[k] + " " + k).join(", ") + ")" : "")];
  s.findings.forEach((f, i) => {
    const title = pick(f, "title", "name", "rule", "id"); let detail = pick(f, "detail", "description", "summary", "message"); const fix = pick(f, "fix", "recommendation", "remediation");
    if (title && detail.startsWith(title)) detail = detail.slice(title.length).replace(/^[\s:.-]+/, "");
    L.push((i + 1) + ". [" + normSev(f.severity) + "] " + title + (detail ? " - " + detail.slice(0, 400) : "") + (fix ? " Fix: " + fix.slice(0, 300) : ""));
  });
  if (s.truncated) L.push("... " + s.truncated + " more (raise max_findings to see them).");
  const sk = (s.skipped || []).concat(extraSkipped || []);
  if (sk.length) L.push("Not read: " + sk.slice(0, 20).map((x) => typeof x === "string" ? x : (x.name || x.file || "") + (x.reason ? " (" + x.reason + ")" : "")).join("; "));
  L.push("Summary: " + JSON.stringify(s.summary).slice(0, 1500));
  return L.join("\n");
}

// tool findings -> the Deck Finding contract the ingest API takes.
function toDeckFindings(tool, findings) {
  return findings.slice(0, 2000).map((f) => ({
    title: (pick(f, "title", "name", "rule", "id") || tool.name + " finding").slice(0, 300),
    severity: normSev(f.severity), category: tool.id,
    description: pick(f, "detail", "description", "summary", "message").slice(0, 4000) || undefined,
    recommendation: pick(f, "fix", "recommendation", "remediation").slice(0, 2000) || undefined,
    tags: ["mcp", tool.id],
  }));
}

// ---------------------------------------------------------------- server
function createServer(o) {
  // o: { env, home, here, cwd, fetchText, postJson(url, body, headers), account deps, version }
  const st = { eng: null, cat: null, ent: null, mods: {}, acct: null, acctAt: 0, results: new Map(), seq: 0 };
  const origin = (o.env.DARKNODE_ORIGIN || DEFAULT_ORIGIN).replace(/\/+$/, "");
  const apiBase = (o.env.DARKNODE_API || DEFAULT_API).replace(/\/+$/, "");
  const imp = (rel) => import(pathToFileURL(path.join(st.eng.root, rel)).href);
  const load = async () => {
    if (!st.cat) { st.eng = await engineRoot({ env: o.env, here: o.here, home: o.home, origin, fetchText: o.fetchText }); st.cat = await imp("api/catalog.js"); st.ent = await imp("core/entitlements.js"); }
    return st.cat;
  };
  const account = async () => { if (!st.acct || Date.now() - st.acctAt > 300000) { st.acct = await resolveAccount(o.account); st.acctAt = Date.now(); } return st.acct; };
  const allowed = (t, tier) => st.ent.rank(tier) >= st.ent.rank(t.tier);

  const RUN_SCHEMA = (t) => ({
    type: "object",
    properties: {
      paths: { type: "array", items: { type: "string" }, description: "Files or folders on this machine to analyze (folders are read recursively, skipping .git and node_modules). Relative paths are from " + o.cwd + "." },
      files: { type: "array", items: { type: "object", properties: { name: { type: "string" }, text: { type: "string" } }, required: ["text"] }, description: "Inline file contents, when the data is not on disk. The name's extension helps detect the format." },
      options: { type: "object", description: "Engine options, the same settings the " + t.name + " tool has in the Deck (thresholds etc). Usually leave empty." },
      max_findings: { type: "integer", minimum: 1, maximum: 1000, description: "Findings to return, most severe first (default 50)." },
    },
  });
  const META = [
    { name: "darknode_account", description: "Show the signed-in Darknode account, its plan, the Darknode tools this plan can run and which plan unlocks the others.", inputSchema: { type: "object", properties: {} } },
    { name: "darknode_send_to_deck", description: "Send the findings of an earlier Darknode tool run to the user's Darknode Deck (they appear in the Findings and Security Graph after the Deck pulls them in). Needs a workspace API key with the ingest:write scope from Deck > Integrations > API keys, given here or as DARKNODE_API_KEY and DARKNODE_WORKSPACE.", inputSchema: { type: "object", properties: { result_id: { type: "string", description: "The result_id an earlier tool run returned." }, workspace_id: { type: "string" }, api_key: { type: "string", description: "A dk_ workspace API key. Prefer the DARKNODE_API_KEY environment variable." } }, required: ["result_id"] } },
  ];
  const toolName = (t) => "darknode_" + t.id;

  async function listTools() {
    const cat = await load(), a = await account();
    return META.concat(cat.TOOLS.filter((t) => allowed(t, a.tier)).map((t) => ({
      name: toolName(t), title: "Darknode " + t.name,
      description: t.does + " Input: " + t.input + " Runs locally with the Darknode Deck's engine; the data stays on this machine.",
      inputSchema: RUN_SCHEMA(t), annotations: { readOnlyHint: true, openWorldHint: false },
    })));
  }

  async function call(name, args) {
    args = args || {};
    const cat = await load(), a = await account();
    if (name === "darknode_account") {
      const can = cat.TOOLS.filter((t) => allowed(t, a.tier)), locked = cat.TOOLS.filter((t) => !allowed(t, a.tier));
      const txt = [(a.signedIn ? "Signed in as " + (a.email || a.name || a.uid) : "Not signed in (sign in with `darknode nexus`, then /login, to use your plan)") + ". Plan: " + st.ent.planLabel(a.tier) + (a.owner ? " (owner)" : "") + ".",
        a.note || "", "Tools on this plan (" + can.length + "): " + (can.map((t) => t.name).join(", ") || "none"),
        locked.length ? "Need a higher plan: " + locked.map((t) => t.name + " (" + st.ent.planLabel(t.tier) + ")").join(", ") : "", "Tools from: " + st.eng.source + (st.eng.note ? ". " + st.eng.note : "")].filter(Boolean).join("\n");
      return { content: [{ type: "text", text: txt }], structuredContent: { signedIn: a.signedIn, plan: a.tier, tools: can.map((t) => t.id), locked: locked.map((t) => ({ id: t.id, plan: t.tier })) } };
    }
    if (name === "darknode_send_to_deck") {
      const r = st.results.get(String(args.result_id || ""));
      if (!r) return err("Unknown result_id. Run a Darknode tool first and pass the result_id it returned.");
      const key = args.api_key || o.env.DARKNODE_API_KEY, wid = args.workspace_id || o.env.DARKNODE_WORKSPACE;
      if (!key || !wid) return err("Needs a workspace API key and workspace id: create a key with the ingest:write scope in the Deck (Integrations > API keys), then set DARKNODE_API_KEY and DARKNODE_WORKSPACE for this server.");
      if (!/^[A-Za-z0-9_-]{1,128}$/.test(wid)) return err("That workspace id is not valid.");
      const body = { findings: toDeckFindings(r.tool, r.findings) };
      if (!body.findings.length) return { content: [{ type: "text", text: "That run had no findings to send." }] };
      const res = await o.postJson(apiBase + "/api/v1/ingest/" + wid, body, { Authorization: "Bearer " + key });
      if (!res || res.status >= 300) return err("The Deck refused the findings (HTTP " + (res && res.status) + "): " + ((res && res.json && res.json.error) || "no detail"));
      return { content: [{ type: "text", text: "Sent " + (res.json.accepted || body.findings.length) + " findings to the Deck. They show up in Findings the next time the Deck is open." }], structuredContent: res.json };
    }
    const t = cat.TOOLS.find((x) => toolName(x) === name);
    if (!t) throw Object.assign(new Error("Unknown tool: " + name), { code: -32602 }); // the spec's protocol error for an unknown tool
    if (!allowed(t, a.tier)) return err(t.name + " needs the " + st.ent.planLabel(t.tier) + " plan; this account is on " + st.ent.planLabel(a.tier) + ".");
    const g = gatherFiles(args, o.cwd);
    if (!g.files.length) return err("Nothing to analyze. Pass paths (files or folders on this machine) or files [{name, text}]." + (g.skipped.length ? " Not read: " + g.skipped.join("; ") : ""));
    const E = st.mods[t.engine] || (st.mods[t.engine] = await imp(t.engine));
    let r; try { r = await cat.run(t, E, g.files, args.options && typeof args.options === "object" ? args.options : {}); }
    catch (e) { return err(t.name + " could not read that input: " + (e && e.message || e)); }
    const max = Math.max(1, Math.min(1000, parseInt(args.max_findings, 10) || 50));
    const s = shapeResult(t, r, max);
    const id = "r" + (++st.seq).toString(36) + Date.now().toString(36).slice(-4);
    st.results.set(id, { tool: t, findings: findingsOf(r) }); if (st.results.size > 50) st.results.delete(st.results.keys().next().value);
    s.result_id = id; s.files = g.files.length;
    return { content: [{ type: "text", text: resultText(s, g.skipped) + "\nresult_id: " + id + " (pass it to darknode_send_to_deck to add these findings to the Deck)" }], structuredContent: JSON.stringify(s).length > 400000 ? Object.assign({}, s, { findings: s.findings.slice(0, 20), truncated: s.total - 20 }) : s };
  }
  const err = (text) => ({ content: [{ type: "text", text }], isError: true });

  async function handle(msg) {
    const id = msg.id, m = msg.method, p = msg.params || {};
    if (m === "initialize") return { result: { protocolVersion: PROTOCOLS.includes(p.protocolVersion) ? p.protocolVersion : PROTOCOLS[0], capabilities: { tools: { listChanged: false } }, serverInfo: { name: "darknode", title: "Darknode", version: o.version || "1.0.0" }, instructions: "Darknode security analysis tools. Each darknode_<tool> runs one Darknode Deck engine locally on files from this machine (paths) or inline text (files). Call darknode_account to see the plan and which tools it unlocks." } };
    if (m === "ping") return { result: {} };
    if (m === "tools/list") return { result: { tools: await listTools() } };
    if (m === "tools/call") {
      if (typeof p.name !== "string" || (p.arguments != null && (typeof p.arguments !== "object" || Array.isArray(p.arguments)))) return { error: { code: -32602, message: "Invalid params: tools/call needs a string name and an object of arguments" } };
      return { result: await call(p.name, p.arguments) };
    }
    if (id === undefined) return null;                                   // a notification: no reply
    return { error: { code: -32601, message: "Method not found: " + m } };
  }
  return { handle, listTools, call, _st: st };
}

// stdio loop: one JSON-RPC message per line on stdin, replies on stdout, logs on stderr.
// Resolves once stdin has ended and every request in flight has been answered.
function serveStdio(server, input, output) {
  let buf = "", pending = 0, ended = false, done;
  const finished = new Promise((r) => { done = r; });
  const settle = () => { if (ended && !pending) done(); };
  const send = (o) => { try { output.write(JSON.stringify(o) + "\n"); } catch (_) {} };
  input.setEncoding("utf8");
  // one message -> its response object, or null (notification). A non-object (null, 5, "x") is an
  // Invalid Request; it used to throw inside the .catch and crash the server.
  const one = (msg) => {
    if (!msg || typeof msg !== "object" || Array.isArray(msg)) return Promise.resolve({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "Invalid Request" } });
    return Promise.resolve().then(() => server.handle(msg)).then((r) => r && msg.id !== undefined ? Object.assign({ jsonrpc: "2.0", id: msg.id }, r) : null,
      (e) => msg.id !== undefined ? { jsonrpc: "2.0", id: msg.id, error: { code: Number.isInteger(e && e.code) ? e.code : -32603, message: String(e && e.message || e) } } : null);
  };
  const line1 = (line) => {
    line = line.trim(); if (!line) return;
    let msg; try { msg = JSON.parse(line); } catch (_) { send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } }); return; }
    pending++;
    // a JSON-RPC batch (2025-03-26) gets one array reply; an all-notification batch gets none
    const p = !Array.isArray(msg) ? one(msg).then((r) => { if (r) send(r); })
      : !msg.length ? Promise.resolve(send({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "Invalid Request" } }))
      : Promise.all(msg.map(one)).then((rs) => { rs = rs.filter(Boolean); if (rs.length) send(rs); });
    p.finally(() => { pending--; settle(); });
  };
  input.on("data", (d) => {
    buf += d; let nl;
    while ((nl = buf.indexOf("\n")) >= 0) { const line = buf.slice(0, nl); buf = buf.slice(nl + 1); line1(line); }
  });
  input.on("end", () => { if (buf.trim()) line1(buf); buf = ""; ended = true; settle(); }); // a last message with no newline still counts
  return finished;
}

module.exports = { createServer, serveStdio, importSpecifiers, resolveSpec, relativize, syncEngines, engineRoot, resolveAccount, gatherFiles, shapeResult, resultText, toDeckFindings, jwtClaims, PROTOCOLS };

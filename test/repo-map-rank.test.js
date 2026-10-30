"use strict";
// Task-ranked repo map (lib/nexus/repo-map.js rankRepoMap / renderRanked): a task about a
// function must rank its file and its direct callers first, files in play pull their
// neighbours up, generic names do not dominate, and the render never exceeds its budget.
const { buildRepoMap, extractRefs, mentionsOf, pageRank, rankRepoMap, renderRanked, estTokens } = require("../lib/nexus/repo-map");

let pass = 0, fail = 0;
const ok = (name, cond) => { if (cond) pass++; else { fail++; console.log("  \x1b[31mFAIL\x1b[0m " + name); } };
const eq = (name, a, b) => ok(name + "  (" + JSON.stringify(a) + " === " + JSON.stringify(b) + ")", JSON.stringify(a) === JSON.stringify(b));
const group = (t) => console.log("\n\x1b[1m" + t + "\x1b[0m");

// A small app: billing/invoice.js defines computeInvoiceTotal, used by two callers; a big
// unrelated utility module defines generic names (get, list) that everything "uses".
const FIX = [
  { path: "src/billing/invoice.js", content: "function computeInvoiceTotal(lines) {\n  return lines.reduce((a, l) => a + applyTaxRate(l.amount), 0);\n}\nfunction formatInvoiceNumber(n) { return 'INV-' + n; }\nmodule.exports = { computeInvoiceTotal, formatInvoiceNumber };\n" },
  { path: "src/billing/tax.js", content: "function applyTaxRate(amount) { return amount * 1.2; }\nmodule.exports = { applyTaxRate };\n" },
  { path: "src/routes/checkout.js", content: "const { computeInvoiceTotal } = require('../billing/invoice');\nfunction handleCheckout(req) { return computeInvoiceTotal(req.lines); }\nmodule.exports = { handleCheckout };\n" },
  { path: "src/jobs/monthly.js", content: "const { computeInvoiceTotal, formatInvoiceNumber } = require('../billing/invoice');\nfunction runMonthlyBilling(accounts) { return accounts.map((a) => formatInvoiceNumber(a.id) + computeInvoiceTotal(a.lines)); }\n" },
  { path: "src/util/store.js", content: "function get(k) { return k; }\nfunction list() { return []; }\nfunction set(k, v) { return v; }\nmodule.exports = { get, list, set };\n" },
  { path: "src/ui/panel.js", content: "const s = require('../util/store');\nfunction renderUserPanel() { return s.get('a') + s.list().length + [1].map((x) => x).join(); }\nconst m = new Map(); m.get('x'); m.set('y', 1);\n" },
  { path: "src/ui/settings.js", content: "const s = require('../util/store');\nfunction renderSettingsPage() { return s.get('b') + s.list(); }\n" },
  { path: "src/auth/session.js", content: "function createSessionToken(user) { return user.id; }\nfunction verifySessionToken(t) { return !!t; }\nmodule.exports = { createSessionToken, verifySessionToken };\n" },
  { path: "src/routes/login.js", content: "const { createSessionToken } = require('../auth/session');\nfunction handleLogin(u) { return createSessionToken(u); }\n" },
];
const MAP = buildRepoMap(FIX, { refs: true, symbolsPerFile: 200 });
const topFiles = (r, n) => { const seen = []; for (const d of r.defs) { if (!seen.includes(d.path)) seen.push(d.path); if (seen.length >= n) break; } return seen; };

group("building blocks");
{
  const refs = extractRefs("const total = computeTotal(x); if (total) return computeTotal(y);");
  eq("refs count every use", refs.get("computeTotal"), 2);
  ok("keywords are not refs", !refs.has("return") && !refs.has("const"));
  const m = mentionsOf("fix `get` in computeInvoiceTotal, see src/billing/tax.js and the invoice rounding");
  ok("code-shaped words are identifiers", m.idents.has("computeInvoiceTotal"));
  ok("backticked words are identifiers", m.idents.has("get"));
  ok("plain English words are only weak hints", m.words.has("invoice") && !m.idents.has("invoice") && !m.idents.has("rounding"));
  ok("path-shaped words are paths", m.paths.has("src/billing/tax.js"));
  const r = pageRank(3, [{ from: 0, to: 1, w: 1 }, { from: 2, to: 1, w: 1 }], [1, 1, 1]);
  ok("pagerank: the node everything points to ranks first", r[1] > r[0] && r[1] > r[2]);
  ok("pagerank sums to 1", Math.abs(r.reduce((a, b) => a + b, 0) - 1) < 1e-6);
  const r2 = pageRank(3, [{ from: 0, to: 1, w: 1 }, { from: 2, to: 1, w: 1 }], [0, 0, 1]);
  ok("pagerank: restarting at a node lifts it", r2[2] > r[2]);
  eq("pagerank of nothing", pageRank(0, [], []), []);
}

group("task relevance");
{
  const r = rankRepoMap(MAP, { query: "computeInvoiceTotal returns the wrong total when tax is zero" });
  eq("the named function is the top definition", [r.defs[0].name, r.defs[0].path], ["computeInvoiceTotal", "src/billing/invoice.js"]);
  const top5 = topFiles(r, 5);
  ok("its file and both direct callers are in the top 5 files", ["src/billing/invoice.js", "src/routes/checkout.js", "src/jobs/monthly.js"].every((p) => top5.includes(p)));
  ok("what it calls (applyTaxRate) ranks above unrelated code", r.defs.findIndex((d) => d.name === "applyTaxRate") < r.defs.findIndex((d) => d.name === "createSessionToken"));
  const r2 = rankRepoMap(MAP, { query: "login sessions expire too early", focus: ["src/routes/login.js"] });
  eq("a file in play pulls up what it depends on", r2.defs[0].name, "createSessionToken");
  const r3 = rankRepoMap(MAP, { query: "look at src/billing/tax.js" });
  eq("a path in the message focuses that file", r3.defs[0].path, "src/billing/tax.js");
  const r4 = rankRepoMap(MAP, { query: "" });
  ok("generic names (get, list, set) do not top an unbiased map", !["get", "list", "set"].includes(r4.defs[0].name));
  ok("deterministic", JSON.stringify(rankRepoMap(MAP, { query: "x" })) === JSON.stringify(rankRepoMap(MAP, { query: "x" })));
  ok("a map built without refs still ranks (no edges)", rankRepoMap(buildRepoMap(FIX), { query: "computeInvoiceTotal" }).defs[0].name === "computeInvoiceTotal");
  eq("an empty map ranks to nothing", rankRepoMap(buildRepoMap([]), { query: "a" }).defs, []);
}

group("budget");
{
  const r = rankRepoMap(MAP, { query: "computeInvoiceTotal" });
  for (const tokens of [40, 60, 100, 300, 5000]) {
    const t = renderRanked(MAP, r, { tokens });
    ok("render fits " + tokens + " tokens (" + estTokens(t) + ")", estTokens(t) <= tokens);
  }
  const full = renderRanked(MAP, r, { tokens: 5000, minShare: 0 });
  ok("a big budget shows every definition", !/lower-ranked/.test(full) && r.defs.every((d) => full.includes(d.name + ":" + d.line) || full.includes(d.name + "*:" + d.line)));
  const small = renderRanked(MAP, r, { tokens: 60 });
  ok("a small budget keeps the top definition and says what it dropped", small.includes("computeInvoiceTotal:1") && /lower-ranked definitions not shown/.test(small));
  const floored = renderRanked(MAP, r, { tokens: 5000 });
  ok("near-zero definitions are dropped even when they would fit, and counted", estTokens(floored) <= estTokens(full) && /lower-ranked definitions not shown/.test(floored) === (floored !== full));
  eq("a budget too small for the header renders nothing", renderRanked(MAP, r, { tokens: 3 }), "");
  // Larger synthetic repo: still under budget and fast.
  const big = [];
  for (let i = 0; i < 800; i++) big.push({ path: "pkg/m" + i + ".js", content: "function handlerNumber" + i + "() { return handlerNumber" + ((i * 7) % 800) + "() + helperValue" + (i % 50) + "(); }\nfunction helperValue" + i + "() { return " + i + "; }\n" });
  const t0 = Date.now();
  const bm = buildRepoMap(big, { refs: true, symbolsPerFile: 200 });
  const br = rankRepoMap(bm, { query: "handlerNumber42 is slow" });
  const txt = renderRanked(bm, br, { tokens: 1024 });
  const ms = Date.now() - t0;
  ok("800 files build, rank and render in under 3s (" + ms + "ms)", ms < 3000);
  ok("800 files stay within 1024 tokens", estTokens(txt) <= 1024);
  eq("800 files: the named function still ranks first", br.defs[0].name, "handlerNumber42");
}

console.log("\n" + (fail ? "\x1b[31m" : "\x1b[32m") + pass + " passed, " + fail + " failed\x1b[0m  (ranked repo map)");
process.exit(fail ? 1 : 0);

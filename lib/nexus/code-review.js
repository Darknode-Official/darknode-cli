"use strict";
// /codereview: a multi-agent code review in the shape of Claude Code's /code-review.
//   1. resolve the target (uncommitted diff, branch, PR #, or a path) to one diff
//   2. fan out reviewer agents in parallel, each hunting one angle, JSON findings out
//   3. merge duplicates across reviewers
//   4. one verifier agent per candidate tries to disprove it (CONFIRMED/PLAUSIBLE/REJECTED)
//   5. rank most-severe first, cap per effort level, report; --fix / --comment act on it
// Everything here is pure (the git/gh runner and file reader are injected) so the
// pipeline is unit-tested; the Nexus TUI runs the agents.

const SEVERITY = ["critical", "high", "medium", "low"];
const VERDICTS = ["CONFIRMED", "PLAUSIBLE", "REJECTED"];

// Reviewer angles. Each reviewer gets exactly one so they don't all find the same thing.
const ANGLES = {
  correctness: { label: "logic", ask: "logic errors in what the change does: wrong or inverted conditions, wrong variable, off-by-one, wrong return value, broken control flow, a branch that can never run" },
  edges: { label: "edge cases", ask: "inputs and states the change mishandles: empty, null/undefined, zero, negative, very large, unicode, missing keys, error and early-return paths, partial failure halfway through" },
  state: { label: "state & resources", ask: "state, ordering and resources: races, async work not awaited or errors swallowed, stale caches, shared mutable state, listeners/timers/handles that leak, cleanup that never runs" },
  contracts: { label: "callers", ask: "callers and contracts: read the callers and callees of every changed function and find call sites the change breaks, changed return shapes or types, removed behavior something still relies on, config/schema mismatches" },
  security: { label: "security", ask: "security holes the change introduces or exposes: injection, path traversal, missing authorization, secret exposure, unsafe deserialization, SSRF, untrusted input reaching a dangerous sink" },
  tests: { label: "tests", ask: "tests in the change that cannot catch the bug they are named after: they would pass on the old code, assert nothing that can fail, or test a copy of the logic instead of the real code" },
  cleanup: { label: "cleanup", ask: "cleanups with identical behavior: logic an existing helper in this repo already does, needless repeated work on a hot path, code that is much simpler written another way. Use category reuse, simplification or efficiency", cleanup: true },
};

// low -> few high-confidence findings; max -> many, some uncertain (PLAUSIBLE kept).
const LEVELS = {
  low: { angles: ["correctness"], verify: false, plausible: false, max: 3 },
  medium: { angles: ["correctness", "edges"], verify: true, plausible: false, max: 5 },
  high: { angles: ["correctness", "edges", "state", "contracts"], verify: true, plausible: false, max: 8 },
  xhigh: { angles: ["correctness", "edges", "state", "contracts", "security", "cleanup"], verify: true, plausible: true, max: 12 },
  max: { angles: ["correctness", "edges", "state", "contracts", "security", "tests", "cleanup"], verify: true, plausible: true, max: 20 },
};
const LEVEL_NAMES = Object.keys(LEVELS);
const DEFAULT_LEVEL = "medium";

// parseArgs("high 42 --fix --max-findings 3", saved) -> options. The level is sticky:
// with none given, saved.level (the last one typed) is reused; same for --max-findings.
function parseArgs(argstr, saved) {
  saved = saved || {};
  const toks = String(argstr || "").trim().split(/\s+/).filter(Boolean);
  const o = { level: LEVELS[saved.level] ? saved.level : DEFAULT_LEVEL, levelGiven: false, target: "", fix: false, comment: false, maxFindings: saved.maxFindings == null ? null : saved.maxFindings, maxGiven: false, note: "", error: "" };
  const rest = [];
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i], low = t.toLowerCase();
    if (low === "--fix") o.fix = true;
    else if (low === "--comment") o.comment = true;
    else if (low === "--max-findings" || low.startsWith("--max-findings=")) {
      const v = low.includes("=") ? low.split("=")[1] : (toks[++i] || "").toLowerCase();
      if (v === "all") o.maxFindings = Infinity;
      else if (v === "default") o.maxFindings = null;
      else if (/^\d+$/.test(v) && +v > 0) o.maxFindings = +v;
      else { o.error = "--max-findings takes a number, all, or default"; return o; }
      o.maxGiven = true;
    }
    else if (/^--/.test(t)) { o.error = "unknown option " + t; return o; }
    else if (!rest.length && !o.levelGiven && (LEVELS[low] || low === "ultra")) {
      o.level = LEVELS[low] ? low : "max"; o.levelGiven = true;
      if (low === "ultra") o.note = "ultra runs in Claude Code's cloud; Nexus runs it here at max.";
    }
    else rest.push(t);
  }
  o.target = rest.join(" ");
  if (o.comment && !/^#?\d+$/.test(o.target)) o.error = "--comment posts to a GitHub pull request: /codereview <PR#> --comment";
  return o;
}

// --- diff helpers ---------------------------------------------------------
const cleanPath = (p) => String(p || "").trim().replace(/^["']|["']$/g, "").replace(/^(a|b)\//, "").replace(/^\.\//, "");

// files touched by a unified diff, in order.
function changedFiles(diff) {
  const out = []; const re = /^diff --git a\/(.+?) b\/(.+)$/gm; let m;
  while ((m = re.exec(String(diff || "")))) if (!out.includes(m[2])) out.push(m[2]);
  if (!out.length) { const re2 = /^\+\+\+ (?:b\/)?(.+)$/gm; while ((m = re2.exec(String(diff || "")))) if (m[1] !== "/dev/null" && !out.includes(m[1])) out.push(m[1]); }
  return out;
}

// split a unified diff into { file: its section }.
function fileSections(diff) {
  const out = {}; const parts = String(diff || "").split(/^(?=diff --git )/m);
  for (const p of parts) { const m = /^diff --git a\/(.+?) b\/(.+)$/m.exec(p); if (m) out[m[2]] = (out[m[2]] || "") + p; }
  return out;
}

// new-side line numbers each file's hunks cover (added + context), the lines a
// GitHub review comment may anchor to with side RIGHT.
function rightLines(diff) {
  const out = {}; let file = null, n = 0;
  for (const ln of String(diff || "").split("\n")) {
    let m;
    if ((m = /^diff --git a\/(.+?) b\/(.+)$/.exec(ln))) { file = m[2]; out[file] = out[file] || new Set(); n = 0; continue; }
    if ((m = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(ln))) { n = +m[1]; continue; }
    if (!file || !n) continue;
    if (ln.startsWith("+++") || ln.startsWith("---")) continue;
    if (ln.startsWith("+") || ln.startsWith(" ")) { out[file].add(n); n++; }
    else if (ln.startsWith("\\")) continue;
  }
  return out;
}

// an untracked text file as a "new file" diff section, so it is reviewed like any change.
function newFileDiff(file, text) {
  const lines = String(text).replace(/\n$/, "").split("\n");
  return "diff --git a/" + file + " b/" + file + "\nnew file mode 100644\n--- /dev/null\n+++ b/" + file + "\n@@ -0,0 +1," + lines.length + " @@\n" + lines.map((l) => "+" + l).join("\n") + "\n";
}

function clip(s, n) { s = String(s || ""); return s.length > n ? s.slice(0, n) + "\n... (truncated, " + (s.length - n) + " more chars; read the files for the rest)" : s; }

// --- target resolution ------------------------------------------------------
// run(cmd, args) -> Promise<{ code, stdout }>, exists(p) -> bool, read(p) -> string|null.
async function resolveTarget(target, io) {
  const run = io.run, git = (args) => run("git", args);
  const ok = (r) => r && r.code === 0;
  const inRepo = ok(await git(["rev-parse", "--is-inside-work-tree"]));
  const t = String(target || "").trim();
  if (/^#?\d+$/.test(t)) {
    const num = t.replace("#", "");
    const d = await run("gh", ["pr", "diff", num]);
    if (!ok(d)) return { error: "could not read pull request #" + num + " with gh (is gh installed and signed in, and is this the right repo?)" };
    const v = await run("gh", ["pr", "view", num, "--json", "headRefOid,title,url"]);
    let meta = {}; try { meta = JSON.parse(v.stdout); } catch (_) {}
    return { kind: "pr", pr: num, head: meta.headRefOid || "", label: "pull request #" + num + (meta.title ? " (" + meta.title + ")" : ""), diff: d.stdout };
  }
  if (t && io.exists(t)) {
    if (inRepo) { const d = await git(["diff", "HEAD", "--no-color", "--", t]); if (ok(d) && d.stdout.trim()) return { kind: "path", label: t + " (uncommitted changes)", diff: d.stdout }; }
    const txt = io.read(t);
    if (txt == null) return { error: t + " is a folder with no uncommitted changes; pass a file, or commit nothing yet and review its diff" };
    return { kind: "file", label: t + " (whole file)", diff: newFileDiff(cleanPath(t), txt), whole: true };
  }
  if (!inRepo) return { error: t ? "'" + t + "' is not a file here and this is not a git repo" : "/codereview needs a git repo, or pass a file: /codereview <file>" };
  const base = await defaultBranch(git);
  if (t) {
    if (!ok(await git(["rev-parse", "--verify", "--quiet", t + "^{commit}"]))) return { error: "'" + t + "' is not a file, branch, commit or PR number" };
    const cur = (await git(["rev-parse", "--abbrev-ref", "HEAD"])).stdout.trim();
    const from = t === base ? "HEAD" : t, against = t === base ? base : base || "HEAD~1";
    const mb = await git(["merge-base", against, from]);
    const d = await git(["diff", "--no-color", (ok(mb) ? mb.stdout.trim() : against) + ".." + from]);
    if (!ok(d) || !d.stdout.trim()) return { error: "no changes on " + (from === "HEAD" ? cur : t) + " compared with " + against };
    return { kind: "branch", label: (from === "HEAD" ? cur : t) + " vs " + against, diff: d.stdout };
  }
  // no target: uncommitted work first (tracked + untracked), then this branch's commits, then the last commit.
  let diff = (await git(["diff", "HEAD", "--no-color"])).stdout || "";
  const un = (await git(["ls-files", "--others", "--exclude-standard"])).stdout || "";
  for (const f of un.split("\n").map((s) => s.trim()).filter(Boolean).slice(0, 40)) { const txt = io.read(f); if (txt != null && txt.length < 200000 && !/\u0000/.test(txt)) diff += newFileDiff(f, txt); }
  if (diff.trim()) return { kind: "uncommitted", label: "uncommitted changes", diff };
  const cur = (await git(["rev-parse", "--abbrev-ref", "HEAD"])).stdout.trim();
  if (base && cur !== base && cur !== "HEAD") {
    const mb = await git(["merge-base", base, "HEAD"]);
    if (ok(mb)) { const d = await git(["diff", "--no-color", mb.stdout.trim() + "..HEAD"]); if (d.stdout && d.stdout.trim()) return { kind: "branch", label: cur + " vs " + base, diff: d.stdout }; }
  }
  const d = await git(["show", "--no-color", "--format=commit %H%n%n%s%n", "HEAD"]);
  if (ok(d) && /^diff --git /m.test(d.stdout)) return { kind: "commit", label: "the last commit", diff: d.stdout };
  return { error: "nothing to review: no uncommitted changes and no commits" };
}

async function defaultBranch(git) {
  const r = await git(["symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"]);
  if (r && r.code === 0 && r.stdout.trim()) return r.stdout.trim();
  for (const b of ["main", "master"]) { const v = await git(["rev-parse", "--verify", "--quiet", b]); if (v && v.code === 0) return b; }
  return "";
}

// --- prompts ------------------------------------------------------------------
const FINDING_SHAPE = '{"file":"path/relative/to/repo","line":123,"severity":"critical|high|medium|low","category":"correctness","summary":"one sentence: the defect","short_summary":"the claim in at most 60 chars","failure_scenario":"concrete inputs/state -> the wrong output or crash"}';

// opts: { angle, scope, diff, files, cap, context } -- context = extra file text for engines without file tools.
function buildReviewerPrompt(opts) {
  const a = ANGLES[opts.angle] || ANGLES.correctness;
  const files = opts.files || changedFiles(opts.diff);
  return [
    "You are one reviewer in a code review of " + opts.scope + ". Other reviewers cover other angles; you cover only this one:",
    "  " + a.ask + ".",
    "",
    "The diff is below. Read the changed files and enough surrounding code (callers, callees, types, tests) to be sure. Do not modify any file and do not run commands that change anything.",
    a.cleanup
      ? "Only report a cleanup when the behavior stays identical and the gain is clear. No style or naming opinions."
      : "Report only defects you can tie to concrete inputs or state that produce a wrong result, crash, hang, leak or hole. No style, naming, missing-comment or hypothetical-refactor notes. A problem that existed before the change and that the change does not touch is out of scope.",
    "Anchor each finding on the changed line (new-side line number) closest to the defect.",
    "",
    "Answer with ONLY a JSON array, no prose before or after, at most " + (opts.cap || 6) + " items, [] if you find nothing. Each item:",
    "  " + FINDING_SHAPE,
    "",
    "Changed files: " + files.join(", "),
    "--- DIFF ---",
    clip(opts.diff, opts.maxDiff || 60000),
    "--- END DIFF ---",
  ].concat(opts.context ? ["", "--- CURRENT CONTENTS OF CHANGED FILES ---", clip(opts.context, 40000), "--- END ---"] : []).join("\n");
}

function buildVerifyPrompt(f, opts) {
  return [
    "A reviewer of " + opts.scope + " reported this finding. Your job is to try to disprove it.",
    "",
    "  file: " + f.file + (f.line ? ":" + f.line : ""),
    "  claim: " + f.summary,
    "  failure scenario: " + f.failure_scenario,
    "",
    "Read the code at that location and everything that reaches it (callers, guards, types, config). Do not modify any file.",
    "  CONFIRMED  you traced the failure through the actual code: the inputs/state are reachable and the result is wrong.",
    "  PLAUSIBLE  the code really does this, but you could not prove the triggering input/state is reachable.",
    "  REJECTED   the code does not do this, it is handled elsewhere, it is intended, it predates the change and the change does not touch it, or it is only a style opinion.",
    "",
    "Answer with ONLY one JSON object, no prose: {\"verdict\":\"CONFIRMED|PLAUSIBLE|REJECTED\",\"severity\":\"critical|high|medium|low\",\"line\":123,\"reason\":\"one sentence\"}",
    "",
    "The change in that file:",
    clip(opts.section || "", 16000),
  ].concat(opts.context ? ["", "--- CURRENT CONTENTS OF " + f.file + " ---", clip(opts.context, 24000), "--- END ---"] : []).join("\n");
}

function buildFixPrompt(findings, scope) {
  return "Fix these verified findings from a code review of " + scope + ". Make minimal, surgical changes: change only what each fix needs, matching the surrounding code. Where the project has tests, add one per fix that fails on the old code, then run the tests.\n\n"
    + findings.map((f, i) => (i + 1) + ". " + f.file + (f.line ? ":" + f.line : "") + " [" + f.severity + "] " + f.summary + "\n   failure: " + f.failure_scenario).join("\n")
    + "\n\nWhen done, list each finding by number with its outcome: fixed, skipped (and why), or no_change_needed (and why).";
}

// --- parsing ------------------------------------------------------------------
// pull the first parseable JSON value of the wanted kind ("[" or "{") out of model text.
function extractJson(text, open) {
  const s = String(text || "").replace(/```(?:json)?/gi, "");
  const close = open === "[" ? "]" : "}";
  for (let start = s.indexOf(open); start >= 0; start = s.indexOf(open, start + 1)) {
    let depth = 0, inStr = false, esc = false;
    for (let i = start; i < s.length; i++) {
      const c = s[i];
      if (inStr) { if (esc) esc = false; else if (c === "\\") esc = true; else if (c === '"') inStr = false; continue; }
      if (c === '"') inStr = true;
      else if (c === "[" || c === "{") depth++;
      else if (c === "]" || c === "}") { depth--; if (depth === 0) { if (c !== close) break; try { return JSON.parse(s.slice(start, i + 1)); } catch (_) { break; } } }
    }
  }
  return undefined;
}

const normSev = (s) => { s = String(s || "").toLowerCase(); return SEVERITY.includes(s) ? s : s === "nit" || s === "info" ? "low" : s === "blocker" ? "critical" : "medium"; };

// reviewer text -> normalized findings (null if the reply had no JSON at all).
function parseFindings(text, angle) {
  let v = extractJson(text, "[");
  if (v === undefined) { const o = extractJson(text, "{"); if (o && Array.isArray(o.findings)) v = o.findings; }
  if (!Array.isArray(v)) return null;
  return v.filter((x) => x && typeof x === "object" && x.file && x.summary).map((x) => ({
    file: cleanPath(x.file).replace(/:(\d+)$/, ""),
    line: Math.max(0, parseInt(x.line, 10) || parseInt((/:(\d+)$/.exec(String(x.file)) || [])[1], 10) || 0),
    severity: normSev(x.severity),
    category: String(x.category || (ANGLES[angle] && ANGLES[angle].cleanup ? "simplification" : "correctness")).toLowerCase().replace(/[^a-z-]/g, "").slice(0, 40) || "correctness",
    summary: String(x.summary).trim().replace(/\s+/g, " "),
    short_summary: String(x.short_summary || x.summary).trim().replace(/\s+/g, " ").slice(0, 60),
    failure_scenario: String(x.failure_scenario || x.scenario || "").trim().replace(/\s+/g, " "),
    angles: [angle || "correctness"],
  }));
}

function parseVerdict(text) {
  const o = extractJson(text, "{");
  if (o && typeof o === "object") {
    const v = String(o.verdict || "").toUpperCase();
    if (VERDICTS.includes(v)) return { verdict: v, severity: o.severity ? normSev(o.severity) : null, line: parseInt(o.line, 10) || 0, reason: String(o.reason || "").trim() };
  }
  const m = /\b(CONFIRMED|PLAUSIBLE|REJECTED)\b/.exec(String(text || ""));
  return m ? { verdict: m[1], severity: null, line: 0, reason: "" } : null;
}

// --- merge, rank, report ----------------------------------------------------
const words = (s) => new Set(String(s).toLowerCase().match(/[a-z0-9_]{3,}/g) || []);
function similar(a, b) { const A = words(a), B = words(b); if (!A.size || !B.size) return 0; let n = 0; for (const w of A) if (B.has(w)) n++; return n / (A.size + B.size - n); }
const sevRank = (s) => { const i = SEVERITY.indexOf(s); return i < 0 ? SEVERITY.length : i; };

// the same defect found by two reviewers -> one finding (keeps the more severe copy).
function dedupe(findings) {
  const out = [];
  for (const f of findings) {
    const dup = out.find((g) => g.file === f.file && (f.line === g.line || (Math.abs(f.line - g.line) <= 3 && similar(f.summary, g.summary) >= 0.3) || similar(f.summary, g.summary) >= 0.6));
    if (!dup) { out.push(Object.assign({}, f, { angles: (f.angles || []).slice() })); continue; }
    for (const a of f.angles || []) if (!dup.angles.includes(a)) dup.angles.push(a);
    if (sevRank(f.severity) < sevRank(dup.severity)) Object.assign(dup, { severity: f.severity, summary: f.summary, short_summary: f.short_summary, failure_scenario: f.failure_scenario, line: f.line });
  }
  return out;
}

// keep CONFIRMED (+ PLAUSIBLE at levels that allow it; unverified at low), sort, cap.
function rank(findings, opts) {
  const keep = findings.filter((f) => f.verdict === "CONFIRMED" || (f.verdict === "PLAUSIBLE" && opts.plausible) || (!f.verdict && !opts.verify));
  keep.sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || (a.verdict === "PLAUSIBLE") - (b.verdict === "PLAUSIBLE") || (b.angles || []).length - (a.angles || []).length || a.file.localeCompare(b.file) || a.line - b.line);
  const cap = opts.max === Infinity ? keep.length : opts.max;
  return { shown: keep.slice(0, cap), hidden: Math.max(0, keep.length - cap) };
}

const ID = (s) => s;
// c = optional color fns { red, yellow, gray, bold, cyan, green }.
function formatReport(r, c) {
  c = Object.assign({ red: ID, yellow: ID, gray: ID, bold: ID, cyan: ID, green: ID }, c || {});
  const sevC = (s) => (s === "critical" || s === "high" ? c.red : s === "medium" ? c.yellow : c.gray)(s);
  const head = c.bold("code review") + c.gray("  " + r.level + " · " + r.label + " · " + r.reviewers + " reviewer" + (r.reviewers === 1 ? "" : "s") + " · " + r.candidates + " candidate" + (r.candidates === 1 ? "" : "s") + (r.verified ? " · " + r.verified + " verified" : "") + (r.rejected ? " · " + r.rejected + " rejected" : ""));
  const lines = [head];
  if (r.failedReviewers) lines.push(c.yellow(r.failedReviewers + " reviewer" + (r.failedReviewers === 1 ? "" : "s") + " gave no usable answer; coverage is partial."));
  if (!r.shown.length) { lines.push("", c.green("No issues found.") + c.gray(r.candidates ? " Every candidate was rejected on verification." : "")); return lines.join("\n"); }
  lines.push("");
  r.shown.forEach((f, i) => {
    lines.push(c.bold((i + 1) + ".") + " " + sevC(f.severity) + "  " + c.cyan(f.file + (f.line ? ":" + f.line : "")) + "  " + c.gray(f.category) + (f.verdict === "PLAUSIBLE" ? "  " + c.yellow("plausible") : f.verdict ? "" : "  " + c.gray("unverified")) + (f.outcome ? "  " + c.green(f.outcome) : ""));
    lines.push("   " + f.summary);
    if (f.failure_scenario) lines.push("   " + c.gray("failure: ") + f.failure_scenario);
    if (f.reason && f.verdict) lines.push("   " + c.gray("verified: " + f.reason));
  });
  if (r.hidden) lines.push("", c.gray(r.hidden + " more finding" + (r.hidden === 1 ? "" : "s") + " over the cap. /codereview --max-findings all shows every one."));
  return lines.join("\n");
}

// GitHub review payload: findings on a diff line become inline comments, the rest go in the body.
function buildPrReview(findings, diff, head) {
  const rl = rightLines(diff), comments = [], loose = [];
  for (const f of findings) {
    const txt = "**" + f.severity + "** " + f.summary + (f.failure_scenario ? "\n\nFailure: " + f.failure_scenario : "");
    if (f.line && rl[f.file] && rl[f.file].has(f.line)) comments.push({ path: f.file, line: f.line, side: "RIGHT", body: txt });
    else loose.push("- `" + f.file + (f.line ? ":" + f.line : "") + "` " + txt.replace(/\n\n/g, " "));
  }
  const body = "Code review: " + findings.length + " finding" + (findings.length === 1 ? "" : "s") + "." + (loose.length ? "\n\nOutside the diff:\n" + loose.join("\n") : "");
  return Object.assign({ event: "COMMENT", body, comments }, head ? { commit_id: head } : {});
}

// run tasks with at most n in flight; results keep input order.
async function pool(items, n, fn) {
  const out = new Array(items.length); let next = 0;
  const worker = async () => { while (next < items.length) { const i = next++; out[i] = await fn(items[i], i); } };
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, worker));
  return out;
}

module.exports = { SEVERITY, VERDICTS, ANGLES, LEVELS, LEVEL_NAMES, DEFAULT_LEVEL, parseArgs, changedFiles, fileSections, rightLines, newFileDiff, resolveTarget, buildReviewerPrompt, buildVerifyPrompt, buildFixPrompt, extractJson, parseFindings, parseVerdict, dedupe, rank, formatReport, buildPrReview, pool };

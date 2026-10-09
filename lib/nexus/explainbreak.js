"use strict";
// ================= explain-break: "git blame" for which of the agent's turns broke the test ==
// bisect answers "which turn broke it?" authoritatively, but it RE-RUNS the test once per probe —
// which costs time and only works when the checkpoints are still restorable and the test is
// deterministic. Very often you want the answer INSTANTLY and for free, the moment the final test
// comes back red, even if the test is flaky or the environment can't be rebuilt.
//
// `explain-break` does that statically: it reads the failing test output and the per-turn
// checkpoint timeline (which paths each turn changed, plus the turn's label) and CORRELATES them —
// the files and symbols the failure names against the files each turn touched — to rank the turns
// most likely responsible. No test is run; it's a heuristic "git blame for what the agent did".
// It pairs with bisect: explain-break gives an instant best-guess and points to bisect for proof.
//
// WHY NOVEL: test-failure triage tools blame COMMITS or lines of source (git blame, SZZ). This
// blames the AGENT'S OWN TURNS using Nexus's per-turn change timeline — attributing a red test to
// a step in the agent's trajectory, not to a VCS commit. The correlation core is pure and
// deterministic, so it unit-tests without a model, like loopguard/filestate/diagnose.
//
// The engine is pure: extractRefs(text) + scoreTurns(refs, turns) + explainBreak(text, turns).
// Reading the timeline and (optionally) running the test once to capture the failure live in the
// thin wiring entry (explainBreakTool).

// Words that look like identifiers but carry no attribution signal — kept out of symbol matching.
const STOP = new Set([
  "expected", "received", "actual", "error", "assert", "assertion", "equal", "equals", "true",
  "false", "null", "none", "undefined", "object", "array", "string", "number", "value", "test",
  "tests", "fail", "failed", "failing", "passed", "throw", "throws", "thrown", "function", "return",
  "const", "class", "import", "export", "module", "require", "line", "column", "stack", "trace",
  "traceback", "exception", "called", "with", "from", "this", "that", "self", "args", "kwargs",
  "should", "must", "does", "will", "have", "been", "when", "then", "else", "true", "while",
]);

// Pull the attribution signals out of a failing test's output: referenced file paths (with an
// optional :line), candidate symbol/identifier names, and (via diagnose) a failure category.
function extractRefs(text) {
  const t = String(text == null ? "" : text);
  const paths = [];
  const seenPath = new Set();
  // file-ish tokens: a dotted name with a code-ish extension, optional :line:col, optional dir(s).
  const pre = /(?:^|[\s("'`\[])([\w./@-]+\.(?:js|jsx|ts|tsx|mjs|cjs|py|go|rs|rb|java|kt|c|cc|cpp|h|hpp|cs|php|swift|json|yml|yaml|toml|sh))(?::(\d+))?(?::\d+)?/g;
  let m;
  while ((m = pre.exec(t))) {
    let p = m[1].replace(/\\/g, "/");
    if (/^https?:\/\//i.test(p)) continue;
    const key = p + ":" + (m[2] || "");
    if (seenPath.has(key)) continue;
    seenPath.add(key);
    paths.push({ path: p, base: p.split("/").pop(), line: m[2] ? parseInt(m[2], 10) : null });
  }
  // candidate symbols: identifiers >= 4 chars, not pure stopwords, not file bases already captured.
  const symbols = new Set();
  const bases = new Set(paths.map((p) => p.base.replace(/\.[^.]+$/, "").toLowerCase()));
  let s;
  const sre = /\b([A-Za-z_$][\w$]{3,})\b/g;
  while ((s = sre.exec(t))) {
    const w = s[1];
    const lw = w.toLowerCase();
    if (STOP.has(lw)) continue;
    if (bases.has(lw)) continue;
    symbols.add(w);
  }
  let category = null, keyLine = null;
  try { const d = require("./diagnose").diagnose(t, 1); if (d) { category = d.category; keyLine = d.line; } } catch (_) {}
  return { paths, symbols: Array.from(symbols), category, keyLine };
}

// Normalise a path for comparison: drop a leading ./, compare both full and basename.
function samePath(a, b) {
  a = String(a || "").replace(/\\/g, "/").replace(/^\.\//, "");
  b = String(b || "").replace(/\\/g, "/").replace(/^\.\//, "");
  if (a === b) return "exact";
  if (a.endsWith("/" + b) || b.endsWith("/" + a)) return "suffix";
  if (a.split("/").pop() === b.split("/").pop()) return "base";
  return null;
}

// Score each turn against the failure's references. turns: [{label, ts, paths:[...]}] in order.
// Returns a ranked array of suspects with the evidence that earned each its score.
function scoreTurns(refs, turns) {
  refs = refs || { paths: [], symbols: [] };
  turns = Array.isArray(turns) ? turns : [];
  const n = turns.length;
  const suspects = turns.map((turn, i) => {
    const tpaths = (turn.paths || []).map((p) => String(p));
    let score = 0;
    const reasons = [];
    // strongest signal: a file named in the failure was changed by this turn
    for (const ref of (refs.paths || [])) {
      for (const tp of tpaths) {
        const rel = samePath(ref.path, tp);
        if (rel === "exact" || rel === "suffix") { score += 100; reasons.push("changed " + tp + ", which the failure names" + (ref.line ? " (around line " + ref.line + ")" : "")); }
        else if (rel === "base") { score += 55; reasons.push("changed " + tp + " (same filename the failure references)"); }
      }
    }
    // weaker signal: a symbol the failure mentions appears in this turn's label or a changed path
    const hay = (String(turn.label || "") + " " + tpaths.join(" ")).toLowerCase();
    let symHits = 0;
    for (const sym of (refs.symbols || [])) {
      if (symHits >= 5) break;
      if (hay.includes(sym.toLowerCase())) { score += 12; symHits++; reasons.push("mentions \"" + sym + "\", which appears in the failure"); }
    }
    // recency tie-break: a later turn is marginally likelier to be the one that broke it
    const recency = n > 1 ? (i / (n - 1)) * 4 : 0;
    score += recency;
    return { index: i, turn: turn.label || "(turn " + i + ")", ts: turn.ts || null, paths: tpaths, score: Math.round(score * 10) / 10, reasons };
  });
  suspects.sort((a, b) => (b.score - a.score) || (b.index - a.index));
  return suspects;
}

// Pure top-level: parse the failure, score the turns, and shape a ranked verdict.
function explainBreak(failureText, turns) {
  const refs = extractRefs(failureText);
  const ranked = scoreTurns(refs, turns);
  const top = ranked[0];
  const hasSignal = top && top.score >= 50; // at least a filename-level correlation
  const result = {
    category: refs.category,
    keyLine: refs.keyLine,
    referencedPaths: refs.paths.map((p) => p.path + (p.line ? ":" + p.line : "")),
    referencedSymbols: refs.symbols.slice(0, 12),
    suspects: ranked.slice(0, 5),
    confident: !!hasSignal,
  };
  if (!turns || !turns.length) result.summary = "no recorded turn timeline to correlate the failure against (run some file-changing turns first).";
  else if (hasSignal) result.summary = "Most likely culprit: the turn \"" + top.turn + "\"" + (top.ts ? " (" + new Date(top.ts).toLocaleString() + ")" : "") + " — " + top.reasons[0] + ". Run `bisect` to confirm.";
  else result.summary = "No strong path/symbol overlap between the failure and any turn's changes — the failure may be environmental or indirect. Run `bisect` for an authoritative, test-driven answer.";
  return result;
}

// ---- thin wiring entry: get the failure text + the timeline, then correlate ----
// a.output / a.failure / a.error: the failing test output (preferred). If none is given and a
// test runner is injected, run the project's test once to capture a live failure. Reuses
// bisect's loadCheckpoints so there is one checkpoint-timeline format.
async function explainBreakTool(a, cwd, deps) {
  a = a || {};
  deps = deps || {};
  const loadCheckpoints = deps.loadCheckpoints || require("./bisect").loadCheckpoints;
  const turns = (deps.turns || loadCheckpoints(cwd, deps)) || [];
  let failureText = a.output || a.failure || a.error || a.text || "";
  let ran = null;
  if (!failureText) {
    const cmd = a.test || a.command || (deps.detectTest ? deps.detectTest() : null);
    if (cmd && typeof deps.runTest === "function") {
      const r = await deps.runTest(cmd);
      ran = cmd;
      if (r && r.code === 0) return { status: "passing", testCommand: cmd, summary: "'" + cmd + "' passes — there is no break to explain." };
      failureText = (r && r.output) || "";
    }
  }
  if (!failureText) return { error: "explain-break needs the failing test output — pass output:'<test output>' (or test:'<cmd>' to run and capture it)" };
  if (!turns.length) return { error: "no checkpoint timeline to attribute the failure to — .nexus/checkpoints.jsonl is empty; run some file-changing turns first" };
  const res = explainBreak(failureText, turns);
  if (ran) res.testCommand = ran;
  return res;
}

module.exports = {
  explainBreakTool, explainBreak, extractRefs, scoreTurns, samePath, STOP,
};

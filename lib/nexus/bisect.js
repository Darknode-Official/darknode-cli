"use strict";
// ================= bisect: regression bisect over the agent's OWN per-turn checkpoints =====
// Nexus already takes a non-destructive git-tree checkpoint BEFORE every file-changing turn (so
// /undo and /rewind can restore exactly the files a turn changed). That gives something git
// bisect can't see: a fine-grained, sub-commit timeline of the agent's work, one snapshot per
// turn. When a long autonomous run ends with the tests red, the operator is left asking "which
// of the agent's turns broke it?" — and re-reading a 30-step transcript is miserable.
//
// `bisect` binary-searches THAT timeline. It restores each probed checkpoint's file state (the
// union of every path the agent touched, so each probe is a clean, deterministic state), runs
// the project's own test command, and narrows good->bad to the exact turn that introduced the
// break — in ~log2(turns) test runs instead of re-running every turn. Then it restores the
// working tree to where it started, so the bisect leaves no trace. It is "git bisect below the
// commit level", over the agent's actions rather than over commits.
//
// WHY NOVEL: git bisect works over commits a human made; step-level agent bisect tools that
// exist (e.g. retrial) RE-EXECUTE the recorded run through the model at each probe, which is
// slow and non-deterministic. This bisects by RESTORING saved filesystem checkpoints and testing
// them — no model, no re-execution, fully deterministic — which is only possible because Nexus
// persists a per-turn tree snapshot. Pinpointing the culprit turn is "git blame for what the
// agent did".
//
// The valuable core is PURE + DETERMINISTIC and unit-tested with a synthetic oracle:
//   makeBisect / bisectRun   the classic good->bad boundary search driver
//   attributeCulprit         maps the boundary back to the turn (label + timestamp) responsible
// The git restore + test execution is injected (deps) so the orchestration tests with fakes,
// exactly like loopguard/filestate/diagnose/batch.

// ---- pure binary-search driver: find the boundary in a monotonic good...good,bad...bad run ----
// Invariant maintained by the caller's first two probes: index `lo` is GOOD, index `hi` is BAD.
// Each next()/record() pair probes the midpoint and halves the interval. Done when hi-lo<=1;
// firstBad === hi (the earliest BAD index). Deterministic: next() and record() agree on the mid.
function makeBisect(lo, hi) {
  lo = lo | 0; hi = hi | 0;
  const log = [];
  function mid() { return (lo + hi) >> 1; }
  function next() { return (hi - lo) <= 1 ? null : mid(); }
  function record(verdict) {
    const idx = mid();
    log.push({ index: idx, verdict });
    if (verdict === "bad") hi = idx; else lo = idx;
  }
  return { next, record, get firstBad() { return hi; }, get lo() { return lo; }, get hi() { return hi; }, get steps() { return log.length; }, log };
}

// ---- pure orchestrator: drive a bisect over `n` ordered states using an injected async probe ----
// probe(index) -> "good" | "bad". State 0 is expected GOOD (earliest checkpoint), state n-1 is the
// current (expected BAD) state. Returns a status plus the probe log. Handles the two degenerate
// cases explicitly: no regression (current is good) and bad-from-start (earliest is already bad).
async function bisectRun(n, probe) {
  n = n | 0;
  if (n < 2) return { status: "insufficient", reason: "need at least two states (one checkpoint plus the current state) to bisect", steps: 0, log: [] };
  const log = [];
  const first = await probe(0); log.push({ index: 0, verdict: first });
  if (first === "bad") return { status: "bad-from-start", firstBad: 0, steps: 1, log };
  const last = await probe(n - 1); log.push({ index: n - 1, verdict: last });
  if (last === "good") return { status: "no-regression", steps: 2, log };
  const b = makeBisect(0, n - 1);
  let idx;
  while ((idx = b.next()) !== null) {
    const v = await probe(idx);
    b.record(v);
    log.push({ index: idx, verdict: v });
  }
  return { status: "found", firstBad: b.firstBad, steps: log.length, log };
}

// ---- pure attribution: map the good->bad boundary back to the turn that caused it ----
// States are: checkpoints[0..m-1] (each the tree BEFORE that turn) plus the current state at
// index m. A boundary at firstBad=f means state f is the first bad one, so the turn that ran
// BETWEEN checkpoint f-1 and f is the culprit — i.e. the turn recorded at checkpoints[f-1].
function attributeCulprit(result, checkpoints) {
  checkpoints = Array.isArray(checkpoints) ? checkpoints : [];
  const m = checkpoints.length;
  if (!result || result.status === "insufficient") return { found: false, reason: (result && result.reason) || "insufficient data" };
  if (result.status === "no-regression") return { found: false, reason: "no regression — the test passes at the current state, nothing to bisect" };
  if (result.status === "bad-from-start") return { found: false, preExisting: true, reason: "the test already fails at the earliest recorded checkpoint — the break predates Nexus's timeline (not introduced by a recorded turn)" };
  const f = result.firstBad;
  const ci = f - 1; // the turn between checkpoint f-1 and f
  const cp = checkpoints[ci] || checkpoints[m - 1] || {};
  return {
    found: true,
    firstBadState: f,
    culpritCheckpoint: ci,
    turn: cp.label || "(turn " + ci + ")",
    ts: cp.ts || null,
    paths: cp.paths || [],
    reason: "the test first fails after the turn \"" + (cp.label || "(turn " + ci + ")") + "\"" + (cp.ts ? " (" + new Date(cp.ts).toLocaleString() + ")" : "") + (cp.paths && cp.paths.length ? ", which changed: " + cp.paths.slice(0, 6).join(", ") + (cp.paths.length > 6 ? " +" + (cp.paths.length - 6) + " more" : "") : ""),
  };
}

// ---- persistence: the per-turn checkpoint timeline, so a headless bisect can read it ----
// The in-memory /undo checkpoints vanish when the TUI exits; persisting {tree,label,ts,paths}
// lets `bisect` (and a future cross-session /rewind) reconstruct the timeline. Trees are loose
// git objects written by nexusCheckpoint and remain materialisable until git gc. Capped so the
// file can't grow without bound.
const MAX_PERSISTED = 500;
function persistCheckpoint(cwd, ck, deps) {
  deps = deps || {};
  const fs = deps.fs || require("fs");
  const path = deps.path || require("path");
  if (!ck || !ck.tree || !Array.isArray(ck.paths) || !ck.paths.length) return false; // only bisectable (path-scoped) checkpoints
  try {
    const dir = path.join(cwd, ".nexus");
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, "checkpoints.jsonl");
    const rec = { tree: ck.tree, label: String(ck.label || ""), ts: ck.ts || Date.now(), paths: ck.paths };
    fs.appendFileSync(file, JSON.stringify(rec) + "\n");
    // trim to the last MAX_PERSISTED lines if we've grown large
    try {
      const lines = fs.readFileSync(file, "utf8").trim().split("\n").filter(Boolean);
      if (lines.length > MAX_PERSISTED) fs.writeFileSync(file, lines.slice(-MAX_PERSISTED).join("\n") + "\n");
    } catch (_) {}
    return true;
  } catch (_) { return false; }
}
function loadCheckpoints(cwd, deps) {
  deps = deps || {};
  const fs = deps.fs || require("fs");
  const path = deps.path || require("path");
  try {
    const raw = fs.readFileSync(path.join(cwd, ".nexus", "checkpoints.jsonl"), "utf8");
    return raw.trim().split("\n").filter(Boolean).map((l) => { try { return JSON.parse(l); } catch (_) { return null; } }).filter((r) => r && r.tree && Array.isArray(r.paths));
  } catch (_) { return []; }
}

// ---- thin wiring entry: load the timeline, bisect it with real restore+test, restore back ----
// deps (injected by darknode.js, faked in tests):
//   restore(tree, paths) -> bool   materialise a checkpoint's file state (nexusRestore)
//   snapshot() -> treeHash         capture the current (bad) state so we can return to it
//   runTest(cmd) -> {code,output}  run the project's test command
//   detectTest() -> cmd|null       auto-detect the project's test command
//   loadCheckpoints() -> [...]     (optional) override the on-disk timeline (used by tests)
async function bisectTool(a, cwd, deps) {
  a = a || {};
  deps = deps || {};
  const checkpoints = (deps.loadCheckpoints ? deps.loadCheckpoints() : loadCheckpoints(cwd, deps)) || [];
  if (!checkpoints.length) return { error: "no checkpoint timeline to bisect — .nexus/checkpoints.jsonl is empty. Checkpoints are recorded as the agent changes files across turns; run some file-changing turns first." };
  const testCmd = a.test || a.command || (deps.detectTest ? deps.detectTest() : null);
  if (!testCmd) return { error: "no test command to bisect with — pass test:'<cmd>' (e.g. test:'npm test') or configure a detectable project test" };
  if (typeof deps.restore !== "function" || typeof deps.runTest !== "function") return { error: "bisect needs a git repo with checkpoint restore available" };

  // The union of every path any recorded turn touched: restoring this exact set to a given
  // checkpoint's tree reproduces the agent-relevant file state as of that turn, deterministically.
  const allPaths = Array.from(new Set([].concat.apply([], checkpoints.map((c) => c.paths || [])))).filter(Boolean);
  const snap = deps.snapshot ? deps.snapshot() : null; // current (bad) state to return to
  const m = checkpoints.length;             // states: 0..m-1 are checkpoints, m is "current"
  const classify = (r) => (r && r.code === 0 ? "good" : "bad");

  const probe = async (index) => {
    const tree = index < m ? checkpoints[index].tree : (snap || (checkpoints[m - 1] && checkpoints[m - 1].tree));
    deps.restore(tree, allPaths);
    const r = await deps.runTest(testCmd);
    return classify(r);
  };

  let result, err = null;
  try { result = await bisectRun(m + 1, probe); }
  catch (e) { err = (e && e.message) || String(e); }
  finally { if (snap) { try { deps.restore(snap, allPaths); } catch (_) {} } } // always return to where we started
  if (err) return { error: "bisect aborted: " + err + " — working tree restored to its starting state" };

  const culprit = attributeCulprit(result, checkpoints);
  const out = {
    status: result.status,
    testCommand: testCmd,
    checkpoints: m,
    testsRun: result.steps,
    probeLog: result.log,
    culprit,
    restored: !!snap,
  };
  out.summary = culprit.found
    ? "Regression isolated in " + result.steps + " test run(s) across " + m + " checkpoint(s): " + culprit.reason
    : (result.status === "no-regression" ? "No regression — '" + testCmd + "' passes at the current state." : culprit.reason) + " (" + result.steps + " test run(s))";
  return out;
}

module.exports = {
  bisectTool, bisectRun, makeBisect, attributeCulprit,
  persistCheckpoint, loadCheckpoints, MAX_PERSISTED,
};

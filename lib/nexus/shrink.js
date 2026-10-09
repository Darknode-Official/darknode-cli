"use strict";
// ================= shrink: delta-debug the agent's OWN edits to the minimal breaking subset ===
// bisect answers WHEN a break was introduced (which turn); explain-break guesses WHICH turn from
// static clues. Neither answers the question a reviewer actually acts on: of everything the agent
// changed, WHICH FILES are the ones that break the test? A long autonomous run can touch 20 files
// across 10 turns; the break usually lives in two of them, and the rest is noise the reviewer must
// wade through.
//
// `shrink` applies classic delta debugging (Zeller's ddmin) to the agent's own changes. The unit
// of change is one touched file. The baseline (earliest checkpoint) passes; the full set of
// changes (current working tree) fails. shrink searches for a 1-minimal subset: a set of changed
// files such that keeping JUST those at their new version (and reverting all the others to the
// baseline) still reproduces the failure, while dropping any one of them makes it pass. That
// minimal set is the real blast radius of the bug.
//
// This is only possible because Nexus can materialise an ARBITRARY mix of file versions on demand
// (path-scoped checkpoint restore): restore everything to the baseline tree, then restore just the
// subset to the current tree, and run the test. The working tree is returned to its starting state
// afterwards, so shrink leaves no trace.
//
// WHY NOVEL: delta debugging is a classic algorithm, but applying ddmin to isolate the minimal
// failure-inducing subset of an AI AGENT'S edits — using the agent's own checkpoint timeline as
// the version source — is not something shipped tooling does. It's complementary to bisect (time)
// and explain-break (static guess): shrink answers "which changes", with a proof by construction.
//
// Robustness: an arbitrary subset of edits may not build/apply and can fail with a DIFFERENT error
// than the real bug; ddmin must not mistake that for "still reproduces". The oracle therefore
// classifies three ways — pass / reproduces-the-same-failure / unresolved(different failure) — and
// only the same-signature failure counts as reproducing (same-signature matching reuses diagnose).
//
// The ddmin engine is pure, deterministic and memoised, and unit-tests with a synthetic oracle,
// exactly like loopguard/filestate/diagnose/bisect. The git restore + test execution is injected.

// ---- split an array into n roughly-equal contiguous chunks (ddmin's partitioning step) ----
function splitChunks(arr, n) {
  const chunks = [];
  const len = arr.length;
  const size = len / n;
  for (let i = 0; i < n; i++) {
    const a = Math.round(i * size), b = Math.round((i + 1) * size);
    const ch = arr.slice(a, b);
    if (ch.length) chunks.push(ch);
  }
  return chunks;
}

// Stable key for a subset so the oracle is memoised (order-independent).
function subsetKey(subset) { return subset.slice().sort().join("\u0000"); }

// ---- pure ddmin: minimise `units` to a 1-minimal subset that still makes `test` return "fail" ----
// test(subsetArray) -> "fail" | "pass" | "unresolved". Only "fail" counts as reproducing. Returns
// { minimal, tests, cacheSize }. Deterministic; the result is 1-minimal (removing any single unit
// from `minimal` would stop reproducing). Worst case O(n^2) tests, usually far fewer; memoised.
async function ddmin(units, test, opts) {
  opts = opts || {};
  const cache = new Map();
  let tests = 0;
  const run = async (subset) => {
    const k = subsetKey(subset);
    if (cache.has(k)) return cache.get(k);
    tests++;
    let v;
    try { v = await test(subset); } catch (_) { v = "unresolved"; }
    if (v !== "fail" && v !== "pass") v = "unresolved";
    cache.set(k, v);
    return v;
  };

  let cfail = units.slice();
  let n = 2;
  while (cfail.length >= 2) {
    const chunks = splitChunks(cfail, Math.min(n, cfail.length));
    let reduced = false;
    // 1) does any single chunk reproduce on its own? (reduce to it)
    for (const ch of chunks) {
      if ((await run(ch)) === "fail") { cfail = ch; n = 2; reduced = true; break; }
    }
    // 2) else does any complement (everything but one chunk) reproduce? (remove that chunk)
    if (!reduced) {
      for (const ch of chunks) {
        const inCh = new Set(ch);
        const comp = cfail.filter((x) => !inCh.has(x));
        if (comp.length && comp.length < cfail.length && (await run(comp)) === "fail") {
          cfail = comp; n = Math.max(n - 1, 2); reduced = true; break;
        }
      }
    }
    // 3) else increase granularity, or stop if we can't split finer
    if (!reduced) {
      if (n >= cfail.length) break;
      n = Math.min(2 * n, cfail.length);
    }
  }
  return { minimal: cfail, tests, cacheSize: cache.size };
}

// Do two failure diagnoses describe the SAME bug? (same category + overlapping key file/summary.)
// Used so an unrelated error from an invalid subset isn't mistaken for the original failure.
function sameFailure(a, b) {
  if (!a || !b) return !!(a || b) ? false : true; // if we couldn't diagnose either, be permissive
  if (a.category !== b.category) return false;
  const fa = (a.line || "").match(/[\w./-]+\.\w+/g) || [];
  const fb = (b.line || "").match(/[\w./-]+\.\w+/g) || [];
  if (fa.length && fb.length) return fa.some((f) => fb.includes(f));
  return true; // same category, no file hints to contradict
}

// ---- thin wiring: build the version-mixing oracle from checkpoints and run ddmin ----
// deps: loadCheckpoints(), restore(tree,paths), snapshot(), runTest(cmd), detectTest(),
//       diagnose(output,code,cmd) (optional; defaults to lib/nexus/diagnose).
async function shrinkTool(a, cwd, deps) {
  a = a || {};
  deps = deps || {};
  const diagnose = deps.diagnose || (function () { try { return require("./diagnose").diagnose; } catch (_) { return () => null; } })();
  const turns = (deps.loadCheckpoints ? deps.loadCheckpoints() : require("./bisect").loadCheckpoints(cwd, deps)) || [];
  if (!turns.length) return { error: "no checkpoint timeline to shrink — .nexus/checkpoints.jsonl is empty; run some file-changing turns first" };
  if (typeof deps.restore !== "function" || typeof deps.runTest !== "function") return { error: "shrink needs a git repo with checkpoint restore available" };

  const baselineTree = turns[0].tree;
  const allPaths = Array.from(new Set([].concat.apply([], turns.map((c) => c.paths || [])))).filter(Boolean);
  if (!allPaths.length) return { error: "the recorded turns changed no files — nothing to shrink" };
  const cap = a.max || 24;
  if (allPaths.length > cap) return { error: "too many changed files to delta-debug (" + allPaths.length + " > " + cap + ") — narrow it with paths:[...] or raise max; ddmin cost grows with the file count" };
  const testCmd = a.test || a.command || (deps.detectTest ? deps.detectTest() : null);
  if (!testCmd) return { error: "no test command to shrink with — pass test:'<cmd>' or configure a detectable project test" };

  const snap = deps.snapshot ? deps.snapshot() : null;      // current (failing) state to return to
  const restoreBack = () => { try { if (snap) deps.restore(snap, allPaths); } catch (_) {} };

  // Materialise the exact mixed state for a subset: everything at baseline, subset at current.
  const oracleRaw = async (subset) => {
    deps.restore(baselineTree, allPaths);
    if (subset.length) deps.restore(snap || (turns[turns.length - 1] && turns[turns.length - 1].tree), subset);
    return await deps.runTest(testCmd);
  };

  try {
    // Confirm the full set (current) reproduces, and capture the original failure signature.
    const full = await oracleRaw(allPaths);
    if (full && full.code === 0) { restoreBack(); return { status: "passing", testCommand: testCmd, summary: "'" + testCmd + "' passes at the current state — there is no break to shrink." }; }
    const origDiag = diagnose((full && full.output) || "", (full && full.code) || 1, testCmd);
    // Confirm the baseline (no changes) passes, else the break is pre-existing, not the agent's.
    const base = await oracleRaw([]);
    if (base && base.code !== 0) { restoreBack(); return { status: "pre-existing", testCommand: testCmd, summary: "the test already fails with none of the agent's changes applied — the break is pre-existing, not contained in this run's edits." }; }

    const test = async (subset) => {
      const r = await oracleRaw(subset);
      if (r && r.code === 0) return "pass";
      const d = diagnose((r && r.output) || "", (r && r.code) || 1, testCmd);
      return sameFailure(d, origDiag) ? "fail" : "unresolved";
    };

    const { minimal, tests } = await ddmin(allPaths, test, {});
    restoreBack();

    const removed = allPaths.filter((p) => !minimal.includes(p));
    return {
      status: "found",
      testCommand: testCmd,
      changedFiles: allPaths.length,
      minimal,
      innocent: removed,
      testsRun: tests,
      restored: !!snap,
      summary: "Minimal breaking change set (" + minimal.length + " of " + allPaths.length + " changed file(s), " + tests + " test run(s)): " + minimal.join(", ") + (removed.length ? ". The other " + removed.length + " changed file(s) are not needed to reproduce the failure and can be reviewed separately." : "."),
    };
  } catch (e) {
    restoreBack();
    return { error: "shrink aborted: " + ((e && e.message) || e) + " — working tree restored to its starting state" };
  }
}

module.exports = {
  shrinkTool, ddmin, splitChunks, subsetKey, sameFailure,
};

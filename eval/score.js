"use strict";
// NX-008 — deterministic scoring for the Nexus eval harness.
//
// Scoring is deterministic wherever possible (the brief's requirement): a coding
// task passes iff its verifier command exits 0; a security task is scored by
// true-/false-positive against ground truth. Human-judged axes (review quality)
// carry a rubric and are scored separately by raters, not here. All functions
// are pure so they are unit-tested without running a model.

// Score one run. task: the task spec. verify: the observed outcome
// ({code} for command tasks, {findings:[]} for finding tasks).
// -> a per-run score object; `pass` is the deterministic verdict.
function scoreRun(task, verify) {
  const t = task || {}, v = verify || {};
  if (t.type === "finding") {
    const got = new Set((v.findings || []).map(String));
    const truth = new Set((t.groundTruth || []).map(String));
    let tp = 0, fp = 0;
    for (const g of got) (truth.has(g) ? tp++ : fp++);
    const fn = [...truth].filter((x) => !got.has(x)).length;
    const precision = tp + fp ? tp / (tp + fp) : 1;
    const recall = tp + fn ? tp / (tp + fn) : 1;
    const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
    return { pass: fp === 0 && fn === 0, tp, fp, fn, precision, recall, f1 };
  }
  // Default: a command verifier. Exit 0 = pass (build succeeded, tests passed…).
  return { pass: v.code === 0, code: typeof v.code === "number" ? v.code : null };
}

function mean(xs) { return xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 0; }
function stat(xs) { const m = mean(xs); const varc = xs.length ? mean(xs.map((x) => (x - m) * (x - m))) : 0; return { mean: m, variance: varc, stdev: Math.sqrt(varc) }; }

// Aggregate many seeded runs of ONE task: pass-rate plus mean+variance of each
// cost/latency/token metric. A system that passes half the time is reported as
// 0.5 with its variance, never rounded to "works" (the brief's variance rule).
function aggregate(runs) {
  runs = runs || [];
  const n = runs.length;
  const passRate = n ? runs.filter((r) => r.score && r.score.pass).length / n : 0;
  const m = (k) => stat(runs.map((r) => (r.metrics && typeof r.metrics[k] === "number") ? r.metrics[k] : 0));
  // For finding tasks, average precision/recall across seeds too.
  const findingRuns = runs.filter((r) => r.score && typeof r.score.precision === "number");
  const fp = findingRuns.length ? {
    precision: stat(findingRuns.map((r) => r.score.precision)),
    recall: stat(findingRuns.map((r) => r.score.recall)),
    falsePositiveRate: 1 - mean(findingRuns.map((r) => r.score.precision)),
  } : null;
  return { n, passRate, cost: m("costUsd"), latencyMs: m("latencyMs"), tokens: m("tokens"), findings: fp };
}

module.exports = { scoreRun, aggregate, stat };

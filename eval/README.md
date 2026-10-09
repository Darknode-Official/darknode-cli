# Nexus Evaluation Harness (NX-008)

A deterministic, reproducible harness for measuring the Nexus agent loop and its
security capabilities. It is runnable by a third party from this document alone.

## Run it

```bash
# Exercise the full pipeline with no model (load -> score -> aggregate -> write):
node eval/harness.js --dry

# Real run against an engine (needs that engine installed/reachable):
node eval/harness.js --engine ollama
node eval/harness.js --engine claude --seeds 5        # 5 seeds -> variance
node eval/harness.js --task fix-failing-sum --seeds 3  # one task

# The held-out set — USE ONCE, at the very end (invalidates it afterwards):
node eval/harness.js --final
```

Results are written to `eval/results/<timestamp>.json` with, per task: every
seeded run's score and `{latencyMs, tokens, costUsd}` metrics, plus an aggregate
(`passRate` and mean+variance of each metric; precision/recall/FPR for finding
tasks). A gain that costs an order of magnitude more shows up in the cost field
and is reported as a separate finding, not folded into pass-rate.

## What it measures (axes)

One task set per axis, each task a JSON file in `eval/tasks/`:
feature-implementation, multi-file change, diagnosis-from-failing-trace,
long-horizon persistence, environment/tool operation, calibration, review
quality (rubric-scored), and each NX-005 security capability.

## Task schema

```json
{
  "id": "unique-id",
  "axis": "feature-implementation",
  "type": "command" | "finding",
  "provenance": "where this task came from",
  "contamination": "why it is not in any engine's training data",
  "setup": "bash that builds the sandbox repo",
  "prompt": "what the agent is asked to do",
  "verify": "bash; exit 0 = pass   (command tasks)",
  "groundTruth": ["kind:path", "…"]   // finding tasks
}
```

A task **without** `provenance` and a `contamination` argument is **excluded**
(unknown contamination status = excluded, per NX-008). Scoring is deterministic:
a command task passes iff `verify` exits 0; a finding task is scored by
true-/false-positive against `groundTruth`. Human-judged axes (review quality)
carry a written rubric, two raters, and reported agreement — scored outside this
file.

## Discipline

- **Development vs held-out.** Iterate only on `eval/tasks/`. `eval/held-out/` is
  read exactly once, by `--final`, to produce the reported number.
- **Seeds + variance.** Always report variance, not just the mean. A system that
  passes half the time is reported as 0.5 with its spread, never as "works".
- **Audit the scorer.** A sample of automated scores must be hand-audited and the
  disagreement rate reported (especially finding-label matching — see
  `sec-secret-detect.json`).

## Status

The harness, scorer, task schema, metrics, variance aggregation, and held-out
discipline are implemented and unit-tested (`test/run.js`, NX-008 group). **No
baseline has been produced yet** — that requires real engine runs and is the next
step; `--dry` proves the pipeline without a model and deliberately does not
fabricate pass-rates.

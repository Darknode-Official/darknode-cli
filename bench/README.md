# Nexus coding-agent benchmark

A small, honest, **objective** benchmark for coding agents. Every task is a tiny repo with a
`test.js`; an agent "passes" a task only by editing files until `node test.js` exits 0, in an
**isolated copy** — no opinion, no partial credit, no agent sees another's work.

The point: replace the claim "Nexus is better than Claude Code / Codex" with a *measurement*.

## What's here

- `tasks/<id>/` — one task each: `meta.json` (the prompt), `seed/` (the starting files incl.
  `test.js`), and `solution/` (a known-good fix, used ONLY by the self-test).
- `selftest.mjs` — proves each task is well-formed (fails on seed, passes with solution) and that
  the scorer is honest. Runs with no model. **Run this first.**
- `run.mjs` — runs the configured agents against the tasks and writes a report + per-run logs.
- `agents.json` — the agents to compare, as shell command templates.

## Run it

```sh
node bench/selftest.mjs          # validate the tasks + scorer (no model needed)
node bench/run.mjs               # run all ENABLED agents in agents.json
node bench/run.mjs --agents=nexus-local --tasks=fix-range   # a subset
node bench/run.mjs --timeout=300 # per-task seconds cap
```

Results land in `bench/results/<timestamp>/` (`report.md`, `results.json`, `logs/`).

## The agents (edit `agents.json`)

| agent | what it is | needs |
| --- | --- | --- |
| `nexus-local` | Nexus's OWN loop on a local Ollama model (offline, no key) | Ollama + a model. `DARKNODE_MODEL=qwen2.5-coder` to pin one |
| `nexus-claude` | Nexus orchestrating Claude Code (same model as Claude Code) | `claude` installed + authed |
| `claude-code` | plain Claude Code, no Nexus | `claude` installed + authed |
| `codex` | OpenAI Codex CLI, no Nexus | `codex` installed + authed |

Only `nexus-local` is enabled by default because it needs no network. The apples-to-apples
comparison for "is Nexus better than Claude Code" is **`nexus-claude` vs `claude-code`** — same
underlying model, so it measures what the *harness* adds (repo map, verify, guardrails), not the
model. Enable those two (set `"enabled": true`) on a machine where `claude` is authed and re-run.

## Honesty notes

- A small local model (e.g. an 8B) will fail most tasks — that is a real, expected result, not a
  harness bug. Use `qwen2.5-coder` or a frontier model via the API for a fair `nexus-local` score.
- The tasks here are deliberately small and deterministic (Node, no deps). They measure basic
  agentic competence — locate, edit precisely, verify — not large-repo reasoning. Add harder tasks
  by dropping a new folder in `tasks/` (seed + test.js + solution) and re-running `selftest.mjs`.
- Wall-clock depends on the machine and model; compare agents on the SAME machine in one run.

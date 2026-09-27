# Nexus overnight build log

Goal: make Nexus a best-in-class agentic coding agent (competitive with Claude Code, Codex,
Devin) by closing the concrete gaps in its *own* coding loop, while keeping its differentiators
(multi-engine orchestration, enterprise guardrails, git-worktree subagents, polished TUI).

Ground rules held throughout: every new capability lives in a pure, unit-tested `lib/nexus/*`
module with thin glue in `darknode.js`; the test suite must stay green; no capability ships that
can't be verified. Baseline before this work: **491 tests, 0 fail**.

## Shipped (all tested)

### Wave 1 — Codebase intelligence: repo map  (`lib/nexus/repo-map.js`)
Closes the biggest "codebase understanding" gap. Builds a ranked file tree + per-language symbol
outline (JS/TS, Python, Go, Rust, Java, C/C++, PHP, Ruby, shell) via forgiving regexes; ignores
`node_modules`/`dist`/lockfiles/binaries; filters language keywords out of the symbol lists.
- Auto-injected once per session to orient **every** engine (not just the local one) — previously
  only the local engine got any auto-context, and only via keyword overlap.
- `repo_map{}` tool + `/map` command (`/map on|off`). Cached per session, invalidated on writes.

### Wave 2 — Editing that doesn't fail  (`lib/nexus/edit.js`)
Was: a single literal find/replace. Now:
- `multi_edit{path,edits:[…]}` — several edits to one file, atomic (all-or-nothing).
- Whitespace/indentation-flexible matching as a **single-match-only** fallback (never guesses when
  ambiguous), re-indenting the replacement to the block it replaced.
- `apply_patch{patch}` — applies a unified diff, **anchoring on context** so drifted `@@` line
  numbers don't matter; multi-file, per-file policy + secret checks, workspace-escape guard.
- `edit_file` upgraded to use the flexible fallback and report when it did.

### Wave 3 — Verify-first execution  (`lib/nexus/verify.js`)
The edit→run→observe→fix half that was missing from the default loop.
- Detects the project's own commands (npm/yarn/pnpm/bun scripts, pytest, cargo, go, gradle, maven,
  make targets, rspec/rake) → `{test, build, lint, typecheck}`.
- `verify{kind?}` tool (agent self-checks its work before finishing) + `/verify` command.

### Wave 4 — Wired the orphaned code-intelligence modules
`code-radar`, `code-review-auto`, `code-diff-explain`, `smart-test` were well-written but never
required anywhere (dead code). Now surfaced as instant, no-LLM commands:
`/radar` (complexity + hotspot map), `/audit` (rule-based review of changed code),
`/diffexplain` (semantic diff summary), `/testgen <fn|file>` (test scaffold).

### Wave 5 — Symbol navigation  (`lib/nexus/repo-map.js` → `findSymbol`)
Agentic "go to definition" without an LSP: `find_symbol{name}` tool ranks exact defs first, then
case-insensitive, then substring. Reuses the Wave-1 map.

## Result
**550 tests, 0 fail** (59 new). New tools respect plan mode, the `.nexus/policy.json` guardrails,
the danger classifier, secret scanning, and the audit trail — same as the pre-existing tools.

## Deliberately deferred
- Native provider tool-calling (replace prompt-driven JSON for API models): the #1 reliability gap,
  but it rewrites the working local loop and can't be verified end-to-end without a live model, so
  it's held rather than shipped blind. Candidate for the next focused, model-in-the-loop session.

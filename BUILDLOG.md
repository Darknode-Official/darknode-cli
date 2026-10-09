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

### Wave 6 — Native (structured) tool-calling  (`lib/nexus/native-tools.js` + `ollama.js`)
The former #1 gap. The loop asked the model to emit `{thought,action,tool,args}` as TEXT and parsed
it (that is why `normalizeToolCall` exists — to recover mangled JSON). Capable providers do native
tool-calling: a guaranteed tool name + JSON-schema-checked args. Built and **verified end-to-end**:
- `native-tools.js` (pure, 20 unit tests): `TOOL_SCHEMAS` (JSON input schema per built-in tool) →
  `toAnthropicTools` / `toOpenAITools` / `toOllamaTools`; `parse{Anthropic,OpenAI,Ollama}Reply` +
  `normalizeReply` collapse every provider's reply into ONE `{text, toolCalls:[{id,name,args}], done}`
  shape (the same `{name,args}` the dispatch already runs); `*AssistantTurn` / `*ToolResult{s}`
  build the follow-up messages; `runNativeToolLoop({chat,dispatch,...})` is the whole
  edit→run→observe cycle, dependency-injected so it is unit-tested with a fake model.
- `ollama.js` → `ollamaChatNative(model, messages, tools, signal)`: same routing as `ollamaChat`
  (Ollama / OpenAI-compatible / Anthropic) but sends `tools` and returns the raw provider body +
  a provider tag for `normalizeReply`.
- **Live proof:** drove a real native tool call against the local qwen3 model (`darknode-13b`) —
  it emitted a structured `list_dir` call, the result was fed back as a native tool message, and it
  terminated. No text-JSON parsing anywhere in that path.

## Result
**570 tests, 0 fail** (79 new). New tools respect plan mode, the `.nexus/policy.json` guardrails,
the danger classifier, secret scanning, and the audit trail — same as the pre-existing tools.

## Remaining wiring for native tool-calling (one careful, provider-verified step)
The mechanism is built + tested; flipping the interactive loop (`darknode.js` ~2808) from the
prompt-driven path onto `ollamaChatNative` + `normalizeReply` is deliberately NOT done yet because
of one hard constraint that can only be verified against the strict APIs (unreachable from here):
- **1:1 pairing:** OpenAI and Anthropic reject the next request unless EVERY `tool_use` in an
  assistant turn has a matching `tool_result`. A native reply may contain several tool calls at
  once, but the current loop runs ONE per step. The wiring must run *all* of a reply's calls (each
  through the existing permission → plan → policy → danger → hooks → dispatch → audit chain, one
  card each) and append one assistant turn + all tool_results, before the next model turn.
- Suggested rollout: gate behind `NEXUS_NATIVE_TOOLS=1`, enable Ollama-local first (verified,
  lenient), then the strict API paths once a model-in-the-loop session confirms the pairing. The
  prompt-driven path stays as the fallback for models without tool support.

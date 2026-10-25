# Nexus — Complete Guide

Nexus is the AI coding agent inside Darknode CLI. It drives multiple AI engines
from one terminal interface: Claude, Gemini, Codex, OpenCode, Aider, and local
models via Ollama. This document explains every feature and how they work together.

> Every command and key, generated from the live command tables: [NEXUS-COMMANDS.md](NEXUS-COMMANDS.md) (`npm run docs` regenerates it). Inside Nexus, `/docs <words>` searches it, and the AI reads it automatically when you ask about Nexus itself.

---

## Starting Nexus

```bash
darknode nexus              # interactive TUI (full-screen terminal UI)
darknode nexus "fix the bug in auth.js"   # one-shot: do the task, print result, exit
darknode nexus -m opus      # start with a specific model
darknode nexus -y           # auto-approve all tool calls (no confirmation prompts)
darknode nexus --resume     # resume the last session
```

Aliases: `darknode code`, `darknode ai` — all launch Nexus.

---

## Engines

An engine is a backend AI that does the actual work. Switch anytime with `/engine`.

| Engine | Command | What it is | Cost |
|--------|---------|------------|------|
| **claude** | `/engine claude` | Claude Code CLI (rich streaming, tools, sub-agents) | Subscription or API |
| **gemini** | `/engine gemini` | Google Gemini CLI (1M context window) | API |
| **codex** | `/engine codex` | OpenAI Codex CLI (GPT-5, o4-mini) | API |
| **opencode** | `/engine opencode` | OpenCode — drives any provider you configure | API |
| **aider** | `/engine aider` | Aider — edit-focused, shows diffs | API |
| **ollama** | `/engine ollama` | Local models via Ollama — fully offline, free | Free |

Each engine has its own binary, install command, and supported models. Nexus
wraps them all behind the same interface: same slash commands, same TUI, same
cost tracking.

### Models

```
/model              show current model
/model opus         switch to Claude Opus
/model haiku        switch to Claude Haiku
/models             list all available models per engine (cloud tiers + local)
```

Cloud engines (Claude) support: `opus`, `sonnet`, `haiku`, `fable` (or full
names like `claude-opus-4-8`). Local engines list whatever you have pulled
(`ollama list`).

---

## The Agent Loop

When you give Nexus a task, the local agent loop works like this:

```
You: "add input validation to login.js"
  |
  v
System prompt (compressed, ~80 tokens) tells the model:
  - what tools are available
  - reply format: JSON with {thought, action, tool, args}
  - efficiency rules (minimize calls, chain commands)
  |
  v
Step 1: Model thinks, calls read_file{path: "login.js"}
  → File content returned (capped at 16K chars, 8K in lean mode)
  |
Step 2: Model thinks, calls edit_file{path, find, replace}
  → "ok" returned (not the whole file — saves tokens)
  |
Step 3: Model returns action:"final" with a summary
  → Done.
```

Key behaviors:
- **One action per step** — model calls one tool, reads the result, then decides next
- **Step limit** — 25 steps max (12 in lean mode) to prevent runaway loops
- **Thought stripping** — the model's reasoning is displayed to you but stripped from context history (saves ~50-200 tokens per step)
- **Compact results** — tool results are plain strings, not JSON objects (`"ok"` not `{"ok":true}`)
- **Ambiguity check** — `edit_file` errors if the find string matches multiple locations (prevents silent corruption)

### Tools Available

**Local agent** (Ollama engine):
`read_file`, `write_file`, `edit_file`, `list_dir`, `run_command`

**TUI agent** (extended tool set):
All of the above plus: `run_background`, `check_background`, `stop_background`,
`search`, `find`, `http_fetch`, `web_search`, `todo_write`, `sysinfo`,
`list_processes`, `make_dir`, `move`, `copy`, `delete`, `remember`, `discover`

**Claude engine**: uses Claude Code's native tools (Bash, Read, Edit, Write, etc.)

---

## Modes

Toggle with **Shift+Tab** in the TUI.

| Mode | What it does |
|------|-------------|
| **Normal** | Every tool call asks for your approval before running |
| **Auto-accept** | Tool calls run without asking (like `-y` flag) |
| **Plan** | Model outlines the work first, you approve, then it executes |

---

## Cost Saving

Nexus has a layered cost-saving system. Each feature is independent — stack them.

### /cowork — Two-Model Splitting

The biggest cost saver. Assigns a **strong** model (expensive, does real coding)
and a **weak** model (cheap or free, handles grunt work).

```
/cowork opus haiku                  Opus codes, Haiku does cheap tasks
/cowork opus ollama:qwen2.5-coder  Opus codes, local model does cheap tasks (FREE)
/cowork off                         single-model mode
```

**How it routes tasks:**

Every task hits a classifier (`isMechanical`):
- **Mechanical** → weak model: `run`, `test`, `lint`, `build`, `compile`,
  `commit`, `grep`, `find`, `read`, `diff`, `format`, `typecheck`, `install`
- **Not mechanical** → strong model: `implement`, `refactor`, `design`, `debug`,
  `fix`, `write`, `create`, `optimize`, `rewrite`

If the weak model is local (ollama:), mechanical tasks always go there — it's free.
If the weak model is a cheaper Claude tier, Nexus checks whether the token savings
outweigh the overhead of delegation before routing.

**Where cowork applies:**
- Main prompt → Claude gets `--model strong` and `--small weak`
- Sub-agents (`/agents`) → each sub-task individually classified
- Autonomous mode (`/plan`) → planning uses weak, tasks routed by type
- Auxiliary calls → commit messages, changelogs, dream mode use weak

### /lean — Minimal Output

```
/lean       toggle on/off
```

When on:
- Minimal output (no preamble, no recap)
- Agent steps capped at 12 per turn (vs 25)
- Tool output truncated to 8K chars
- `read_file` capped at 8K chars (vs 16K)
- `@file` inline capped at 3K chars (vs 6K)
- Per-turn output budget: 8K tokens (auto-stops)
- History pruned to last 4 messages (vs 6)
- Claude: `--max-turns 8`

### /cheap — Max Savings Preset

```
/cheap      enables lean + low effort in one command
```

Combines `/lean` + `/effort low`. For maximum savings, add a local coworker:
```
/cheap
/cowork opus ollama:qwen2.5-coder
```

### /effort — Thinking Level

```
/effort low       less thinking (mechanical work)
/effort medium    balanced
/effort high      deep reasoning (complex bugs)
```

Only applies to Claude engine (controls Claude's extended thinking).

### /budget — Hard Cost Cap

**Off by default (unlimited).** When off, no `--max-budget-usd` is sent to the
engine. Turn it on to cap spend; `/budget off` turns it back off.

```
/budget 5         cap session at $5 (saved)
/budget 0.50      cap at 50 cents
/budget off       remove the cap (unlimited — the default)
```

Enforced mid-turn — Claude stops if the budget would be exceeded. Your choice
is saved to `~/.nexus/settings.json` and restored next launch.

### Off-by-default limits & persistent settings

Every default that would *limit* your work ships **off**; turn on only what you
want. All toggles persist to `~/.nexus/settings.json` (atomic write) and reload
at launch. Precedence: an env var / CLI flag for this launch > the saved file >
the default.

| Setting | Default | Turn on | What it does when on |
| --- | --- | --- | --- |
| `budgetCap` | off | `/budget <n>` | hard spend cap (mid-turn) |
| `autoCompact` | off\* | `/settings autoCompact on` | aggressive compaction to save spend (claude at 40K, local at 60%) |
| `minimizeCalls` | off | `/settings minimizeCalls on` | adds the "2–5 tool calls" nudge to the system prompt |
| `stepCap` | off | `/settings stepCap on` | caps the native loop at 20 steps/turn |
| `trimOutput` | off | `/settings trimOutput on` | trims tool output / elides tool history outside lean mode |
| `cache` | off | `/cache on` | serves an exact-repeat read-only answer for free |
| `map` | off | `/map on` | auto-injects a repo map to orient the agent |

\* `autoCompact` off still performs the **minimal safe** compaction needed to
keep a request from failing when the real context window is nearly full (local
engines at ~90% of the window; claude near its real window) — that is
correctness, not a limit. The legacy `DARKNODE_COMPACT_AT` env still opts into
aggressive compaction at that token count. Protective safety features
(filestate stale-write guard, guard/redact/permission modes, loopguard) stay
**on** — they protect you, they don't limit you.

`/settings` lists every setting with its live value and whether it came from the
default, the saved file, or an env var.

### /estimate — Pre-Send Cost Check

```
/estimate refactor the auth module to use JWT
```

Shows rough token count and cost before you send the prompt.

### /fallback — Rate-Limit Recovery

```
/fallback haiku
```

If the primary model hits a rate limit, Nexus auto-retries on the fallback model.

### /impact — Session Receipt

```
/impact
```

Shows: local vs cloud turns, tokens used, cost, cowork delegations, cache hits,
and net savings.

---

## Multi-Engine Features

### /race — Run on All Engines

```
/race explain the auth flow
```

Sends the same prompt to every available engine simultaneously. Shows all answers
side by side so you can compare quality and speed.

### /ensemble — Best-of-All

```
/ensemble explain the auth flow
```

Like `/race`, but after collecting all answers, a synthesizer model combines
them into the single best answer.

### /bench — Speed Comparison

```
/bench explain the auth flow
```

Runs on each engine and reports a speed/tokens/cost comparison table.

---

## Code Features

### /agents — Parallel Sub-Agents

```
/agents fix auth ;; add tests ;; update docs
```

Splits work into parallel sub-agents. Each runs independently. With `/cowork`,
mechanical tasks (tests, builds) go to the weak model automatically.

### /plan — Autonomous Mode

```
/plan refactor the database layer
```

The AI breaks the goal into 5-15 concrete tasks, shows you the plan, then
executes each task sequentially. With `/cowork`, planning uses the weak model.

### /review — Code Review

```
/review              review staged changes
/review file.js      review a specific file
```

### /ultrareview — Deep Multi-Agent Review

```
/ultrareview         thorough review of the current branch
```

### /test — Run Tests

```
/test                run the project's test suite
```

### /commit — AI Commit Message

```
/commit              stage + commit with an AI-generated message
```

### /diff — Show Changes

```
/diff                git diff
/diff file.js        diff a specific file
```

### /undo / /redo — File Changes

```
/undo                revert the last file change
/redo                re-apply it
/rewind              show all checkpoints
/checkpoints         list saved states
```

Nexus tracks every file write/edit. Undo reverts the change and restores the
original content. Works per-file, not per-commit.

### /explain — Code Explanation

```
/explain auth.js     explain how auth.js works
```

### /blame — Git Blame

```
/blame file.js:42    who changed this line and why
```

---

## Context Management

### /compact — Compress History

```
/compact             summarize conversation, free context space
```

Auto-triggers at 60% context usage. Summarizes the conversation into a carry
note (1500 chars/message, 6000 total) and resets the message array.

### /context — Show Usage

```
/context             show context window % used
```

Warns at 50% usage.

### /clear — Full Reset

```
/clear               clear all messages, start fresh
```

### @file — Inline File Content

```
@auth.js fix the validation bug
```

Tab-completes file paths. Inlines the file content into your prompt (capped at
6K chars, 3K in lean mode).

### /pin — Persistent File Context

```
/pin auth.js         keep auth.js in context every turn
/unpin auth.js       remove it
/pins                list pinned files
```

### /index — Local RAG

```
/index               build a local search index of the project
```

Lets the local model auto-pull only relevant files instead of reading everything.

---

## Input Shortcuts

| Shortcut | What it does |
|----------|-------------|
| `@file` | Inline file content (Tab-completes) |
| `!cmd` | Run a shell command directly |
| `#note` | Save a note to memory |
| `\` at end of line | Continue on next line (multi-line input) |
| `Shift+Tab` | Cycle through modes (normal → auto-accept → plan) |
| `Ctrl+O` | Expand/collapse output |
| `Alt+Enter` / `Shift+Enter` / `Ctrl+J` | Insert a newline (so does `\` then Enter) |
| `Up/Down` | Move between lines, then step through history (typed draft preserved) |
| `Ctrl+R` | Reverse-i-search history (Ctrl+R again = older · Enter accept · Esc cancel) |
| `Home`/`End`, `Ctrl+A`/`Ctrl+E` | Start / end of the current line |
| `Ctrl+←/→`, `Alt+B`/`Alt+F` | Jump a word · `Alt+Backspace` deletes a word back |
| `Ctrl+W`/`Ctrl+U`/`Ctrl+K` | Kill word back / to start / to end (fills the kill-ring) |
| `Ctrl+Y` | Yank the last kill · `Ctrl+_` undo |
| `Ctrl+G` | Edit the message in `$EDITOR` · `Ctrl+L` redraw |
| `Esc` | Interrupt a running turn · `Esc Esc` (idle) clears the buffer |
| `Ctrl+C` | Interrupt / clear / again-to-exit · `Ctrl+D` exit on an empty line |
| `?` (empty buffer) | Show the keyboard help |
| `Wheel/PgUp/PgDn` | Scroll output |
| Paste | Multi-line kept; a large paste shows as `[Pasted text #N +X lines]`, expanded on send |
| `/` | Open command menu |

---

## Security & Policy

### /guard — Danger Classification

```
/guard               toggle danger guard on/off
```

When on, Nexus classifies every `run_command` call:
- **Safe**: `ls`, `cat`, `grep`, `git status` — runs normally
- **Warn**: `rm`, `git push` — asks for confirmation
- **Block**: `rm -rf /`, `fork bombs`, `:(){ :|:& };:` — blocked entirely

### /redact — Secret Masking

```
/redact              toggle — masks secrets in AI output
```

### /secrets — Scan for Leaks

```
/secrets             scan the project for exposed secrets
```

### /policy — Security Policy

```
/policy              show the active policy
```

Reads from `.nexus/policy.json`:
- `protectedPaths` — files the AI can never write/delete
- `deniedCommands` — blocked shell commands
- `maxFilesPerTurn` — limit on files changed per turn
- `blockSecrets` — prevent writing secrets to files
- `allowNetwork` — enable/disable network access
- `audit` — log all tool calls to `.nexus/audit.jsonl` (hash-chained)

Org-level policies (`~/.darknode/policy.json`) set a floor that local config
can only make stricter.

### /audit — Tool Call Log

```
/audit               show recent tool calls (timestamped, status, path/command)
/audit verify        verify the hash chain integrity
```

---

## Project Configuration

### .nexus/ Directory

```
.nexus/
  NEXUS.md          project instructions loaded every session (all engines)
  config.json       { engine, model }
  mcp.json          MCP servers: { mcpServers: { name: { command, args } } }
  hooks.json        shell hooks: UserPromptSubmit, PreToolUse, PostToolUse, Stop
  commands/*.md     custom /commands (body = prompt, $ARGUMENTS substituted)
  styles/*.md       custom output styles (used by /style)
  snippets.json     saved snippets (/snippet)
  plan.json         current plan state
  policy.json       security policy
  audit.jsonl       tool call audit trail (if enabled)
  index.json        local RAG index (if /index used)
  session.json      session state (auto-managed)
```

### Custom Commands

Create `.nexus/commands/review.md`:
```markdown
Review the code in $ARGUMENTS for bugs, security issues, and style problems.
Focus on correctness first, then performance.
```

Then use it: `/review auth.js`

### Custom Styles

Create `.nexus/styles/minimal.md`:
```
Reply in 1-3 sentences. No code blocks unless asked. No bullet points.
```

Then: `/style minimal`

### Hooks

`.nexus/hooks.json`:
```json
{
  "UserPromptSubmit": [{ "command": "echo 'Prompt: $NEXUS_PROMPT'" }],
  "PreToolUse": [{ "command": "echo 'Tool: $NEXUS_TOOL'" }],
  "PostToolUse": [],
  "Stop": []
}
```

Hooks run shell commands on events. If a hook exits non-zero, the action is blocked.

---

## Styles

```
/style concise       minimal responses
/style explanatory   detailed explanations
/style review        code review mode
/style tdd           test-driven development
/style secure        security-focused
/style teacher       educational, explains reasoning
/style default       reset
```

Styles inject a directive into the system prompt that shapes how the AI responds.
They apply to every engine. Add custom styles as `.nexus/styles/<name>.md`.

---

## Session Management

```
/status              engine, model, mode, cost, context %, active settings
/cost                current session cost breakdown
/export              export conversation to a file
/copy                copy last response to clipboard
/resume              resume previous session
/doctor              diagnose connection/config issues
/update              check for Darknode CLI updates
```

---

## Misc Commands

```
/changelog           generate a changelog from git history
/watch               watch files for changes and auto-run tasks
/dream               generate creative project ideas based on codebase
/gaps                find gaps in test coverage / documentation
/stats               project code statistics (languages, lines, largest files)
/deps                dependency audit
/env                 show environment variables relevant to the project
/todo                find TODO/FIXME/HACK markers across the codebase
/tree                project directory tree
/git                 git shortcuts (status, log, branch, etc.)
/recent              recently modified files
/keys                show configured API keys (masked)
/theme               change TUI color theme
/offline             toggle offline mode (local models only)
/notify              toggle desktop notifications on task completion
/scan                run security scans on the project
```

---

## Token Efficiency

Nexus is designed to minimize token usage without reducing capability:

1. **Compressed system prompts** — same instructions, ~40% fewer words
2. **Thought stripping** — model reasoning displayed but not kept in message history
3. **Plain string results** — `"ok"` not `{"ok":true}`, raw content not `{"content":"..."}`
4. **Tool efficiency directive** — system prompt tells the model to chain commands, read only needed lines, never re-read after write
5. **Safe auto-compaction** — off by default; still compacts to prevent a context-window overflow (local ~90%, claude near its real window). Opt into aggressive compaction with `/settings autoCompact on` (claude 40K, local 60%)
6. **Carry note limits** — 1500 chars/message, 6000 total after compaction
7. **Output truncation** — tool results capped at 8K chars

These are always active. `/lean` and `/cheap` add more aggressive caps on top.

---

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `DARKNODE_API_BASE` | OpenAI-compatible API endpoint (any provider) |
| `DARKNODE_API_KEY` | API key for the above |
| `DARKNODE_MODEL` | Override default local model |
| `DARKNODE_ANTHROPIC_KEY` | Direct Claude API key (bypasses Claude Code CLI) |
| `ANTHROPIC_API_KEY` | Alternative Claude API key |
| `OLLAMA_HOST` | Ollama host (default: 127.0.0.1) |
| `OLLAMA_PORT` | Ollama port (default: 11434) |
| `OLLAMA_TIMEOUT` | Model timeout in ms (default: 300000) |

Legacy `SENTINEL_*` variants are checked as fallbacks.

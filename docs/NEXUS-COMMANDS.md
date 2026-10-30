# Nexus reference

How Nexus works and every command it has. Generated from the live command tables — do not edit by hand.

## How it works

### What Nexus is

Nexus is a terminal AI coding agent (the `nexus` / `darknode nexus` command). It drives one of six engines behind one interface: claude (Claude Code), gemini, codex, opencode, aider, or ollama (local, free, offline). Switch with /engine, pick a model with /model.

Every engine gets the same slash commands, cost tracking, checkpoints and safety guard. Project instructions live in .nexus/NEXUS.md and are given to every engine.

### Sending, queueing, interrupting

Enter sends. While a turn is running, Enter QUEUES the prompt (shown as '· queued'); Ctrl+X or Ctrl+S sends it now and interrupts the current turn.

Esc interrupts a running turn. If nothing was produced yet, the prompt is put back in the composer to edit and resend.

Esc Esc (after a turn) rewinds: undoes that turn's file changes and puts the prompt back; /redo re-applies.

### Modes (Shift+Tab cycles)

normal / accept edits — the agent edits files and runs commands, subject to the /guard danger check and your /allow and /deny rules · plan — the prompt asks for a plan only and file/system-changing tools are blocked · bypass — also waives the destructive-command guard (use with care). The mode is remembered between sessions (bypass never is).

### Input prefixes

/command runs a Nexus command (type / to browse; Tab completes) · @path attaches a file or image (Tab completes) · !cmd runs a shell command and gives the output to the AI · #note saves a note to .nexus/NEXUS.md memory.

Pasting an image path or attaching one with @ shows 'attached N image(s)' and sends it to the model (needs a vision-capable model on local engines).

### Side panel and /btw (never added to the conversation)

/btw <question> asks a quick side question answered from the conversation so far. It opens a framed card and is NOT saved to the chat history.

/pager opens the newest tool output in full inside the TUI (the transcript only previews it): j/k or arrows scroll, space/b page, g/G jump to top/end, / searches (smart case), n/N step through matches, y copies everything shown, q closes. /pager 2 opens the one before; /pager answer pages the last answer. /less is the same command. While a shell command runs, its card shows the last lines it printed (Ctrl+O shows more), and /pager opens a snapshot of everything so far.

/find <text> searches the whole conversation — your prompts, every answer and every tool output — in the same pager, landing on the newest match; N steps to older matches, n to newer. /find alone opens the whole conversation at the end.

In the card: type a follow-up and press Enter to ask it · Enter or Esc on an empty field closes · Esc clears a typed follow-up · Left/Right step through earlier side answers · Up/Down, PgUp/PgDn and the mouse wheel scroll · Ctrl+Y copies the answer · Ctrl+X forgets all side questions. /btw with no question reopens the last one.

Read-only lookups open in the same card instantly, even mid-turn, without touching the chat: /activity /cheaper /compat /context /cost /docs /estimate /help /impact /keys /ledger /pins /recent /savings /session /stats /status /tokens /tree /turns /warm.

### Agents panel and agent conversations

Sub-agents (Claude Task agents, /agents a ;; b, local spawn_agents) appear in the agents panel under the prompt with status (running/done/failed/stopped) and time. Finished agents stay listed until you clear them.

Press Down on an empty prompt to focus the panel · Up/Down move · Enter, Right or a digit opens that agent · s stops a running agent · x clears finished agents · Esc returns to the prompt.

Opening an agent shows its full conversation like the main chat: its brief, its own messages, thinking and tool calls with results, and a live 'working' line while it runs. Up/Down, PgUp/PgDn, the wheel scroll · Home = its brief, End = latest · Left/Right switch agent · s stops it · Ctrl+Y copies its result · Esc (or Enter/q) goes back to the list with the same agent selected.

A Claude sub-agent's messages appear only in its own view, not in the main reply.

### Cost and tokens

The status bar shows context use and, on the claude engine, the prompt-cache countdown ('cache 4m'). /cost is exact list-price cost, /turns the per-turn ledger, /tokens the breakdown, /warm the cache countdown with warm-vs-cold follow-up cost, /cheaper lossless ways to spend less.

/cheap turns on lossless savings only (no quality loss). Limiting features (budget cap, auto-compact) are OFF by default; toggles you set are remembered in ~/.nexus/settings.json.

### Checkpoints and safety

A git checkpoint is taken before every file-changing turn: /undo, /redo, /rewind N, /checkpoints. Only files Nexus changed are restored.

File tools are confined to the project folder; secrets are blocked from being written; destructive shell commands are checked by /guard; .nexus/permissions.json holds allow/deny rules (/allow, /deny, /perms; a repo's own allow rules apply only after /trust) and .nexus/policy.json the security policy.

### Your own commands

/alias name = text|/cmd makes a shortcut (saved in ~/.nexus/settings.json) · /feature create <name> <what it does> adds a project command · .nexus/commands/*.md are custom /commands whose body is the prompt ($ARGUMENTS is substituted) · /commands lists them.

## All commands

- `/help` — commands, input prefixes & keys · /help <word> searches them (opens in the side panel)
- `/clear` — start a fresh chat
- `/chat-clear` — clear the screen, keep the conversation memory
- `/compact` — summarize & shrink the context
- `/trust` — trust this workspace's .nexus MCP servers, hooks + allow rules
- `/connect` — connect an AI: local model · Claude (API) · any provider
- `/context` — show token / context usage (opens in the side panel)
- `/cost` — session cost at exact list prices (opens in the side panel)
- `/turns` — per-turn cost ledger for this session (opens in the side panel)
- `/cheaper` — lossless ways to spend fewer tokens (opens in the side panel)
- `/warm` — prompt-cache countdown + warm-vs-cold follow-up cost (opens in the side panel)
- `/tokens` — estimate what @-attaching a file/dir costs (opens in the side panel)
- `/alias` — make a shortcut: /alias name = text|/cmd
- `/retry` — re-run your last prompt (fresh, no cache)
- `/pricing` — exact per-model prices (USD per million tokens)
- `/budget` — set a spend cap in USD
- `/report` — cost & usage report for chargeback (/report json|save|since <date>)
- `/compliance` — write a signed audit+usage compliance bundle (SOC2/review)
- `/undo` — revert the last turn's file changes
- `/rewind` — restore a specific checkpoint (/rewind N)
- `/checkpoints` — list undo checkpoints
- `/invariants` — diff-lint the pending diff against .nexus/invariants.json
- `/attest` — capability manifest from the hash-chained audit log
- `/bisect` — find the turn that broke the test (/bisect [test cmd])
- `/whatbroke` — instant blame: which turn most likely broke a failing test
- `/shrink` — delta-debug the edits to the minimal breaking file set (/shrink [test cmd])
- `/resume` — reload the last saved session
- `/branch` — fork & switch conversation branches (/branch new <name>)
- `/export` — save the conversation to markdown (/export <file> to pick where)
- `/copy` — copy the last reply to the clipboard
- `/status` — session engine, model, tokens & cost (opens in the side panel)
- `/session` — this session's uptime, files changed & tools used (opens in the side panel)
- `/doctor` — check engines & tools are available
- `/init` — scaffold .nexus/ in this project
- `/model` — pick the model — lists the engine catalog; /model <name|number>
- `/engine` — switch AI: claude · gemini · codex · opencode · aider · ollama
- `/commands` — list custom project commands
- `/agents` — run tasks in parallel: /agents a ;; b ;; c
- `/mcp` — list / connect MCP servers
- `/hooks` — show configured tool hooks
- `/race` — run a prompt on every engine at once
- `/review` — second opinion from a different engine
- `/codereview` — multi-agent bug review: parallel reviewers, each finding verified · /codereview [low|medium|high|xhigh|max] [file|branch|PR#] [--fix] [--comment] [--max-findings n|all]
- `/redo` — reapply an undone change
- `/ultrareview` — rigorous multi-lens review of the working diff (severity-ranked)
- `/changelog` — release notes from git history, grouped by type
- `/secrets` — scan the repo for leaked credentials
- `/scan` — quick TCP port scan of a host
- `/notify` — bell + desktop alert on long turns and questions · /notify on|off
- `/watch` — run a cmd; auto-fix & re-run until it passes
- `/commit` — AI commit message + commit the diff
- `/diff` — colored word-level diff · /diff <file> · /diff --staged
- `/pin` — keep a file in context every turn
- `/pins` — list pinned files (opens in the side panel)
- `/unpin` — remove a pinned file
- `/redact` — mask secrets before cloud sends
- `/ensemble` — all engines answer, then synthesize the best
- `/settings` — all options, neatly arranged (alias /options /config)
- `/jobs` — background commands the agent started (run_background)
- `/loop` — autonomous goal loop: /loop [-n rounds] <goal> until GOAL-DONE
- `/team` — multi-model workspace: architect + builder + reviewer, loops to PASS
- `/policy` — show the enterprise security policy (org + local)
- `/audit` — audited tool actions · /audit verify (tamper check)
- `/bench` — speed / tokens / cost table per engine
- `/explain` — explain the diff or a file in plain English
- `/test` — generate & run unit tests for a file
- `/refactor` — restructure code for clarity without changing behavior
- `/migrate` — migrate code: /migrate <from> to <to>
- `/pr` — AI-write a PR title+body from the diff and open it (gh)
- `/index` — index the repo for local auto-context
- `/map` — show the repo map (file+symbol outline); /map on|off
- `/verify` — detect + run this project's tests/build
- `/radar` — codebase complexity + hotspot map
- `/review-fast` — fast rule-based review of changed code (no AI)
- `/diffexplain` — explain the current git diff
- `/testgen` — scaffold tests for a function/file
- `/snippet` — save / use a prompt macro
- `/snippets` — list saved prompt macros
- `/plan` — make & run an editable task checklist
- `/git` — branch, status & recent commits
- `/blame` — who last changed a file's lines
- `/cowork` — strong model codes, weak model does cheap work
- `/cheap` — max token savings with ZERO quality loss (status · off)
- `/tight` — surgical edits — change only what differs (lossless)
- `/lean` — ask for minimal output (saves output tokens) · /lean on|off
- `/style` — output style: concise·explanatory·review·tdd·secure·teacher
- `/effort` — claude thinking level — interactive slider (or low|medium|high|xhigh|max|ultracode)
- `/estimate` — rough token/cost of a prompt before sending (opens in the side panel)
- `/fallback` — auto-switch model on rate-limit
- `/guard` — preflight destructive commands (enforce|warn|off)
- `/permissions` — allow/deny tool rules — /allow /deny <rule>
- `/impact` — session savings (tokens & cost avoided) (opens in the side panel)
- `/savings` — cross-session cost-savings analysis + 30d projection (opens in the side panel)
- `/cache` — serve exact-repeat read-only answers free (on/off/clear)
- `/models` — list cloud & local models
- `/api` — drive ANY model via an OpenAI-compatible API (OpenRouter, Groq, …)
- `/recent` — recently changed files (opens in the side panel)
- `/keys` — keyboard shortcuts (opens in the side panel)
- `/docs` — Nexus docs: /docs <topic> or /docs <words> to search every command & key (opens in the side panel)
- `/gaps` — list TODO/FIXME markers · /gaps plan
- `/dream` — consolidate the session into NEXUS.md memory
- `/tree` — show the project file tree (opens in the side panel)
- `/theme` — change the color theme
- `/color` — set the accent color · /color <name|0-255|#hex> · /color reset
- `/colors` — list accent colors
- `/gradient` — set the logo gradient · /gradient <theme|reset>
- `/mouse` — toggle mouse capture · /mouse off to select & copy text
- `/hack` — offensive-security mode — pentest/CTF persona + the Darknode toolkit
- `/pentest` — HYDRA — interactive AI-assisted penetration testing · /pentest <target>
- `/ai-prompt` — AI rewrites & sharpens your prompt, then loads it to edit/send
- `/offline` — local-only privacy lock · /offline on|off
- `/todo` — scan the project for TODO/FIXME/HACK markers (/todo <TAG> filters)
- `/stats` — codebase overview: files, lines & languages, largest files (opens in the side panel)
- `/deps` — dependency hygiene: unused + undeclared package imports
- `/env` — env-var audit: used-but-undocumented vs .env.example
- `/login` — sign in with Google or GitHub (Firebase)
- `/logout` — sign out of Nexus
- `/whoami` — show the signed-in account
- `/setup` — install Ollama + pull a local model
- `/restart` — save session, restart Nexus with latest code, resume where you left off
- `/update` — check for & install a newer Nexus (/update apply to install now)
- `/autoupdate` — auto-update on launch: /autoupdate on | check | off
- `/next` — queue a prompt after the current turn (Ctrl+X / Ctrl+S runs it now; clear / rm <n> to manage)
- `/btw` — side question — answered from context, never saved to history
- `/find` — search the whole conversation, tool output included: /find <text> (n/N step through matches, q closes)
- `/pager` — read the newest tool output in full: /pager [n] | answer (j/k, space, g/G, / search, q)
- `/compat` — which features this model supports (nothing is hidden) (opens in the side panel)
- `/mode` — capability preset: /mode power|cost|speed|reset (model-compatible only)
- `/god-prompt` — arm max-quality mode for your NEXT message only (gold border, auto-reverts)
- `/autocompact` — auto-shrink the context when it fills up · /autocompact auto|off|<amount>
- `/recap` — recap this session now · /recap [on|off] toggles the after-task recap
- `/title` — name the terminal tab for this session's topic · /title [text|on|off]
- `/feature` — add/remove your own commands: /feature create <name> <what it does> · /feature remove <name>
- `/open` — launch the live web dashboard in your browser
- `/dashboard` — start/stop the localhost web UI — live pipelines, jobs & cowork agents
- `/marketplace` — browse, install & publish agents, skills, hooks & pipelines
- `/cron` — scheduled pipeline runs — /cron add "0 9 * * *" <goal> · /cron list · /cron remove <id>
- `/expand` — toggle tool-call detail
- `/vim` — toggle vim modal editing in the input box · /vim on|off
- `/terminal-setup` — make Shift+Enter insert a newline (per-terminal setup) · /terminal-setup off
- `/exit` — quit Nexus

## Command groups (/help)

### Session

- `/clear` — start a new conversation
- `/chat-clear` — clear the screen but keep the conversation in memory
- `/compact` — summarize the conversation to free up context
- `/resume` — reload the last saved session
- `/export` — save the conversation to markdown (/export <file> to pick where)
- `/copy` — copy the last reply to the clipboard
- `/undo` — revert the last turn's file changes
- `/status` — engine, model, tokens & cost
- `/recap` — recap the session so far (/recap [on|off] for after-task recaps)
- `/title` — name the terminal tab for this topic (/title [text|on|off])
- `/exit` — quit Nexus

### Model & cost

- `/model` — pick the model (lists the catalog)
- `/engine` — switch AI backend
- `/effort` — thinking level: low … max | ultracode
- `/cost` — session cost at exact list prices
- `/budget` — set a spend cap in USD
- `/cheap` — max token savings, zero quality loss
- `/tight` — surgical minimal edits (lossless)
- `/cowork` — strong model codes, weak model assists
- `/impact` — tokens & cost you've saved

### Code & repo

- `/diff` — colored word-level diff of your changes
- `/commit` — write a commit message & commit
- `/review` — second opinion from another engine
- `/codereview` — parallel reviewers + a verifier per finding, ranked by severity (--fix applies, --comment posts to a PR)
- `/test` — generate & run tests for a file
- `/explain` — explain the diff or a file in plain English
- `/plan` — make & run an editable task checklist
- `/scan` — quick TCP port scan of a host
- `/secrets` — scan the repo for leaked credentials

### Extend

- `/feature` — add your own command: /feature create <name> <what it does>
- `/commands` — list your custom project commands
- `/open` — launch the live web dashboard in your browser
- `/dashboard` — start/stop the localhost web UI
- `/settings` — all options, neatly arranged
- `/theme` — change the color theme
- `/keys` — the full keyboard-shortcut list

### Input prefixes

- `/command` — run a command (type / to browse)
- `@file` — attach a file or image (Tab completes the path)
- `!command` — run a shell command (output goes to the AI)
- `#note` — save a note to memory

## Keyboard shortcuts (/keys)

### Send & edit

- `Enter` — send the message
- `Alt+Enter / Shift+Enter / Ctrl+J` — insert a newline
- `Home / End` — start / end of the line
- `Ctrl+A / Ctrl+E` — start / end of the line
- `Ctrl+← / → · Alt+B / F` — jump a word
- `Alt+Backspace · Ctrl+W` — delete the word before the cursor
- `Ctrl+U / Ctrl+K` — kill to start / end of line
- `Ctrl+Y` — yank back what was killed
- `Ctrl+_` — undo the last edit

### History

- `Ctrl+P / Ctrl+N` — previous / next command (your draft is kept)
- `Up / Down (while typing)` — step through history
- `Ctrl+R` — reverse-search history

### Session

- `Shift+Tab` — cycle mode: normal / accept edits / plan / bypass
- `Ctrl+O` — expand or collapse tool detail
- `Esc` — interrupt a running turn
- `Ctrl+X / Ctrl+S` — send a typed/queued prompt now (interrupts the current turn)
- `Esc Esc` — rewind: undo last turn's file changes + edit the prompt (/redo re-applies)
- `Esc Esc` — clear the input (idle)
- `Ctrl+C` — interrupt, then clear, then exit
- `Ctrl+D` — exit on an empty line
- `Ctrl+G` — edit the message in $EDITOR
- `Ctrl+L` — redraw the screen

### Scroll, select & copy

- `Mouse wheel` — scroll the transcript
- `Up / Down (empty input)` — scroll line by line
- `PgUp / PgDn` — scroll a page
- `Home` — jump to the oldest
- `End` — jump to the latest
- `Select with the mouse` — just drag to select, then copy — the mouse is yours by default
- `/mouse on` — re-enable click + wheel capture (selection then needs Shift+drag)

## Topic guides (/docs <topic>)

### Overview (`/docs overview`)

```
Nexus is a terminal AI coding agent built into the Darknode CLI. It drives one of six
engines from a single dependency-free binary:
  claude    — the Claude Code CLI in the cloud (strongest; needs `claude` installed + logged in)
  gemini · codex · opencode · aider — those vendors' CLIs, same interface
  ollama    — a free, private, local model on your machine (needs Ollama)

It reads & writes files, runs commands, checkpoints every change, shows real token cost
live, saves tokens by delegating cheap work to a weaker/local model, and keeps secrets off
the cloud. Launch it with `darknode nexus --tui`. Type / inside for the command menu.
```

### Quick start (`/docs quickstart`)

```
  darknode init                 scaffold .nexus/ (project context Nexus reads each session)
  darknode nexus --tui          full-screen agent (Claude if installed, else local)
  darknode nexus --tui -e ollama  drive a 100% local, private, free agent
  darknode nexus "add tests to server.js and run them"   one-shot task

Free local setup:
  curl -fsSL https://ollama.com/install.sh | sh
  ollama pull gpt-oss:20b      # fast local agent (~14GB); pull gpt-oss:120b for max power (~63GB)
```

### Engines & models (`/docs engines`)

```
  /engine <name>                   switch AI: claude · gemini · codex · opencode · aider · ollama
  /model [name]                    show/set the model
  /models                          list cloud tiers + installed local models
  /fallback <model>                auto-retry on a cheaper model when rate-limited
  /cowork <strong> <weak>          strong model codes; weak (cheaper Claude tier OR
                                   a free local model via ollama:<name>) does cheap work
  Aliases: opus · sonnet · haiku (or full ids like claude-opus-5-5)
```

### Saving cost (`/docs cost`)

```
In rough order of impact:
  /cowork opus ollama:qwen2.5-coder   free local worker does tests/builds/commit msgs
  /lean                               minimal output (output tokens cost the most)
  /effort low                         less thinking on mechanical work
  /index                              local model auto-pulls only relevant files
  /budget 5                           hard cap (also enforced mid-turn)
  /estimate <prompt>                  rough cost before you send
  /impact                             what you saved this session
  /cheap                              all lossless savers on, lossy ones off (no quality loss)
  /tight                              surgical edits — never rewrite a whole line (lossless)
```

### Multi-engine (`/docs multiengine`)

```
  /race <prompt>       every engine answers at once; keep the best (fastest marked)
  /ensemble <prompt>   every engine answers, then one synthesizes the single best
  /review [engine]     a different engine critiques the last answer
  /bench <prompt>      speed / tokens / cost table per engine (read-only)
```

### Build & verify (`/docs build`)

```
  /plan <goal>         editable checklist (/plan run · /plan add · /plan done N)
  /watch <cmd>         run a command; auto-fix the code and re-run until it passes
  /test <file>         generate + run unit tests
  /agents a ;; b ;; c  run independent tasks in parallel (each in an isolated git worktree)
```

### Git & checkpoints (`/docs git`)

```
A git checkpoint is taken before every file-changing turn.
  /undo /redo /rewind N   restore only the files Nexus changed (unrelated edits kept)
  /diff /git /blame /recent  session diff · status+log · line authorship · recent files
  /commit                    AI commit message + commit
```

### Safety & privacy (`/docs safety`)

```
  /guard enforce|warn|off  preflight destructive shell commands (rm -rf, dd, pipe-to-shell…)
  /secrets                 scan the repo for leaked credentials
  /scan <host>             quick TCP port scan
  /redact                  mask secrets before anything is sent to a cloud engine
  /offline                 local-only lock — nothing leaves the machine
```

### Context (`/docs context`)

```
  @file        inline a file into your message (Tab completes the path)
  !cmd         run a shell command inline
  #note        save a durable memory to .nexus/NEXUS.md
  /pin <file>  keep a file in context every turn
  /tree        project file tree
  /index       build a keyword index for local auto-context
  /compact /context   shrink & inspect the context window
  \ + Enter    continue on a new line
```

### Session (`/docs session`)

```
  /resume      reload the last saved session (.nexus/session.json)
  /export      write the conversation to a markdown file
  /copy        copy the last reply to the clipboard
  /dream       consolidate the session into NEXUS.md memory
  /gaps        list TODO/FIXME/HACK markers (/gaps plan → checklist)
  /status /doctor /impact   session status · health · savings receipt
```

### Keyboard (`/docs keys`)

```
  Enter          send        \ then Enter   newline
  Shift+Tab      cycle mode (normal / accept edits / plan / bypass)
  Ctrl+O         expand tool detail
  Ctrl+C         stop the current turn (again to quit)
  Up / Down      input history      Tab   complete /command or @path
  wheel · PgUp/PgDn · Home/End   scroll
```

### Project config (.nexus/) (`/docs config`)

```
  NEXUS.md        project instructions loaded every session (given to ALL engines)
  config.json     { engine, model }
  mcp.json        MCP servers: { mcpServers: { name: { command, args } } }
  hooks.json      shell hooks: UserPromptSubmit · PreToolUse · PostToolUse · Stop
  commands/*.md   custom /commands (body = prompt, $ARGUMENTS substituted)
  snippets.json · plan.json · index.json · session.json   (auto-managed; gitignored)
```

### Environment (`/docs env`)

```
  DARKNODE_MODEL   default local model for the ollama engine
  OLLAMA_HOST / OLLAMA_PORT   point at a remote Ollama (default 127.0.0.1:11434)
  OLLAMA_TIMEOUT   local request timeout ms (default 300000)
  OLLAMA_NUM_CTX   local context window in tokens (default 16384; more = more memory)
  NO_COLOR=1       disable colored output
```

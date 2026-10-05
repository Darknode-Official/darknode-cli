# Nexus Runtime — Architecture

> Accurate as of 2026-10-04 against branch `feat/nexus-coding-agent`. Every claim
> below is anchored to a file and line. If the tree and this document disagree,
> the tree is right and this document is the bug (see NX-001). Counts were taken
> with `find … -name '*.js'` and `grep -c`; they are reproduced in §9.

Nexus is the agent runtime behind the DarkNode product line. It ships as the
`darknode` CLI (the binary is also installed as `nexus`). It is a dependency-free
Node program: a single-file **host** plus **extracted pure libraries**.

- **Product name:** Nexus. **Package:** `darknode-cli` (v2.45.0). **Bins:**
  `darknode` and `nexus`, both → `darknode.js` (`package.json` `bin`).
- **Active entry point:** `darknode.js` (`package.json` `main`), ~4200 lines.
- **Legacy:** `darknode-legacy.js` is the pre-extraction security console. It is
  **not** the active runtime; it is retained only in `package.json` `files[]`.
  Do not reason about current behaviour from it. (It still carries a stale
  `darknode-b4194` Firebase project id at `darknode-legacy.js:1063`; the live
  project is `sentinel-b4194`, `darknode.js:1160`.)

## 1. Entry point & dispatch

Process entry is at the bottom of `darknode.js` (~`:4175`):

- `const args = process.argv.slice(2)` (`:4175`).
- Binary name is detected via `path.basename(process.argv[1])` (`:4196`). If
  invoked as `nexus`, it goes straight to the TUI: `cli(["nexus","--tui"])`
  (`:4197`). In engagement mode the interactive menu is refused (`:4198`).
- Otherwise `cli(args)` (`:4202`).

Dispatch is two-stage:

1. `async function cli(args)` (`:815`) — handles `authz` early (`:817`), then
   checks `DARKNODE_ENGAGEMENT`: when set, **every** command is routed through the
   fail-closed engagement gate's allow-list (`:816-829`); otherwise it falls
   through to `cliRun(args)`.
2. `async function cliRun(args, gate)` (`:831`) — the real command table. It
   tries the data-driven registry first (`if (CMD_MAP[cmd])`, `:833`,
   `lib/cli/registry.js`), then a long `else if (cmd === …)` chain. Unmatched →
   `usage()` (`:1122`).

Top-level commands (branch → line): `scan` 834, `dns` 835, `whois` 836,
`headers` 837, `cert` 838, `subs` 839, `nmap` 840, `nuclei` 841, `hashcat` 842,
`subrecon` 843, `cve` 844, `fuzz` 845, `git` 846, `totp` 867, `hash` 868,
`lab` 869, `update` 870, `payloads` 875, `genpass` 876, `myip` 877, `ipinfo` 878,
`hashfile` 879, `api` 880, `serve` 899, `listen` 900, `tools` 901, `setup` 902,
`init` 903, `docs`/`doc`/`help` 904, `login` 905, `logout` 913, `whoami` 914,
`policy` 915, `audit` 921, `report` 925, `savings` 936, `changelog` 948,
`env` 958, `deps` 973, `stats`/`loc` 989, `guard` 1000, `capindex`/`capmap`/`caps`
1021, `todo`/`todos` 1042, `compliance` 1054, `marketplace` 1072, `cron` 1082,
`doctor` 1089, and the agent itself `nexus`/`code`/`ai` 1106.

The **agent** is the `nexus` branch (`:1106-1121`): subcommands `init`, `docs`,
`setup`, `login`, `run`/`supervise`/`loop` → `nexusRun()`, `overnight`,
`agents`/`parallel` → `nexusAgents()`, default → `aiCoder()` (interactive TUI).

## 2. The agent loop

Five loops share one pattern: the model emits one JSON action per step
`{thought, action:"tool"|"final", tool, args}`; a tool runs; its **real** result
is appended as the next observation. Observations are never assumed.

- **A — interactive TUI turn (primary).** `darknode.js:2935`. `stepLimit` = 20
  (12 in `lean`, `:2933`). Stops on `action:"final"` (`:2943`), ctrl-c, a lean
  per-turn 8K-token budget (`:2937`), or the step ceiling. `run_command`
  observations are the real `{code, output}` from `coderShell` (`:2981`);
  `verify` runs the project's own tests and reports `ok: r.code === 0` (`:2990`).
  A "do real work first" nudge (≤2) blocks premature `final` (`:2943`).
- **B — compact sub-agent `ollamaExec`.** `:2046`, 15-step cap (`:2050`); used by
  `spawn_agents`, `nexus run`, `/loop`, `/team`; `classifyDanger` inline (`:2064`).
- **C — headless one-shot in `aiCoder`.** `:1574`, 25-step cap (12 lean).
- **D — provider-agnostic native tool loop.** `lib/nexus/native-tools.js:155`,
  `maxSteps` default 20 (`:158`); dependency-injected (`chat`, `dispatch`,
  `shouldStop`); returns `{finalText, calls, steps, stopped, hitLimit}` (`:182`);
  stops when the model returns no tool calls (`:168`).
- **E — multi-level plan→execute→verify `nexusRun`.** `:2109`. `planGoal()`
  decomposes (`:2153`); `while (true)` picks the next undone task (`:2162`),
  executes, then **verifies** with `verifyTask()` (`:2179`); `maxTries` 1 (3 with
  `--overnight`); a `--until` wall-clock deadline is a time budget (`:2165`);
  state persisted to `.nexus/run.json`.
- **F — pure goal controller.** `lib/nexus/loop.js`: `loopDecision` stops on a
  trailing `GOAL-DONE` token or `round >= maxRounds`; `clampRounds` → 1..20,
  default 6.

**Stop conditions in one place:** model-signalled completion, step ceilings
(12/15/20/25), a lean per-turn token budget, an optional session cost cap
(`costCap`, `/budget` `:3442`), and a run-level `--until` wall-clock budget.

## 3. Engine abstraction

One registry, one entry per backend: `lib/nexus/engines.js`, `ENGINES` (`:8`).
Each entry declares `label, bin, install, kind, paid, ctx, model, models, caps,
args(prompt,opts), tips`. `args(prompt,opts)` is the **only** place an engine's
CLI flags are built (`:2-7`) — this is the engine-isolation invariant (§7).

`kind` selects the driver: `"stream"` (Claude Code NDJSON), `"cli"` (spawn + read
stdout), `"local"` (in-process Ollama / OpenAI-compatible / native Anthropic loop).

Six engines (`ENGINE_ORDER`, `:45`): `claude` (stream, paid), `gemini` (cli),
`codex` (cli), `opencode` (cli), `aider` (cli), `ollama` (local, free). Adding an
engine = adding one entry. `engineAvail` (`darknode.js:2210`) treats `local` as
always available, else checks `hasBin`.

The `local` engine (`lib/nexus/ollama.js`, `ollamaChat` `:75`) fans out three ways:
- **Local Ollama** at `127.0.0.1:11434` (`HOST()`/`PORT()` `:9-10`, POST `/api/chat`
  `:81`; overridable via `OLLAMA_HOST`/`OLLAMA_PORT`).
- **Any OpenAI-compatible endpoint** when `DARKNODE_API_BASE`/`OPENAI_BASE_URL` set
  (`openaiCompatChat` `:18`).
- **Native Anthropic Messages API** for `claude-*` ids when `ANTHROPIC_API_KEY`
  present (`anthropicChat` `:50-72`) — an API-key path distinct from the `claude`
  CLI engine.

Model selection: `pickCoderModel` (`:148`) / `ensureCoderModel` (`:175`) auto-pulls
`qwen2.5-coder` (`DEFAULT_CODER` `:163`); `ensureDarknodeModel` (`:202`) builds a
persona from `lib/nexus/darknode.Modelfile`.

## 4. Governance & safety

There are **two parallel governance stacks**.

### 4a. Per-project policy + audit (always on in the coding loop)
`lib/governance/policy.js`. `POLICY_DEFAULTS` (`:6-14`): `protectedPaths`
(`.env`, `*.pem`, `*.key`, `**/.ssh/**`, `**/secrets/**`, `**/.git/**`, …),
`deniedCommands`, `requireApprovalPaths`, `maxFilesPerTurn`, `blockSecrets:true`,
`allowNetwork`, `audit:true`. `policyCheck(policy, action)` (`:18-27`) is a **pure
verdict** `{allow, reason?, approval?}` — it does not throw. **The live TUI loop
makes it blocking**: on `!allow` the tool result becomes `"BLOCKED by policy"` and
the action never executes (`darknode.js:2967-2968`); `blockSecrets` is enforced on
writes (`:2977,2979,2980`); `maxFilesPerTurn` at `:2969`.

**Audit chain** (`policy.js:31` `auditLog`, `:43` `auditVerify`): append-only,
`seq` + `prevHash` + per-record `sha256`, written to `.nexus/audit.jsonl`.
`auditVerify` detects edit/removal/reorder. A second HMAC-keyed implementation is
in `lib/governance/audit-log.js`.

### 4b. Signed-authorization engagement gate (opt-in; the S0 subsystem)
Activated by `DARKNODE_ENGAGEMENT=<id>` (`darknode.js:816-829`).

- `lib/governance/authorization.js` — the authorization **envelope**
  `{record, signature}` (`:7`). `record` carries client, agreement reference,
  in/out-of-scope assets, permitted action classes, testing window, emergency
  contact (`:8-12`). **Attesting party:** `signature` is **Ed25519 over
  canonical(record)** by a trusted-authorizer key; the gate only verifies, never
  signs (`:11-13`). Action classes: `["recon","scan","vuln-scan","exploit"]`
  (`:16-21`). Targets: `parseTarget`/`parseScopeEntry` canonicalise IPv4
  obfuscation and IDN via the WHATWG URL parser (`:30-41,70-72`); `MIN_CIDR_BITS=16`
  rejects over-broad ranges (`:22`). Everything **fails closed** (`:4-5`).
- `lib/governance/engagement-gate.js` — `authorize(req)` (`:166`); on any
  exception → `{allow:false, code:"GATE_ERROR"}` (`:177`). Every decision is
  appended to the engagement audit file (`:178-180`); **if the audit write fails,
  it refuses to run** (`AUDIT_FAILURE`, `:181`). `guard(id,tool,argv,fn)` (`:188`)
  throws `GateDenied` on deny. `filterInScope` (`:198`) drops out-of-scope
  discovered hosts. `OFFLINE_COMMANDS` (`:239`) run ungated. Operator surface:
  `lib/governance/authz-cli.js` (`darknode authz …`).

### 4c. Unified gate (available, not yet the live path)
`lib/nexus/guardrails.js:28` `evaluateAction` composes `policyCheck` +
`classifyDanger` + `scanSecrets` into one `{decision: allow|ask|deny, risk,
reasons}` (escalation = strongest). It is **pure; the caller enforces**. It is
wired only to the `darknode guard` preview command (`darknode.js:1014`). The live
TUI loop re-implements the same composition inline (§5) rather than calling it —
a consolidation opportunity tracked under NX-002.

## 5. Tool surface & the pre-exec gate

Canonical schemas: `lib/nexus/native-tools.js:21-49` (`TOOL_SCHEMAS`).
- **Files:** `read_file`, `write_file`, `edit_file`, `multi_edit`, `apply_patch`,
  `list_dir`, `make_dir`, `move`, `copy`, `delete`.
- **Shell/process:** `run_command`, `run_background`, `check_background`,
  `stop_background`, `list_processes`, `sysinfo`.
- **Search/nav:** `search` (grep), `find` (glob), `repo_map`, `find_symbol`.
- **Network:** `http_fetch`, `web_search`.
- **Agentic/meta:** `verify`, `remember`, `discover`, `todo_write`, `spawn_agents`.
- **MCP tools** (`mcp__*`) merged dynamically (`darknode.js:2986`).

Execution is inline in the TUI loop (`:2974-2993`). **Before** any tool runs, the
inline composite gate fires: plan-mode block (`:2952`), permission allow-list
`permDecision` (`:2953`), destructive-command `classifyDanger` (`:2955`),
`policyCheck` (`:2967`), `blockSecrets` scan on writes (`:2977`), PreToolUse hook
(`:2973`). Only `!blocked` runs the tool. Post-exec: PostToolUse hook (`:2997`) and
`auditLog` (`:2999`).

## 6. State

- **Per-turn history:** in-memory `oMsgs` (provider-shaped).
- **Session:** `.nexus/session.json` via `saveSession()` (`:3254`), chmod-secured by
  `secureNexus`; restored by `/resume` (`:3434`).
- **Durable memory:** `.nexus/NEXUS.md` loaded into every system prompt
  (`:1489,1525,1529`); appended by the `remember` tool (`:2991`) and `/dream`.
- **Run state:** `.nexus/run.json` (plan + task status/tries), `.nexus/report.md`.
- **Undo/redo:** git-tree checkpoints (`/undo` `:3446`, `/rewind` `:3437`).
- **Usage ledger:** `.nexus/usage.jsonl` → `/report`, `/savings`.
- **Audit:** `.nexus/audit.jsonl` hash chain (§4a). **Export:** `/export` markdown.
- **Machine state:** `~/.darknode/` (login tokens, Firebase config, setup marker)
  via `readGlobal`/`writeGlobal` chmod 0600 (`:1133-1137`).
- **Config:** `.nexus/config.json`, `mcp.json`, `hooks.json`, `commands/*.md`,
  `plan.json`, `index.json`, `snippets.json`.

## 7. Design invariants (test-enforced)
- **Engine isolation** — a flag for one AI never reaches another; `args()` is the
  single source. `test/run.js` asserts no Claude-only flag appears in another
  engine's argv.
- **Least privilege** — file/command tools are `policyCheck`-gated before
  execution; an org floor at `~/.darknode/policy.json` can only be tightened.
- **Provenance** — every enforced action is appended to the hash chain; any edit,
  deletion, or reorder is detected by `auditVerify`.

## 8. Security capabilities — real vs. reference
**Real (live network/host actions):** port scan (real TCP + banner, `darknode.js:102`,
`quickScan` `:3036`), DNS/whois/headers/cert/subs/subrecon, HTTP fuzzing (`:203`),
external `nmap`/`nuclei`/`hashcat` orchestration (gate's `runExternal`
`engagement-gate.js:209`), `vuln-scanner.js` (real https/tls/dns), `scanSecrets`
secret detection, `deps.js`/`envaudit.js`/`git-security.js` over real repo files,
the HYDRA `pentest-engine.js` (real exec), and `report-generator.js` /
`compliance.js` verifiable artifacts (hash + optional HMAC).

**Reference/knowledge (data + guidance, no live action):** `attack-planner.js`,
`ctf-helper.js`, `threat-model.js` (STRIDE), and the offline catalogs
(`methodologies`, `security-kb`, `threat-intel-data`, `exploit-db`, `cve-lookup`,
`protocols-data`, `ad-attacks`, `cloud-security`, `wireless-iot`,
`incident-response`, `forensics`, `compliance-data`).

**Isolation gap (noted, not yet closed):** there is no sandbox/VM for
`run_command` beyond the `lab` Docker helper (binds containers to `127.0.0.1`,
`darknode.js:557`) and the destructive-command classifier.

## 9. Module inventory & measured counts
Measured 2026-10-04:
- `lib/nexus/` — **44** modules. Engine/model: `engines.js`, `ollama.js`,
  `native-tools.js`, `parsers.js`, `codex-local.js`, `pricing.js`, `costsave.js`,
  `darknode.Modelfile`. Loop/orchestration: `loop.js`, `bgjobs.js`, `tools.js`,
  `edit.js`, `verify.js`, `repo-map.js`, `memory.js`, `todos.js`, `update.js`,
  `mcp-catalog.js`, `pipelines.js`, `project-bootstrap.js`, `dashboard.js`,
  `api-server.js`, `changelog.js`. Code-intel: `capindex.js`, `code-radar.js`,
  `code-review-auto.js`, `code-diff-explain.js`, `review.js`, `smart-test.js`,
  `codestats.js`, `deps.js`, `envaudit.js`. Security: `pentest-engine.js`,
  `attack-planner.js`, `ctf-helper.js`, `vuln-scanner.js`, `nmap-parser.js`,
  `git-security.js`, `report-generator.js`, `threat-model.js`,
  `incident-response.js`, `methodologies.js`, `security-kb.js`,
  `threat-intel-data.js`.
- `lib/governance/` — `policy.js`, `security.js`, `guardrails.js` (in `lib/nexus/`),
  `authorization.js`, `engagement-gate.js`, `authz-cli.js`, `audit-log.js`,
  `compliance.js`, `compliance-data.js`, `rbac.js`, `reporting.js`, `identity.js`,
  `usage.js`.
- `lib/toolkit/`, `lib/cli/` — security/CTF primitives and the CLI framework
  (dispatch registry, help reference, settings, styles, diff, validate, data blobs).
- Totals: **104** `lib/*.js`; sibling engine repo `nexus` has **61** `src/` modules.

Reproduce:
```
find lib -name '*.js' | wc -l            # 104
ls lib/nexus/*.js | wc -l                # 44
grep -cE 'ok\(|eq\(' test/run.js         # 567 assertions
```

## 10. Testing & CI
```
npm test                                 # framework-free unit suite (567 assertions)
node --check darknode.js lib/**/*.js test/*.js
```
`.github/workflows/ci.yml` runs `node --check` + `npm test` + a CLI smoke test on
Node 18/20/22; `.github/workflows/build-mac-cli.yml` builds the macOS binary.

"use strict";
// ============================================================================
// command-help — per-slash-command usage + examples for the TUI.
//
// The one-line DESCRIPTION of every command still lives in the CMDS table in
// darknode.js (single source of truth); this module adds only the extra two
// things a one-liner can't carry: the argument SYNTAX and a couple of concrete
// EXAMPLES. `/help <command>` renders a card from both, and a handler that
// rejects bad input can show the SAME usage line (usageLine) so the help a user
// reads and the error they hit never drift.
//
// Entry shape, all optional:
//   u   usage/argument syntax shown after the command name
//   a   [[arg, what-it-means], …]  — notes on individual arguments/values
//   ex  ["/cmd …", …]              — runnable examples
//   see ["/other", …]              — related commands
// A command with no entry still gets a card (name + description); it just has
// no args to explain.
// ============================================================================

const HELP = {
  "/help": { u: "[word]", ex: ["/help", "/help cost", "/help /model"], see: ["/docs", "/keys"] },
  "/connect": { u: "", ex: ["/connect"], see: ["/engine", "/model", "/api"] },
  "/alias": { u: "<name> = <text|/command>", a: [["name", "the shortcut you'll type"], ["= …", "what it expands to — plain text or another /command"]], ex: ["/alias ship = /commit", "/alias rv = review this diff for security"] },
  "/retry": { u: "", ex: ["/retry"] },
  "/budget": { u: "<usd>|off", a: [["<usd>", "stop warning past this session spend"], ["off", "remove the cap"]], ex: ["/budget 5", "/budget off"], see: ["/cost", "/savings"] },
  "/report": { u: "[json|save|since <date>]", a: [["json", "machine-readable output"], ["save", "write it to a file"], ["since <date>", "only usage on/after YYYY-MM-DD"]], ex: ["/report", "/report json", "/report since 2026-10-01"], see: ["/cost", "/compliance"] },
  "/compliance": { u: "[verify <bundle.json>]", a: [["verify <file>", "check a bundle's signature + hash chain"]], ex: ["/compliance", "/compliance verify audit.json"], see: ["/audit", "/report"] },
  "/rewind": { u: "[N]", a: [["N", "checkpoint number (see /checkpoints); omit for a picker"]], ex: ["/rewind", "/rewind 3"], see: ["/checkpoints", "/undo", "/redo"] },
  "/bisect": { u: "[test command]", a: [["test command", "how to tell pass from fail; auto-detected if omitted"]], ex: ["/bisect", "/bisect npm test"], see: ["/whatbroke", "/shrink"] },
  "/shrink": { u: "[test command]", ex: ["/shrink", "/shrink npm test"], see: ["/bisect", "/whatbroke"] },
  "/branch": { u: "[new <name>|<name>]", a: [["new <name>", "fork a new conversation branch"], ["<name>", "switch to an existing branch"]], ex: ["/branch", "/branch new spike", "/branch main"], see: ["/resume"] },
  "/export": { u: "[file]", a: [["file", "where to write the markdown; omit for a default name"]], ex: ["/export", "/export chat.md"], see: ["/copy"] },
  "/fixshell": { u: "[check|all]", a: [["check", "report only, change nothing"], ["all", "also clear the larger shell state"]], ex: ["/fixshell", "/fixshell check"] },
  "/model": { u: "[name|number]", a: [["name|number", "pick from the catalog; omit to list it"]], ex: ["/model", "/model 3", "/model sonnet"], see: ["/models", "/engine", "/compat"] },
  "/engine": { u: "[claude|gemini|codex|opencode|aider|ollama]", ex: ["/engine", "/engine claude", "/engine ollama"], see: ["/model", "/connect"] },
  "/agents": { u: "<task> ;; <task> ;; …", a: [[";;", "separates independent tasks run in parallel"]], ex: ["/agents add tests ;; write docs ;; fix lint"], see: ["/team", "/race"] },
  "/race": { u: "<prompt>", ex: ["/race explain this bug"], see: ["/review", "/ensemble", "/bench"] },
  "/review": { u: "[prompt]", ex: ["/review", "/review focus on error handling"], see: ["/codereview", "/review-fast", "/ultrareview"] },
  "/codereview": { u: "[low|medium|high|xhigh|max] [file|branch|PR#] [--fix] [--comment] [--max-findings n|all|default]", a: [["level", "few sure findings → many, some uncertain"], ["--fix", "apply fixes to the working tree"], ["--comment", "post inline PR comments"]], ex: ["/codereview", "/codereview high", "/codereview max 42 --comment"], see: ["/ultrareview", "/review-fast"] },
  "/ultrareview": { u: "[file|branch|PR#]", ex: ["/ultrareview", "/ultrareview HEAD~3"], see: ["/codereview"] },
  "/changelog": { u: "[git range]", ex: ["/changelog", "/changelog v1.0..HEAD"] },
  "/notify": { u: "on|off", ex: ["/notify on", "/notify off"] },
  "/watch": { u: "<command>", a: [["command", "re-run and auto-fix until it exits 0"]], ex: ["/watch npm test"], see: ["/verify", "/test"] },
  "/commit": { u: "[message]", a: [["message", "override the AI-written message"]], ex: ["/commit", "/commit fix: null guard"], see: ["/pr", "/diff"] },
  "/diff": { u: "[file] [--staged]", ex: ["/diff", "/diff src/app.js", "/diff --staged"], see: ["/explain", "/commit"] },
  "/pin": { u: "<file>", ex: ["/pin src/app.js"], see: ["/pins", "/unpin"] },
  "/unpin": { u: "<file>", ex: ["/unpin src/app.js"], see: ["/pins", "/pin"] },
  "/ensemble": { u: "<prompt>", ex: ["/ensemble design a cache layer"], see: ["/race", "/team"] },
  "/loop": { u: "[-n rounds] <goal>", a: [["-n rounds", "max iterations (default keeps going until GOAL-DONE)"], ["goal", "what 'done' means"]], ex: ["/loop make the tests green", "/loop -n 5 wire up auth"], see: ["/team", "/plan", "/next"] },
  "/team": { u: "<goal>", a: [["goal", "architect + builder + reviewer loop until the reviewer says PASS"]], ex: ["/team add rate limiting to the API"], see: ["/loop", "/agents", "/cowork"] },
  "/policy": { u: "", ex: ["/policy"], see: ["/audit", "/guard", "/permissions"] },
  "/audit": { u: "[verify]", a: [["verify", "check the hash chain; exits non-zero if tampered"]], ex: ["/audit", "/audit verify"], see: ["/attest", "/compliance"] },
  "/explain": { u: "[file]", a: [["file", "explain a file; omit to explain the current diff"]], ex: ["/explain", "/explain src/app.js"], see: ["/diffexplain", "/blame"] },
  "/test": { u: "<file>", ex: ["/test src/util.js"], see: ["/testgen", "/verify", "/watch"] },
  "/refactor": { u: "<file> [goal]", ex: ["/refactor src/app.js", "/refactor src/app.js split the parser out"] },
  "/migrate": { u: "<from> to <to>", ex: ["/migrate commonjs to esm", "/migrate react 17 to 18"] },
  "/pr": { u: "[base]", a: [["base", "base branch for the PR (default: the repo default)"]], ex: ["/pr", "/pr develop"], see: ["/commit", "/changelog"] },
  "/index": { u: "[question]", a: [["question", "find the code behind it; omit to (re)build the index"]], ex: ["/index", "/index where is login handled"], see: ["/map", "/find"] },
  "/map": { u: "[task|on|off]", a: [["task", "rank the repo map for a task"], ["on|off", "keep the map in context each turn"]], ex: ["/map", "/map add caching", "/map off"], see: ["/index", "/tree", "/radar"] },
  "/verify": { u: "", ex: ["/verify"], see: ["/test", "/watch"] },
  "/review-fast": { u: "", ex: ["/review-fast"], see: ["/codereview", "/review"] },
  "/testgen": { u: "<function|file>", ex: ["/testgen src/util.js", "/testgen parseDate"], see: ["/test"] },
  "/snippet": { u: "<name> [= <text>] | <name>", a: [["name = text", "save a prompt macro"], ["name", "use a saved macro"]], ex: ["/snippet triage = review the diff for bugs", "/snippet triage"], see: ["/snippets", "/alias"] },
  "/plan": { u: "[goal]", ex: ["/plan", "/plan ship the export feature"], see: ["/loop", "/team"] },
  "/blame": { u: "<file>", ex: ["/blame src/app.js"], see: ["/explain", "/git"] },
  "/cheap": { u: "[status|off]", ex: ["/cheap", "/cheap status", "/cheap off"], see: ["/tight", "/lean", "/costtips", "/savings"] },
  "/lean": { u: "on|off", ex: ["/lean on", "/lean off"], see: ["/cheap", "/tight"] },
  "/style": { u: "<concise|explanatory|review|tdd|secure|teacher>", ex: ["/style concise", "/style secure"] },
  "/effort": { u: "[low|medium|high|xhigh|max|ultracode]", a: [["(Claude only)", "thinking depth; omit for the slider"]], ex: ["/effort", "/effort high"], see: ["/mode", "/god-prompt"] },
  "/estimate": { u: "<prompt>", ex: ["/estimate refactor the auth module"], see: ["/tokens", "/cost"] },
  "/fallback": { u: "[on|off]", ex: ["/fallback on", "/fallback off"] },
  "/guard": { u: "[enforce|warn|off]", ex: ["/guard", "/guard enforce", "/guard off"], see: ["/permissions", "/policy"] },
  "/permissions": { u: "— use /allow <rule> and /deny <rule>", ex: ["/permissions", "/allow run_command(git*)", "/deny write_file(.env)"], see: ["/guard", "/policy"] },
  "/cache": { u: "[on|off|clear]", ex: ["/cache", "/cache on", "/cache clear"], see: ["/warm", "/cheap"] },
  "/api": { u: "<base-url> <model> [key]", a: [["base-url", "any OpenAI-compatible endpoint"]], ex: ["/api https://openrouter.ai/api/v1 meta-llama/llama-3-70b"], see: ["/engine", "/models"] },
  "/docs": { u: "[topic|words]", ex: ["/docs", "/docs modes", "/docs how do I undo"], see: ["/help", "/keys"] },
  "/gaps": { u: "[plan]", a: [["plan", "turn the TODO/FIXME markers into a task plan"]], ex: ["/gaps", "/gaps plan"], see: ["/todo", "/plan"] },
  "/color": { u: "<name|0-255|#hex>|reset", ex: ["/color teal", "/color 208", "/color #c0ffee", "/color reset"], see: ["/colors", "/theme", "/gradient"] },
  "/gradient": { u: "<theme|reset>", ex: ["/gradient aurora", "/gradient reset"], see: ["/color", "/theme"] },
  "/mouse": { u: "[off]", a: [["off", "release the mouse so you can select & copy text"]], ex: ["/mouse", "/mouse off"] },
  "/theme": { u: "[name]", ex: ["/theme", "/theme mono"], see: ["/color", "/colors", "/gradient"] },
  "/pentest": { u: "<target> [--authorized]", a: [["target", "host/app you are AUTHORIZED to test"], ["--authorized", "confirm you have written permission"]], ex: ["/pentest 10.0.0.5 --authorized"], see: ["/hack", "/scan"] },
  "/scan": { u: "<host>", ex: ["/scan example.com"], see: ["/pentest"] },
  "/offline": { u: "on|off", ex: ["/offline on", "/offline off"], see: ["/redact"] },
  "/todo": { u: "[TAG]", a: [["TAG", "filter, e.g. FIXME or HACK; omit for all"]], ex: ["/todo", "/todo FIXME"], see: ["/gaps", "/stats"] },
  "/login": { u: "[code|google|github]", ex: ["/login", "/login google"], see: ["/logout", "/whoami"] },
  "/setup": { u: "", ex: ["/setup"], see: ["/engine", "/doctor"] },
  "/update": { u: "[apply|--check]", a: [["apply", "install the newer version now"]], ex: ["/update", "/update apply"], see: ["/autoupdate", "/restart"] },
  "/autoupdate": { u: "on|check|off", ex: ["/autoupdate on", "/autoupdate off"] },
  "/next": { u: "<prompt> | clear | rm <n>", ex: ["/next run the tests", "/next clear"], see: ["/loop"] },
  "/find": { u: "<text>", a: [["n/N", "step through matches"], ["q", "close"]], ex: ["/find TODO", "/find race condition"], see: ["/pager", "/index"] },
  "/pager": { u: "[n]", a: [["n", "which recent tool output; omit for the newest"]], ex: ["/pager", "/pager 2"], see: ["/find", "/expand"] },
  "/mode": { u: "power|cost|speed|reset", ex: ["/mode power", "/mode reset"], see: ["/effort", "/model"] },
  "/autocompact": { u: "auto|off|<amount>", ex: ["/autocompact auto", "/autocompact off", "/autocompact 80%"], see: ["/compact", "/recap"] },
  "/recap": { u: "[on|off]", a: [["(no arg)", "recap now"], ["on|off", "toggle the after-task recap"]], ex: ["/recap", "/recap off"] },
  "/title": { u: "[text|on|off]", ex: ["/title", "/title auth refactor", "/title off"] },
  "/feature": { u: "create <name> <what it does> | remove <name> | list", ex: ["/feature list", "/feature create triage review the diff for bugs", "/feature remove triage"], see: ["/alias", "/snippet", "/commands"] },
  "/cron": { u: "list | add \"<schedule>\" <goal> | remove <id>", a: [["schedule", "cron expression, e.g. 0 9 * * *"]], ex: ["/cron list", "/cron add \"0 9 * * *\" run the nightly audit"] },
  "/expand": { u: "", ex: ["/expand"], see: ["/pager"] },
  "/vim": { u: "on|off", ex: ["/vim on", "/vim off"] },
  "/terminal-setup": { u: "[off]", ex: ["/terminal-setup", "/terminal-setup off"] },
  "/trust": { u: "", ex: ["/trust"], see: ["/policy", "/permissions"] },
  "/tokens": { u: "<@file|@dir>", ex: ["/tokens @src", "/tokens @README.md"], see: ["/estimate", "/context"] },
  "/dashboard": { u: "[stop]", ex: ["/dashboard", "/dashboard stop"], see: ["/open"] },
};

// The description still comes from CMDS (passed in); this only adds usage/examples.
function get(name) { return HELP[name] || null; }

// A single consistent usage line a handler can print on bad input, so the error
// a user hits matches the `/help <cmd>` card exactly. Returns "" if no syntax.
function usageLine(name) {
  const h = HELP[name];
  if (!h || !h.u) return "";
  return "usage: " + name + (h.u.startsWith("—") || h.u === "" ? (h.u ? " " + h.u : "") : " " + h.u);
}

// Render a help card. `desc` is the CMDS one-liner; C is an optional color kit
// { name, head, dim, flag } of (s)=>string formatters (identity if absent).
function card(name, desc, C) {
  C = C || {};
  const id = (s) => s;
  const name_ = C.name || id, head = C.head || id, dim = C.dim || id, flag = C.flag || id;
  const h = HELP[name];
  const out = [];
  out.push(name_(name) + (desc ? "  " + dim("— " + desc) : ""));
  if (h && h.u) out.push("  " + head("usage ") + name + (h.u.startsWith("—") ? " " + h.u : " " + h.u));
  else out.push("  " + head("usage ") + name + dim("   (no arguments)"));
  if (h && h.a && h.a.length) {
    out.push("  " + head("arguments"));
    const w = Math.min(28, Math.max(...h.a.map((r) => r[0].length)));
    for (const [k, v] of h.a) out.push("    " + flag(k.padEnd(w)) + "  " + dim(v));
  }
  if (h && h.ex && h.ex.length) {
    out.push("  " + head("examples"));
    for (const e of h.ex) out.push("    " + e);
  }
  if (h && h.see && h.see.length) out.push("  " + head("see also ") + h.see.join("  "));
  return out.join("\n");
}

// Is `tok` (with or without a leading slash) a command we can card? Returns the
// normalized "/name" or null. `names` is the live Set/array of real commands.
function resolve(tok, names) {
  if (!tok) return null;
  const t = tok.trim().replace(/^\/+/, "");
  const cand = "/" + t.toLowerCase();
  const has = names instanceof Set ? (n) => names.has(n) : (n) => names.indexOf(n) >= 0;
  return has(cand) ? cand : null;
}

module.exports = { HELP, get, usageLine, card, resolve };
